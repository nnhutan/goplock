package controllers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/nnhutan/goplock/initializers"
	"github.com/nnhutan/goplock/models"
	"github.com/nnhutan/goplock/utils"
	"github.com/redis/go-redis/v9"
	"github.com/thanhpk/randstr"
	"gorm.io/gorm"

	"github.com/gofiber/fiber/v2"
)

// @Summary		Register
// @Description	Register new User
// @Tags			Auth
// @Param			name		formData	string	true	"Name"
// @Param			email		formData	string	true	"Email"
// @Param			password	formData	string	true	"Password"
// @Param		  passwordConfirmation	formData	string	true	"Password Confirmation"
// @Param			photo		formData	string		false	"Photo"
// @Router			/auth/register [POST]
func Register(c *fiber.Ctx) error {
	db := initializers.DB
	user := new(models.UserRegister)

	if err := c.BodyParser(user); err != nil {
		return utils.Error(c, fiber.StatusBadRequest, err.Error())
	}

	errors := models.ValidateStruct(user)

	if len(errors) > 0 {
		return utils.Error(c, fiber.StatusBadRequest, errors)
	}

	// Check if email already exists
	var existingUser models.User
	result := db.First(&existingUser, "email = ?", user.Email)
	if result.RowsAffected > 0 {
		return utils.Error(c, fiber.StatusBadRequest, "Email already exists")
	}

	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		return utils.Error(c, fiber.StatusInternalServerError, err.Error())
	}

	newUser := models.User{
		Name:     user.Name,
		Email:    user.Email,
		Password: hashedPassword,
		Photo:    user.Photo,
	}

	result = db.Create(&newUser)
	if result.Error != nil {
		return utils.Error(c, fiber.StatusInternalServerError, result.Error.Error())
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"success": true,
		"data":    models.FilterUserRecord(&newUser),
	})
}

// @Summary		Login
// @Description	Login User
// @Tags			Auth
// @Param			email		formData	string	true	"Email"
// @Param			password	formData	string	true	"Password"
// @Router			/auth/login [POST]
func Login(c *fiber.Ctx) error {
	payload := new(models.UserLogin)

	if err := c.BodyParser(payload); err != nil {
		return utils.Error(c, fiber.StatusBadRequest, err.Error())
	}

	errors := models.ValidateStruct(payload)
	if errors != nil {
		return utils.Error(c, fiber.StatusBadRequest, errors)
	}

	user := new(models.User)
	err := initializers.DB.First(&user, "email = ?", strings.ToLower(payload.Email)).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return utils.Error(c, fiber.StatusForbidden, "Invalid email or password")
		} else {
			return utils.Error(c, fiber.StatusBadGateway, err.Error())
		}
	}

	if user.Provider == "Google" && user.Password == "" {
		return utils.Error(c, fiber.StatusUnauthorized, "Please login with Google")
	}

	err = utils.VerifyPassword(user.Password, payload.Password)
	if err != nil {
		return utils.Error(c, fiber.StatusForbidden, "Invalid email or password")
	}

	config, _ := initializers.LoadConfig(".")
	accessTokenDetails, refreshTokenDetails, err := utils.GenerateTokenPair(user.ID.String(), &config)
	if err != nil {
		return utils.Error(c, fiber.StatusUnprocessableEntity, err.Error())
	}

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    *refreshTokenDetails.Token,
		Path:     "/",
		MaxAge:   config.RefreshTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: true,
		Domain:   "localhost",
	})

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"success": true, "access_token": accessTokenDetails.Token})
}

// @Summary		Refresh Access Token
// @Description	Refresh Access Token
// @Tags			Auth
// @Router			/auth/refresh [POST]
func RefreshAccessToken(c *fiber.Ctx) error {
	message := "Could not refresh access token"
	refresh_token := c.Cookies("refresh_token")
	redisClient := initializers.RedisClient

	if refresh_token == "" {
		return utils.Error(c, fiber.StatusForbidden, message)
	}

	config, _ := initializers.LoadConfig(".")
	ctx := context.TODO()

	tokenClaims, err := utils.ValidateToken(refresh_token, config.RefreshTokenPublicKey)
	if err != nil {
		return utils.Error(c, fiber.StatusForbidden, err.Error())
	}

	userId, err := redisClient.Get(ctx, tokenClaims.TokenUuid).Result()
	if err == redis.Nil {
		return utils.Error(c, fiber.StatusForbidden, message)
	}

	var user models.User
	err = initializers.DB.First(&user, "id = ?", userId).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return utils.Error(c, fiber.StatusForbidden, "The user belonging to this token no logger exists")
		} else {
			return utils.Error(c, fiber.StatusBadGateway, err.Error())
		}
	}

	redisClient.Del(ctx, tokenClaims.TokenUuid)

	accessTokenDetails, refreshTokenDetails, err := utils.GenerateTokenPair(user.ID.String(), &config)
	if err != nil {
		return utils.Error(c, fiber.StatusUnprocessableEntity, err.Error())
	}

	// Refresh token rotation
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    *refreshTokenDetails.Token,
		Path:     "/",
		MaxAge:   config.RefreshTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: true,
		Domain:   "localhost",
	})

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "access_token": accessTokenDetails.Token})
}

// @Summary		Logout
// @Description	Logout User
// @Tags			Auth
// @Router			/auth/logout [DELETE]
// @Security BearerAuth
// @Success 204
// @Failure 403
func Logout(c *fiber.Ctx) error {
	message := "Token is invalid or session has expired"

	refresh_token := c.Cookies("refresh_token")

	if refresh_token == "" {
		return utils.Error(c, fiber.StatusForbidden, message)
	}

	config, _ := initializers.LoadConfig(".")
	ctx := context.TODO()

	tokenClaims, err := utils.ValidateToken(refresh_token, config.RefreshTokenPublicKey)
	if err != nil {
		return utils.Error(c, fiber.StatusForbidden, err.Error())
	}

	access_token_uuid := c.Locals("access_token_uuid").(string)
	_, err = initializers.RedisClient.Del(ctx, tokenClaims.TokenUuid, access_token_uuid).Result()
	if err != nil {
		return utils.Error(c, fiber.StatusBadGateway, err.Error())
	}

	expired := time.Now().Add(-time.Hour * 24)
	c.Cookie(&fiber.Cookie{
		Name:    "refresh_token",
		Value:   "",
		Expires: expired,
	})
	return c.SendStatus(fiber.StatusNoContent)
}

// @Summary		Send Email Verification
// @Description	Send Email Verification
// @Tags			Auth
// @Router			/auth/verify-email [POST]
// @Security BearerAuth
// @Success 200
// @Security BearerAuth
func SendEmailVerification(c *fiber.Ctx) error {
	code := randstr.String(20)
	user := c.Locals("user").(*models.User)
	verification_code := utils.Encode(code)

	user.VerificationCode = verification_code
	err := initializers.DB.Save(&user).Error
	if err != nil {
		return utils.Error(c, fiber.StatusBadGateway, err.Error())
	}

	config, _ := initializers.LoadConfig(".")

	emailData := utils.EmailData{
		URL:     config.ClientOrigin + "api/auth/verify-email/" + code,
		Name:    user.Name,
		Subject: "Your account verification code",
	}

	utils.SendEmail(user, &emailData, "verificationCode.html")
	message := "We sent an email with a verification code to " + user.Email
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"success": true, "message": message})
}

// @Summary		Verify Email
// @Description	Verify Email
// @Tags			Auth
// @Router			/auth/verify-email/{code} [GET]
// @Param code path string true "Verification Code"
// @Success 200
func VerifyEmail(c *fiber.Ctx) error {
	code := c.Params("code")
	verification_code := utils.Encode(code)
	db := initializers.DB

	var updatedUser models.User
	result := db.First(&updatedUser, "verification_code = ?", verification_code)
	if result.Error != nil {
		return utils.Error(c, fiber.StatusBadRequest, "Invalid verification code or user doesn't exists")
	}

	if updatedUser.Verified {
		return utils.Error(c, fiber.StatusConflict, "User already verified")
	}

	updatedUser.VerificationCode = ""
	updatedUser.Verified = true
	db.Save(&updatedUser)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"success": true, "message": "Email verified successfully"})
}

// @Summary Google GoogleOAuth
// @Description Google GoogleOAuth
// @Tags Auth
// @Router /auth/google [GET]
// @Param code query string true "Authorization Code"
// @Success 200
func GoogleOAuth(c *fiber.Ctx) error {
	code := c.Query("code")
	var pathUrl string = "/"

	if c.Query("state") != "" {
		pathUrl = c.Query("state")
	}

	if code == "" {
		return utils.Error(c, fiber.StatusBadRequest, "Authorization code not provided!")
	}

	tokenRes, err := utils.GetGoogleOauthToken(code)

	if err != nil {
		return utils.Error(c, fiber.StatusBadGateway, err.Error())
	}

	google_user, err := utils.GetGoogleUser(tokenRes.Access_token, tokenRes.Id_token)

	if err != nil {
		return utils.Error(c, fiber.StatusBadGateway, err.Error())
	}

	email := strings.ToLower(google_user.Email)

	user_data := models.User{
		Name:     google_user.Name,
		Email:    email,
		Password: "",
		Photo:    google_user.Picture,
		Provider: "Google",
		Role:     "user",
		Verified: true,
	}

	db := initializers.DB

	if db.Model(&user_data).Where("email = ?", email).Updates(&user_data).RowsAffected == 0 {
		db.Create(&user_data)
	}

	var user models.User
	db.First(&user, "email = ?", email)

	config, _ := initializers.LoadConfig(".")
	_, refreshTokenDetails, err := utils.GenerateTokenPair(user.ID.String(), &config)
	if err != nil {
		return utils.Error(c, fiber.StatusUnprocessableEntity, err.Error())
	}

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    *refreshTokenDetails.Token,
		Path:     "/",
		MaxAge:   config.RefreshTokenMaxAge * 60,
		Secure:   false,
		HTTPOnly: true,
		Domain:   "localhost",
	})

	return c.Redirect(fmt.Sprintf("%s%s", config.ClientOrigin, pathUrl), fiber.StatusTemporaryRedirect)
}

// @Summary Forgot Password
// @Description Forgot Password
// @Tags Auth
// @Router /auth/forgot-password [POST]
// @Param email formData string true "Email"
// @Success 200
func ForgotPassword(c *fiber.Ctx) error {
	payload := new(models.UserForgotPassword)

	if err := c.BodyParser(payload); err != nil {
		return utils.Error(c, fiber.StatusBadRequest, err.Error())
	}

	message := "You will receive a reset email if user with that email exist"

	var user models.User
	result := initializers.DB.First(&user, "email = ?", strings.ToLower(payload.Email))
	if result.Error != nil {
		return utils.Error(c, fiber.StatusBadRequest, "Invalid email or Password")
	}

	if !user.Verified {
		return utils.Error(c, fiber.StatusUnauthorized, "Account not verified")
	}

	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatal("Could not load config", err)
	}

	// Generate Verification Code
	resetToken := randstr.String(20)

	passwordResetToken := utils.Encode(resetToken)
	user.PasswordResetToken = passwordResetToken
	user.PasswordResetAt = time.Now().Add(time.Minute * 15)
	initializers.DB.Save(&user)

	emailData := utils.EmailData{
		URL:     config.ClientOrigin + "/reset-password/" + resetToken,
		Name:    user.Name,
		Subject: "Your password reset token (valid for 10min)",
	}

	utils.SendEmail(&user, &emailData, "resetPassword.html")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"success": true, "message": message})
}

// @Summary Reset Password
// @Description Reset Password
// @Tags Auth
// @Router /auth/reset-password/{resetToken} [PATCH]
// @Param resetToken path string true "Reset Token"
// @Param password formData string true "Password"
// @Param passwordConfirm formData string true "Password Confirm"
// @Success 200
func ResetPassword(c *fiber.Ctx) error {
	var payload = new(models.UserResetPassword)
	resetToken := c.Params("resetToken")

	if err := c.BodyParser(payload); err != nil {
		return utils.Error(c, fiber.StatusBadRequest, err.Error())
	}

	if payload.Password != payload.PasswordConfirm {
		return utils.Error(c, fiber.StatusBadRequest, "Passwords do not match")
	}

	hashedPassword, _ := utils.HashPassword(payload.Password)

	passwordResetToken := utils.Encode(resetToken)

	var updatedUser models.User
	result := initializers.DB.First(&updatedUser, "password_reset_token = ? AND password_reset_at > ?", passwordResetToken, time.Now())
	if result.Error != nil {
		return utils.Error(c, fiber.StatusBadRequest, "The reset token is invalid or has expired")
	}

	updatedUser.Password = hashedPassword
	updatedUser.PasswordResetToken = ""
	initializers.DB.Save(&updatedUser)

	c.ClearCookie("refresh_token")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"success": true, "message": "Password data updated successfully"})
}

// @Summary Change Password
// @Description Change Password
// @Tags Auth
// @Security BearerAuth
// @Router /auth/password [PATCH]
// @Param oldPassword formData string true "Password"
// @Param newPassword formData string true "Password"
// @Param newPasswordConfirm formData string true "Password Confirm"
// @Success 200
func ChangePassword(c *fiber.Ctx) error {
	var payload = new(models.UserChangePassword)

	if err := c.BodyParser(payload); err != nil {
		return utils.Error(c, fiber.StatusBadRequest, err.Error())
	}

	currentUser := c.Locals("user").(*models.User)

	err := utils.VerifyPassword(currentUser.Password, payload.OldPassword)
	if err != nil {
		return utils.Error(c, fiber.StatusForbidden, "Password is incorrect")
	}

	if payload.NewPassword != payload.NewPasswordConfirm {
		return utils.Error(c, fiber.StatusBadRequest, "Passwords do not match")
	}

	hashedPassword, _ := utils.HashPassword(payload.NewPassword)
	currentUser.Password = hashedPassword
	initializers.DB.Save(&currentUser)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"success": true, "message": "Password was changed successfully"})
}
