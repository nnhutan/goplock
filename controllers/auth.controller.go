package controllers

import (
	"context"
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

	utils.SendEmail(user, &emailData)
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
