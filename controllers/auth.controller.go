package controllers

import (
	"context"
	"strings"
	"time"

	"github.com/nnhutan/goplock/initializers"
	"github.com/nnhutan/goplock/models"
	"github.com/nnhutan/goplock/utils"
	"github.com/redis/go-redis/v9"
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
	db := initializers.DB

	if err := c.BodyParser(payload); err != nil {
		return utils.Error(c, fiber.StatusBadRequest, err.Error())
	}

	errors := models.ValidateStruct(payload)
	if errors != nil {
		return utils.Error(c, fiber.StatusBadRequest, errors)
	}

	user := new(models.User)
	err := db.First(&user, "email = ?", strings.ToLower(payload.Email)).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return utils.Error(c, fiber.StatusForbidden, "Invalid email or password")
		} else {
			return utils.Error(c, fiber.StatusBadGateway, err.Error())
		}
	}

	err = utils.VerifyPassword(user.Password, payload.Password)
	if err != nil {
		return utils.Error(c, fiber.StatusBadGateway, "Invalid email or password")
	}

	config, _ := initializers.LoadConfig(".")

	accessTokenDetails, err := utils.CreateToken(user.ID.String(), config.AccessTokenExpiresIn, config.AccessTokenPrivateKey)
	if err != nil {
		return utils.Error(c, fiber.StatusUnprocessableEntity, err.Error())
	}

	refreshTokenDetails, err := utils.CreateToken(user.ID.String(), config.RefreshTokenExpiresIn, config.RefreshTokenPrivateKey)
	if err != nil {
		return utils.Error(c, fiber.StatusUnprocessableEntity, err.Error())
	}

	ctx := context.TODO()
	now := time.Now()

	errAccess := initializers.RedisClient.Set(ctx, accessTokenDetails.TokenUuid, user.ID.String(), time.Unix(*accessTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errAccess != nil {
		return utils.Error(c, fiber.StatusUnprocessableEntity, errAccess.Error())
	}

	errRefresh := initializers.RedisClient.Set(ctx, refreshTokenDetails.TokenUuid, user.ID.String(), time.Unix(*refreshTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errAccess != nil {
		return utils.Error(c, fiber.StatusUnprocessableEntity, errRefresh.Error())
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
	message := "could not refresh access token"

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

	userId, err := initializers.RedisClient.Get(ctx, tokenClaims.TokenUuid).Result()
	if err == redis.Nil {
		return utils.Error(c, fiber.StatusForbidden, message)
	}

	var user models.User
	err = initializers.DB.First(&user, "id = ?", userId).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return utils.Error(c, fiber.StatusForbidden, "the user belonging to this token no logger exists")
		} else {
			return utils.Error(c, fiber.StatusBadGateway, err.Error())
		}
	}

	accessTokenDetails, err := utils.CreateToken(user.ID.String(), config.AccessTokenExpiresIn, config.AccessTokenPrivateKey)
	if err != nil {
		return utils.Error(c, fiber.StatusUnprocessableEntity, err.Error())
	}

	now := time.Now()

	errAccess := initializers.RedisClient.Set(ctx, accessTokenDetails.TokenUuid, user.ID.String(), time.Unix(*accessTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errAccess != nil {
		return utils.Error(c, fiber.StatusUnprocessableEntity, errAccess.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "access_token": accessTokenDetails.Token})
}

// @Summary		Logout
// @Description	Logout User
// @Tags			Auth
// @Router			/auth/logout [DELETE]
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

	_, err = initializers.RedisClient.Del(ctx, tokenClaims.TokenUuid).Result()
	if err != nil {
		return utils.Error(c, fiber.StatusBadGateway, err.Error())
	}

	expired := time.Now().Add(-time.Hour * 24)
	c.Cookie(&fiber.Cookie{
		Name:    "refresh_token",
		Value:   "",
		Expires: expired,
	})
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success"})
}
