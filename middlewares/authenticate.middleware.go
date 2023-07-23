package middlewares

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/nnhutan/goplock/initializers"
	"github.com/nnhutan/goplock/models"
	"github.com/nnhutan/goplock/utils"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

func AuthenticateUser(c *fiber.Ctx) error {
	var access_token string
	authorization := c.Get("Authorization")

	if strings.HasPrefix(authorization, "Bearer ") {
		access_token = strings.TrimPrefix(authorization, "Bearer ")
	}

	if access_token == "" {
		return utils.Error(c, fiber.StatusUnauthorized, "You are not logged in")
	}

	config, _ := initializers.LoadConfig(".")

	tokenClaims, err := utils.ValidateToken(access_token, config.AccessTokenPublicKey)
	if err != nil {
		return utils.Error(c, fiber.StatusUnauthorized, err.Error())
	}

	ctx := context.TODO()
	userid, err := initializers.RedisClient.Get(ctx, tokenClaims.TokenUuid).Result()
	if err == redis.Nil {
		return utils.Error(c, fiber.StatusForbidden, "Token is invalid or session has expired")
	}

	user := new(models.User)
	err = initializers.DB.First(&user, "id = ?", userid).Error

	if err == gorm.ErrRecordNotFound {
		return utils.Error(c, fiber.StatusForbidden, "the user belonging to this token no logger exists")
	}

	c.Locals("user", models.FilterUserRecord(user))
	c.Locals("access_token_uuid", tokenClaims.TokenUuid)

	return c.Next()
}
