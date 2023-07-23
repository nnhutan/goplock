package controllers

import (
	"github.com/nnhutan/goplock/initializers"
	"github.com/nnhutan/goplock/models"
	"github.com/nnhutan/goplock/utils"

	"github.com/gofiber/fiber/v2"
)

// @Summary		Get Me
// @Description	Get current User
// @Tags			User
// @Router			/users/me [GET]
// @Success		200	{object}	models.UserResponse
// @Security BearerAuth
func GetMe(c *fiber.Ctx) error {
	user := c.Locals("user").(models.UserResponse)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"data":    user,
	})
}

// @Summary		Get User
// @Description	Get User by ID
// @Tags			User
// @Param			id	path	string	true	"User ID"
// @Router			/users/{id} [GET]
// @Success		200	{object}	models.UserResponse
// @Security BearerAuth
func GetUser(c *fiber.Ctx) error {
	db := initializers.DB
	var user models.UserResponse
	result := db.Model(&models.User{}).First(&user, "id = ?", c.Params("id"))

	if result.Error != nil {
		status := fiber.StatusInternalServerError
		if result.Error.Error() == "record not found" {
			status = fiber.StatusNotFound
		}
		return utils.Error(c, status, result.Error.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"data":    user,
	})
}

// @Summary		Get Users
// @Description	Get all Users
// @Tags			User
// @Router			/users [GET]
// @Success		200	{array}	models.UserResponse
// @Security BearerAuth
func GetUsers(c *fiber.Ctx) error {
	db := initializers.DB
	users := new([]models.UserResponse)
	db.Model(&models.User{}).Find(&users)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"data":    users,
	})
}
