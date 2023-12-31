package router

import (
	"github.com/nnhutan/goplock/router/routes"

	"github.com/gofiber/fiber/v2"
	_ "github.com/nnhutan/goplock/docs" // docs is generated by Swag CLI, you have to import it.
	"github.com/swaggo/fiber-swagger"
)

// @title			Goplock API
// @description	This is a sample goplock server.
// @BasePath		/api
// @schemes		http https
// @host			localhost:8000
// @version		v1
// @produce		json
// @consumes		json
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
func SetupRoutes(app *fiber.App) {

	api := fiber.New()
	app.Mount("/api", api)

	api.Get("/doc/*", fiberSwagger.WrapHandler)
	api.Get("/healthchecker", func(c *fiber.Ctx) error {
		return c.Status(200).JSON(fiber.Map{
			"status":  "success",
			"message": "Welcome to Golang, Fiber, and GORM",
		})
	})

	routes.AuthRoutes(api)
	routes.UserRoutes(api)
}
