package routes

import (
	"github.com/nnhutan/goplock/controllers"
	"github.com/nnhutan/goplock/middlewares"

	"github.com/gofiber/fiber/v2"
)

func UserRoutes(api *fiber.App) {
	api.Route("/users", func(user fiber.Router) {
		user.Use(middlewares.AuthenticateUser)

		user.Get("/me", controllers.GetMe)
		user.Get("/:id", controllers.GetUser)
		user.Get("/", controllers.GetUsers)
	})
}
