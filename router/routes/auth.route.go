package routes

import (
	"github.com/nnhutan/goplock/controllers"

	"github.com/gofiber/fiber/v2"
)

func AuthRoutes(api *fiber.App) {
	api.Route("/auth", func(auth fiber.Router) {
		auth.Post("/register", controllers.Register)
		auth.Post("/login", controllers.Login)
		auth.Post("/refresh", controllers.RefreshAccessToken)
		auth.Delete("/logout", controllers.Logout)
	})
}
