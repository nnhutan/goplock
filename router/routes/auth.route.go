package routes

import (
	"github.com/nnhutan/goplock/controllers"
	"github.com/nnhutan/goplock/middlewares"

	"github.com/gofiber/fiber/v2"
)

func AuthRoutes(api *fiber.App) {
	api.Route("/auth", func(auth fiber.Router) {
		auth.Post("/register", controllers.Register)
		auth.Post("/login", controllers.Login)
		auth.Post("/refresh", controllers.RefreshAccessToken)
		auth.Delete("/logout", middlewares.AuthenticateUser, controllers.Logout)

		auth.Post("/verify-email", middlewares.AuthenticateUser, controllers.SendEmailVerification)
		auth.Get("/verify-email/:code", controllers.VerifyEmail)

		auth.Get("/oauth/google", controllers.GoogleOAuth)

		auth.Post("/forgot-password", controllers.ForgotPassword)
		auth.Patch("/reset-password/:resetToken", controllers.ResetPassword)
		auth.Patch("/password", middlewares.AuthenticateUser, controllers.ChangePassword)
	})
}
