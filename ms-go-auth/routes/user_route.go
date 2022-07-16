package routes

import (
	"ms-go-auth/controllers" //add this

	"github.com/gofiber/fiber/v2"
)

func UserRoute(app *fiber.App) {
	app.Post("/login", controllers.GenerateToken)
}
