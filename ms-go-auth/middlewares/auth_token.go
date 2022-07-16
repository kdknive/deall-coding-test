package middlewares

import (
	"ms-go-auth/auth" //add this
	"ms-go-auth/responses"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func AuthToken(app *fiber.App) {
	app.Get("/auth", func(c *fiber.Ctx) error {
		tokenString := c.Get("Authorization")
		if tokenString == "" {
			return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": "request does not contain an access token"}})
		}

		err := auth.ValidateToken(tokenString)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": err.Error()}})
		}

		return c.Status(http.StatusOK).JSON(responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": "Token is Valid"}})
	})
}
