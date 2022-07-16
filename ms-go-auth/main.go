package main

import (
	"ms-go-auth/configs"
	"ms-go-auth/middlewares"
	"ms-go-auth/routes" //add this

	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	//run database
	configs.ConnectDB()

	//routes
	routes.UserRoute(app) //add this

	middlewares.AuthToken(app)

	app.Listen(":6000")
}
