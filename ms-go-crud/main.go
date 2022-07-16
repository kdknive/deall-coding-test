package main

import (
	"ms-go-crud/configs"
	"ms-go-crud/routes" //add this

	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	//run database
	configs.ConnectDB()

	//routes
	routes.UserRoute(app) //add this

	app.Listen(":7000")
}
