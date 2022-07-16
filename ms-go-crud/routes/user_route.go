package routes

import (
	"ms-go-crud/controllers" //add this

	"github.com/gofiber/fiber/v2"
)

func UserRoute(app *fiber.App) {
	app.Post("/admin/first", controllers.CreateFirstAdmin)
	app.Post("/admin", controllers.CreateAdmin)
	app.Post("/user", controllers.CreateUser)              //add this
	app.Get("/user/:username", controllers.GetAUser)       //add this
	app.Put("/user/:username", controllers.EditAUser)      //add this
	app.Delete("/user/:username", controllers.DeleteAUser) //add this
	app.Get("/users", controllers.GetAllUsers)             //add this
}
