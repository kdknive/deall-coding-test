package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	Id       primitive.ObjectID `json:"id,omitempty"`
	Role     string             `json:"role,omitempty"`
	Name     string             `json:"name,omitempty" validate:"required"`
	Username string             `json:"username,omitempty" validate:"required"`
	Email    string             `json:"email,omitempty" validate:"required,email"`
	Password string             `json:"password,omitempty" validate:"required"`
}
