package models

import (
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type User struct {
	ID        uuid.UUID `json:"id,omitempty" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name      string    `json:"name,omitempty" gorm:"type:varchar(255);not null"`
	Email     string    `json:"email,omitempty" gorm:"type:varchar(255);not null;unique"`
	Password  string    `json:"password,omitempty" gorm:"type:varchar(255);not null"`
	CreatedAt time.Time `json:"created_at,omitempty" gorm:"type:timestamp;not null;default:now()"`
	UpdatedAt time.Time `json:"updated_at,omitempty" gorm:"type:timestamp;not null;default:now()"`
}

var validate *validator.Validate = validator.New()

type ErrorResponse struct {
	FailedField string `json:"failed_field"`
	Tag         string `json:"tag"`
	Value       string `json:"value,omitempty"`
}

func ValidateStruct[T any](s T) []ErrorResponse {
	var errors []ErrorResponse
	err := validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			errors = append(errors, ErrorResponse{
				FailedField: err.Field(),
				Tag:         err.Tag(),
				Value:       err.Param(),
			})
		}
	}
	return errors
}

type UserLogin struct {
	Email    string `json:"email,omitempty" validate:"required,email"`
	Password string `json:"password,omitempty" validate:"required"`
}

type UserRegister struct {
	Name     string `json:"name,omitempty" validate:"required"`
	Email    string `json:"email,omitempty" validate:"required,email"`
	Password string `json:"password,omitempty" validate:"required"`
}
