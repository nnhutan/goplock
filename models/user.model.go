package models

import (
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID       uuid.UUID `json:"ID,omitempty" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name     string    `json:"Name,omitempty" gorm:"type:varchar(255);not null"`
	Email    string    `json:"Email,omitempty" gorm:"type:varchar(255);not null;unique;" validate:"email,required"`
	Password string    `json:"Password,omitempty" gorm:"type:varchar(255);not null;" validate:"required,min=8,max=32"`
	Role     string    `json:"Role,omitempty" gorm:"type:varchar(255);not null;default:'user'"`
	Provider string    `json:"Provider,omitempty" gorm:"type:varchar(255);not null;default:'local'"`
	Photo    string    `json:"Photo,omitempty" gorm:"type:varchar(255);not null;default:'https://t4.ftcdn.net/jpg/05/49/98/39/360_F_549983970_bRCkYfk0P6PP5fKbMhZMIb07mCJ6esXL.jpg'"`
	Verified bool      `json:"Verified,omitempty" gorm:"type:boolean;not null;default:false"`
}

var validate *validator.Validate = validator.New()

func ValidateStruct[T any](s T) []string {
	var errors []string
	err := validate.Struct(s)

	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			errors = append(errors, err.Field()+" does not satisfy "+err.Tag()+" condition")
		}
	}
	return errors
}

func FilterUserRecord(user *User) UserResponse {
	return UserResponse{
		ID:       user.ID,
		Name:     user.Name,
		Email:    user.Email,
		Role:     user.Role,
		Photo:    user.Photo,
		Provider: user.Provider,
	}
}

type UserLogin struct {
	Email    string `json:"email,omitempty" validate:"required,email"`
	Password string `json:"password,omitempty" validate:"required"`
}

type UserRegister struct {
	Name                 string `json:"name,omitempty" validate:"required"`
	Email                string `json:"email,omitempty" validate:"required,email"`
	Photo                string `json:"photo,omitempty"`
	Password             string `json:"password,omitempty" validate:"required,min=8,max=32"`
	PasswordConfirmation string `json:"passwordConfirmation,omitempty" validate:"required,eqfield=Password"`
}

type UserResponse struct {
	ID       uuid.UUID `json:"id,omitempty"`
	Name     string    `json:"name,omitempty"`
	Email    string    `json:"email,omitempty"`
	Role     string    `json:"role,omitempty"`
	Photo    string    `json:"photo,omitempty"`
	Provider string    `json:"provider,omitempty"`
}
