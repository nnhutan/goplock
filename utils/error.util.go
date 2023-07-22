package utils

import (
	"reflect"

	"github.com/gofiber/fiber/v2"
)

func Error(ctx *fiber.Ctx, statusCode int, errors interface{}) error {
	var returnObject fiber.Map
	if reflect.TypeOf(errors).Kind() == reflect.String {
		returnObject = fiber.Map{
			"success": false,
			"errors":  []string{errors.(string)},
		}
	} else {
		returnObject = fiber.Map{
			"success": false,
			"errors":  errors,
		}
	}
	return ctx.Status(statusCode).JSON(returnObject)
}
