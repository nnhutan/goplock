package main

import (
	"context"
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/nnhutan/goplock/initializers"
	"github.com/nnhutan/goplock/router"
	"github.com/redis/go-redis/v9"
)

func init() {
	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatalln("Failed to load environment variables! \n", err.Error())
	}
	initializers.ConnectDB(&config)
	initializers.ConnectRedis(&config)
}

func main() {
	app := fiber.New()

	app.Use(logger.New())
	app.Use(cors.New())

	ctx := context.TODO()
	_, err := initializers.RedisClient.Get(ctx, "test").Result()

	if err == redis.Nil {
		fmt.Println("key: test does not exist")
	} else if err != nil {
		panic(err)
	}
	router.SetupRoutes(app)

	log.Fatal(app.Listen(":8000"))
}
