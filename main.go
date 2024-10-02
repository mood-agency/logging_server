package main

import (
	"log"
	"loggingserver/config"
	"loggingserver/handlers"
	"loggingserver/middleware"
)

func main() {
	if err := config.InitApp(); err != nil {
		log.Fatalf("Error initializing app: %v", err)
	}

	app := config.ConfigureFiber()

	middleware.ConfigureMiddleware(app)
	handlers.SetupRoutes(app)

	serverPort := config.GetEnv("SERVER_PORT", "8080")
	log.Printf("Starting server on :%s\n", serverPort)
	if err := app.Listen(":" + serverPort); err != nil {
		log.Fatalf("Error in ListenAndServe: %v", err)
	}
}
