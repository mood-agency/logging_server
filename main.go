package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strconv"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"github.com/joho/godotenv"
)

type LogEntry struct {
	Message string `json:"message"`
	Level   string `json:"level"`
}

var (
	logFile   *os.File
	mu        sync.Mutex
	ctx       context.Context
	logWriter *bufio.Writer
)

// Add this new function
func initLogWriter() error {
	logFilePath := getEnv("LOG_FILE_PATH", "logs.txt")
	var err error
	logFile, err = os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening log file: %v", err)
	}
	logWriter = bufio.NewWriter(logFile)
	return nil
}

func configureFiber() *fiber.App {
	serverHeader := getEnv("SERVER_HEADER", "Go Fiber")
	maxConcurrency, _ := strconv.Atoi(getEnv("MAX_CONCURRENCY", "262144"))

	app := fiber.New(fiber.Config{
		Prefork:       true,
		ServerHeader:  serverHeader,
		StrictRouting: true,
		CaseSensitive: true,
		Concurrency:   maxConcurrency,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			var e *fiber.Error
			if errors.As(err, &e) {
				code = e.Code
			}
			return handleError(c, code, err, "")
		},
	})

	return app
}

func setupRoutes(app *fiber.App) {
	app.Post("/log", handleLog)
	app.Get("/logs", handleViewLogs)

	// Add monitoring endpoint
	app.Get("/metrics", monitor.New())
}

func configureMiddleware(app *fiber.App) {
	// Get CORS allowed origins from environment variable
	allowedOrigins := getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:8080")

	// Add CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))

	// Add compression middleware
	app.Use(compress.New())

	// Add logger middleware
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${method} ${path}\n",
	}))
}

func handleError(c *fiber.Ctx, status int, err error, details string) error {
	log.Printf("Error: %v. Details: %s", err, details)
	return c.Status(status).SendString(fmt.Sprintf("Error: %v. Details: %s", err, details))
}

func main() {
	if err := initApp(); err != nil {
		log.Fatalf("Error initializing app: %v", err)
	}

	app := configureFiber()
	setupRoutes(app)
	configureMiddleware(app)

	app.Use(logger.New())

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Get configuration from environment variables
	logFilePath := getEnv("LOG_FILE_PATH", "logs.txt")
	serverPort := getEnv("SERVER_PORT", "8080")

	var err error
	logFile, err = os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	defer logFile.Close()

	// Initialize logWriter
	logWriter = bufio.NewWriter(logFile)
	defer logWriter.Flush()

	numCPU := runtime.NumCPU()
	log.Printf("Starting server on :%s with %d workers\n", serverPort, numCPU)
	if err := app.Listen(":" + serverPort); err != nil {
		log.Fatalf("Error in ListenAndServe: %v", err)
	}
}

// Update the initApp function
func initApp() error {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	ctx = context.Background()

	// Initialize the log writer
	if err := initLogWriter(); err != nil {
		return err
	}

	return nil
}

func handleLog(c *fiber.Ctx) error {
	// Get the expected user ID from environment variable
	expectedUserID := getEnv("AUTHORIZED_USER_ID", "")
	if expectedUserID == "" {
		return c.Status(fiber.StatusInternalServerError).SendString("AUTHORIZED_USER_ID not set")
	}

	// Get the user ID from the query parameter
	userID := c.Query("user_id")

	// Check if the user ID matches the expected user ID
	if userID != expectedUserID {
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized access")
	}

	var entry LogEntry
	if err := c.BodyParser(&entry); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid JSON")
	}

	mu.Lock()
	defer mu.Unlock()

	if _, err := logWriter.WriteString(entry.Level + ": " + entry.Message + "\n"); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to write log")
	}

	// Flush the writer to ensure the log is written
	if err := logWriter.Flush(); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to flush log")
	}

	return c.SendString("Log entry recorded")
}

func handleViewLogs(c *fiber.Ctx) error {
	// Ensure the log writer is initialized
	if logWriter == nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Log writer not initialized")
	}

	// Get the expected user ID from environment variable
	expectedUserID := getEnv("AUTHORIZED_USER_ID", "")
	if expectedUserID == "" {
		return c.Status(fiber.StatusInternalServerError).SendString("AUTHORIZED_USER_ID not set")
	}

	// Get the user ID from the query parameter
	userID := c.Query("user_id")

	// Check if the user ID matches the expected user ID
	if userID != expectedUserID {
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized access")
	}

	mu.Lock()
	defer mu.Unlock()

	// Make sure the writer is properly initialized
	writer := bufio.NewWriter(c.Response().BodyWriter())
	
	// Flush the writer at the end
	err := writer.Flush()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Error flushing response")
	}

	// Get log file path from environment variable
	logFilePath := getEnv("LOG_FILE_PATH", "logs.txt")

	// Reopen the file for reading
	file, err := os.Open(logFilePath)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to open log file")
	}
	defer file.Close()

	// Set the content type to plain text
	c.Set("Content-Type", "text/plain")

	// Stream the file contents to the response
	_, err = io.Copy(c, file)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to read log file")
	}

	return nil
}

// Helper function to get environment variables with a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Helper function to get boolean environment variables with a default value
// func getEnvBool(key string, defaultValue bool) bool {
// 	value := os.Getenv(key)
// 	if value == "" {
// 		return defaultValue
// 	}
// 	return value == "true" || value == "1" || value == "yes"
// }
