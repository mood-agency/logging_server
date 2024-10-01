package main

import (
	"bufio"
	"context"
	"crypto/subtle"
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
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/joho/godotenv"
	"html"
	"regexp"
	"time"
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

	// Add rate limiting middleware
	app.Use(limiter.New(limiter.Config{
		Max:        getRateLimitMax(),
		Expiration: getRateLimitExpiration(),
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).SendString("Rate limit exceeded")
		},
	}))

	// Add monitoring endpoint
	app.Get("/metrics", monitor.New())
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
	// Get the expected API key from environment variable
	expectedAPIKey := getEnv("API_KEY", "")
	if expectedAPIKey == "" {
		return c.Status(fiber.StatusInternalServerError).SendString("API_KEY not set")
	}

	// Get the API key from the Authorization header
	apiKey := c.Get("Authorization")

	// Check if the API key is provided and matches the expected API key
	if apiKey == "" || subtle.ConstantTimeCompare([]byte(apiKey), []byte(expectedAPIKey)) != 1 {
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
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
		return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
	}

	// Get the expected API key from environment variable
	expectedAPIKey := getEnv("API_KEY", "")
	if expectedAPIKey == "" {
		return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
	}

	// Get the API key from the Authorization header
	apiKey := c.Get("Authorization")

	// Check if the API key is provided and matches the expected API key
	if apiKey == "" || subtle.ConstantTimeCompare([]byte(apiKey), []byte(expectedAPIKey)) != 1 {
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
	}

	// Get log file path from environment variable
	logFilePath := getEnv("LOG_FILE_PATH", "logs.txt")

	// Open the file for reading
	file, err := os.Open(logFilePath)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
	}
	defer file.Close()

	// Set the content type to plain text
	c.Set("Content-Type", "text/plain")

	// Create a buffered reader
	reader := bufio.NewReader(file)

	// Stream and sanitize the file contents to the response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
		}

		// Sanitize the log line
		sanitizedLine := sanitizeLogLine(line)

		// Write the sanitized line to the response
		if _, err := c.Write([]byte(sanitizedLine)); err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
		}
	}

	return nil
}

func sanitizeLogLine(line string) string {
	// Remove any control characters
	line = removeControlChars(line)

	// Escape HTML special characters
	line = html.EscapeString(line)

	// Remove any potential sensitive information
	line = removeSensitiveInfo(line)

	return line
}

func removeControlChars(s string) string {
	return regexp.MustCompile(`[\x00-\x1F\x7F]`).ReplaceAllString(s, "")
}

func removeSensitiveInfo(s string) string {
	// Remove email addresses
	s = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`).ReplaceAllString(s, "[EMAIL REDACTED]")

	// Remove IP addresses
	s = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`).ReplaceAllString(s, "[IP REDACTED]")

	// Remove potential credit card numbers
	s = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`).ReplaceAllString(s, "[CC REDACTED]")

	// Add more patterns here as needed

	return s
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

// Add these new functions
func getRateLimitMax() int {
	max, err := strconv.Atoi(getEnv("RATE_LIMIT_MAX", "100"))
	if err != nil {
		log.Printf("Invalid RATE_LIMIT_MAX, using default: 100")
		return 100
	}
	return max
}

func getRateLimitExpiration() time.Duration {
	expiration, err := time.ParseDuration(getEnv("RATE_LIMIT_EXPIRATION", "1m"))
	if err != nil {
		log.Printf("Invalid RATE_LIMIT_EXPIRATION, using default: 1 minute")
		return 1 * time.Minute
	}
	return expiration
}
