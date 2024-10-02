package config

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

var (
	LogFile   *os.File
	Mu        sync.Mutex
	Ctx       context.Context
	LogWriter *bufio.Writer
	Verbose   bool
)

func InitApp() error {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	Ctx = context.Background()

	if err := initLogWriter(); err != nil {
		return err
	}

	Verbose, _ = strconv.ParseBool(GetEnv("VERBOSE", "true"))

	return nil
}

func initLogWriter() error {
	logFilePath := GetEnv("LOG_FILE_PATH", "logs.txt")
	var err error
	LogFile, err = os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("error opening log file: %v", err)
	}
	LogWriter = bufio.NewWriter(LogFile)
	return nil
}

func ConfigureFiber() *fiber.App {
	serverHeader := GetEnv("SERVER_HEADER", "Go Fiber")
	maxConcurrency, _ := strconv.Atoi(GetEnv("MAX_CONCURRENCY", "262144"))

	app := fiber.New(fiber.Config{
		Prefork:       true,
		ServerHeader:  serverHeader,
		StrictRouting: true,
		CaseSensitive: true,
		Concurrency:   maxConcurrency,
		ReadTimeout:   5 * time.Second,
		WriteTimeout:  10 * time.Second,
		IdleTimeout:   120 * time.Second,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			var e *fiber.Error
			if errors.As(err, &e) {
				code = e.Code
			}
			return HandleError(c, code, err, "")
		},
	})

	return app
}

func GetEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// func GetRateLimitMax() int {
// 	max, err := strconv.Atoi(GetEnv("RATE_LIMIT_MAX", "100"))
// 	if err != nil {
// 		log.Printf("Invalid RATE_LIMIT_MAX, using default: 100")
// 		return 100
// 	}
// 	return max
// }

func GetRateLimitExpiration() time.Duration {
	expiration, err := time.ParseDuration(GetEnv("RATE_LIMIT_EXPIRATION", "1m"))
	if err != nil {
		log.Printf("Invalid RATE_LIMIT_EXPIRATION, using default: 1 minute")
		return 1 * time.Minute
	}
	return expiration
}

func HandleError(c *fiber.Ctx, status int, err error, details string) error {
	log.Printf("Error: %v. Details: %s", err, details)
	return c.Status(status).SendString(fmt.Sprintf("Error: %v. Details: %s", err, details))
}