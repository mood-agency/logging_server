package handlers

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"io"
	"log"
	"loggingserver/config"
	"loggingserver/utils"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"golang.org/x/time/rate"
)

var (
	bufferSize    int
	flushInterval time.Duration
	rateLimiter   = make(map[string]*rate.Limiter)
	rateLimiterMu sync.Mutex
	logBuffer     bytes.Buffer
	lastFlush     time.Time
)

func init() {
	var err error
	bufferSize, err = strconv.Atoi(config.GetEnv("BUFFER_SIZE", "1048576"))
	if err != nil {
		log.Printf("Invalid BUFFER_SIZE, using default: 1MB")
		bufferSize = 1024 * 1026 // 1MB buffer
	}

	flushInterval, err = time.ParseDuration(config.GetEnv("FLUSH_INTERVAL", "1s"))
	if err != nil {
		log.Printf("Invalid FLUSH_INTERVAL, using default: 5 seconds")
		flushInterval = 5 * time.Second
	}
}

type LogEntry struct {
	Message string `json:"message"`
	Level   string `json:"level"`
}

func getRateLimiter(apiKey string) *rate.Limiter {
	rateLimiterMu.Lock()
	defer rateLimiterMu.Unlock()

	limiter, exists := rateLimiter[apiKey]
	if !exists {
		// Create a new rate limiter for this API key
		// Allow 10 requests per second with a burst of 20
		rateLimit, _ := strconv.ParseFloat(config.GetEnv("RATE_LIMIT_MAX", "10000"), 64)
		burstLimit, _ := strconv.Atoi(config.GetEnv("RATE_LIMIT_BURST", "20000"))
		limiter = rate.NewLimiter(rate.Limit(rateLimit), burstLimit)
		rateLimiter[apiKey] = limiter
	}

	return limiter
}

func SetupRoutes(app *fiber.App) {
	app.Post("/log", handleLog)
	app.Get("/logs", handleViewLogs)
	app.Delete("/logs", handleDeleteLogs)
	app.Get("/metrics", monitor.New())
}

func handleLog(c *fiber.Ctx) error {
	if err := validateAPIKey(c); err != nil {
		// If the error is due to rate limiting, return immediately
		if err.Error() == "Rate limit exceeded" {
			return c.Status(fiber.StatusTooManyRequests).SendString("Rate limit exceeded")
		}
		return err
	}

	var entry LogEntry
	if err := c.BodyParser(&entry); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid JSON")
	}

	// Input validation
	if len(entry.Message) > 1000 {
		return c.Status(fiber.StatusBadRequest).SendString("Message too long")
	}
	if !isValidLogLevel(entry.Level) {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid log level")
	}

	logLine := entry.Level + ": " + entry.Message + "\n"

	config.Mu.Lock()
	defer config.Mu.Unlock()

	// Append to buffer
	logBuffer.WriteString(logLine)

	// Check if it's time to flush
	if logBuffer.Len() >= bufferSize || time.Since(lastFlush) >= flushInterval {
		if err := flushBuffer(); err != nil {
			log.Printf("Failed to write log: %v", err)
			return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
		}
	}

	return c.SendString("Log entry recorded")
}

func handleViewLogs(c *fiber.Ctx) error {
	if err := validateAPIKey(c); err != nil {
		return err
	}

	logFilePath := config.GetEnv("LOG_FILE_PATH", "logs.txt")

	file, err := os.Open(logFilePath)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
	}
	defer file.Close()

	c.Set("Content-Type", "text/plain")

	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
		}

		sanitizedLine := utils.SanitizeLogLine(line)

		if _, err := c.WriteString(sanitizedLine + "\n"); err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
		}
	}

	return nil
}

func handleDeleteLogs(c *fiber.Ctx) error {
	if err := validateAPIKey(c); err != nil {
		return err
	}

	logFilePath := config.GetEnv("LOG_FILE_PATH", "logs.txt")

	config.Mu.Lock()
	if config.LogFile != nil {
		config.LogFile.Close()
	}
	if config.LogWriter != nil {
		config.LogWriter.Flush()
	}
	config.Mu.Unlock()

	err := os.Remove(logFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return c.Status(fiber.StatusNotFound).SendString("Log file not found")
		}
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to delete log file")
	}

	if err := config.InitApp(); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to reinitialize log writer")
	}

	return c.SendString("Log file deleted successfully")
}

func validateAPIKey(c *fiber.Ctx) error {
	expectedAPIKey := config.GetEnv("API_KEY", "")
	if expectedAPIKey == "" {
		return c.Status(fiber.StatusInternalServerError).SendString("API_KEY not set")
	}

	apiKey := c.Get("Authorization")
	if apiKey == "" || subtle.ConstantTimeCompare([]byte(apiKey), []byte(expectedAPIKey)) != 1 {
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
	}

	// Apply rate limiting
	limiter := getRateLimiter(apiKey)
	if !limiter.Allow() {
		return fiber.NewError(fiber.StatusTooManyRequests, "Rate limit exceeded")
	}

	return nil
}

func flushBuffer() error {
	// flushBuffer writes the contents of the logBuffer to the log file and flushes the writer.
	// It also resets the buffer and updates the lastFlush time.
	//
	// Returns:
	//   - error: Any error encountered during the write or flush operations.
	if logBuffer.Len() == 0 {
		return nil
	}

	if _, err := config.LogWriter.Write(logBuffer.Bytes()); err != nil {
		return err
	}

	if err := config.LogWriter.Flush(); err != nil {
		return err
	}

	logBuffer.Reset()
	lastFlush = time.Now()
	return nil
}

// Add this function to ensure any remaining logs are written when the server shuts down
func FlushLogsOnShutdown() {
	config.Mu.Lock()
	defer config.Mu.Unlock()
	flushBuffer()
}

func isValidLogLevel(level string) bool {
	validLevels := map[string]bool{
		"INFO":    true,
		"WARNING": true,
		"ERROR":   true,
		"DEBUG":   true,
	}
	return validLevels[level]
}
