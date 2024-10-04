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
	"strings"
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

type LogEntry struct {
	Message string `json:"message"`
	Level   string `json:"level"`
}

// init initializes the global variables for the logging system.
//
// This function is automatically called when the package is imported.
// It sets up the following:
//   - bufferSize: The size of the log buffer in bytes. Default is 1MB.
//   - flushInterval: The interval at which logs are flushed to disk. Default is 1 second.
//
// The function reads configuration values from environment variables:
//   - BUFFER_SIZE: Sets the buffer size in bytes. If invalid, defaults to 1MB.
//   - FLUSH_INTERVAL: Sets the flush interval as a duration string (e.g., "1s", "500ms").
//     If invalid, defaults to 5 seconds.
//
// If there are any errors parsing the environment variables, appropriate warning
// messages are logged, and default values are used.
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

// getRateLimiter retrieves or creates a rate limiter for the given API key.
//
// Parameters:
//   - apiKey string: The API key to get or create a rate limiter for.
//
// Returns:
//   - *rate.Limiter: A pointer to the rate.Limiter for the given API key.
//
// This function is thread-safe and manages a map of rate limiters for different API keys.
// If a rate limiter doesn't exist for the given API key, it creates a new one based on
// the configured rate limit and burst limit from the environment variables.
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

// handleLog processes incoming log entries, validates them, and writes them to the log buffer.
// It handles API key validation, rate limiting, and input validation before appending the log entry.
//
// Parameters:
//   - c *fiber.Ctx: The Fiber context containing the request information.
//
// Returns:
//   - error: An error if any step in the process fails, or nil if successful.
//
// The function performs the following steps:
// 1. Validates the API key and checks for rate limiting.
// 2. Parses the log entry from the request body.
// 3. Validates the log entry (message length and log level).
// 4. Appends the log entry to the buffer.
// 5. Flushes the buffer if it's full or if the flush interval has elapsed.
//
// Possible error responses:
// - 429 Too Many Requests: If the rate limit is exceeded.
// - 400 Bad Request: If the JSON is invalid, the message is too long, or the log level is invalid.
// - 500 Internal Server Error: If there's an error writing to the log file.
// - 200 OK: If the log entry is successfully recorded.
func handleLog(c *fiber.Ctx) error {
	// Validate API key and check for rate limiting
	if err := validateAPIKey(c); err != nil {
		// If the error is due to rate limiting, return immediately
		if err.Error() == "Rate limit exceeded" {
			return c.Status(fiber.StatusTooManyRequests).SendString("Rate limit exceeded")
		}
		return err
	}

	// Parse the log entry from the request body
	var entry LogEntry
	if err := c.BodyParser(&entry); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid JSON")
	}

	// Input validation
	if len(entry.Message) > 1000 {
		return c.Status(fiber.StatusBadRequest).SendString("Message too long")
	}

	// Force log level to uppercase
	entry.Level = strings.ToUpper(entry.Level)

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

// handleViewLogs retrieves and returns the contents of the log file.
//
// Parameters:
//   - c *fiber.Ctx: The Fiber context containing the request information.
//
// Returns:
//   - error: An error if any step in the process fails, or nil if successful.
//
// The function performs the following steps:
// 1. Validates the API key.
// 2. Opens and reads the log file.
// 3. Sanitizes each log line.
// 4. Writes the sanitized logs to the response.
//
// Possible error responses:
// - 401 Unauthorized: If the API key is invalid or missing.
// - 500 Internal Server Error: If there's an error reading the log file or writing to the response.
// - 200 OK: If the logs are successfully retrieved and returned.

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

// handleDeleteLogs deletes the current log file and reinitializes the log writer.
//
// Parameters:
//   - c *fiber.Ctx: The Fiber context containing the request information.
//
// Returns:
//   - error: An error if any step in the process fails, or nil if successful.
//
// The function performs the following steps:
// 1. Validates the API key.
// 2. Closes the current log file and flushes the writer.
// 3. Deletes the log file.
// 4. Reinitializes the log writer.
//
// Possible error responses:
// - 401 Unauthorized: If the API key is invalid or missing.
// - 404 Not Found: If the log file doesn't exist.
// - 500 Internal Server Error: If there's an error deleting the file or reinitializing the log writer.
// - 200 OK: If the log file is successfully deleted and the writer reinitialized.

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

// validateAPIKey checks the validity of the API key provided in the request.
//
// Parameters:
//   - c *fiber.Ctx: The Fiber context containing the request information.
//
// Returns:
//   - error: An error if the API key is invalid, missing, or rate-limited; nil if the key is valid.
//
// The function performs the following steps:
// 1. Retrieves the expected API key from the environment.
// 2. Checks if the API key is set in the environment.
// 3. Extracts the API key from the request's Authorization header.
// 4. Compares the provided API key with the expected key.
// 5. Applies rate limiting to the API key.
//
// Possible error responses:
// - 500 Internal Server Error: If the API_KEY is not set in the environment.
// - 401 Unauthorized: If the API key is missing or invalid.
// - 429 Too Many Requests: If the rate limit for the API key is exceeded.
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

// flushBuffer writes the contents of the logBuffer to the log file and flushes the writer.
// It also resets the buffer and updates the lastFlush time.
//
// Returns:
//   - error: Any error encountered during the write or flush operations.
func flushBuffer() error {

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
