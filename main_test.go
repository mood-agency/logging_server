package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"loggingserver/config"
	"loggingserver/handlers"
	"loggingserver/middleware"
	"loggingserver/utils"

	"github.com/gofiber/fiber/v2"
)

func TestMain(m *testing.M) {
	if err := config.InitApp(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.Exit(code)
}

func setupTestApp() *fiber.App {
	app := config.ConfigureFiber()
	handlers.SetupRoutes(app)
	middleware.ConfigureMiddleware(app)
	return app
}

func sendLogEntry(t *testing.T, app *fiber.App, message string, level string, apiKey string) *http.Response {
	logEntry := handlers.LogEntry{
		Message: message,
		Level:   level,
	}
	jsonData, err := json.Marshal(logEntry)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	req := httptest.NewRequest("POST", "/log", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiKey)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to send log entry: %v", err)
	}
	return resp
}

func TestWriteLogs(t *testing.T) {
	app := setupTestApp()

	apiKey := config.GetEnv("API_KEY", "")

	t.Run("test_write_logs", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				message := fmt.Sprintf("Test log entry %d", i)
				resp := sendLogEntry(t, app, message, "INFO", apiKey)
				if resp.StatusCode != fiber.StatusOK {
					t.Errorf("Unexpected status code: %d", resp.StatusCode)
				}
			}(i)
		}

		wg.Wait()

		// Add a small delay to ensure all goroutines have finished
		time.Sleep(100 * time.Millisecond)

		// Flush the logs
		handlers.FlushLogsOnShutdown()

		// Verify logs were written
		req := httptest.NewRequest("GET", "/logs", nil)
		req.Header.Set("Authorization", apiKey)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Failed to get logs: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		logs := string(body)
		if len(logs) == 0 {
			t.Errorf("No logs were written")
		}

		// Check for specific log entries
		for i := 0; i < 100; i++ {
			expectedLog := fmt.Sprintf("Test log entry %d", i)
			if !bytes.Contains(body, []byte(expectedLog)) {
				t.Errorf("Log entry not found: %s", expectedLog)
			}
		}
	})
}

func TestHandleLog(t *testing.T) {
	app := setupTestApp()

	apiKey := config.GetEnv("API_KEY", "test_api_key")
	os.Setenv("API_KEY", apiKey)

	t.Run("valid_log_entry", func(t *testing.T) {
		resp := sendLogEntry(t, app, "Test log entry", "INFO", apiKey)
		if resp.StatusCode != fiber.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.StatusCode)
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/log", bytes.NewBufferString("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", apiKey)
		resp, _ := app.Test(req)

		if resp.StatusCode != fiber.StatusBadRequest {
			t.Errorf("Expected status BadRequest, got %v", resp.StatusCode)
		}
	})

	t.Run("missing_api_key", func(t *testing.T) {
		resp := sendLogEntry(t, app, "Test log entry", "INFO", "")
		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %v", resp.StatusCode)
		}
	})

	t.Run("invalid_api_key", func(t *testing.T) {
		resp := sendLogEntry(t, app, "Test log entry", "INFO", "invalid_key")
		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %v", resp.StatusCode)
		}
	})

	t.Run("lowercase_log_level", func(t *testing.T) {
		resp := sendLogEntry(t, app, "Test log entry with lowercase level", "info", apiKey)
		if resp.StatusCode != fiber.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.StatusCode)
		}

		// Verify the log was written with lowercase level
		getReq := httptest.NewRequest("GET", "/logs", nil)
		getReq.Header.Set("Authorization", apiKey)
		getResp, _ := app.Test(getReq)
		body, _ := io.ReadAll(getResp.Body)
		
		if !bytes.Contains(body, []byte("INFO: Test log entry with lowercase level")) {
			t.Errorf("Log entry not found or level was not capitalized")
		}
	})
}

func TestHandleViewLogs(t *testing.T) {
	app := setupTestApp()

	apiKey := config.GetEnv("API_KEY", "test_api_key")
	os.Setenv("API_KEY", apiKey)

	t.Run("valid_request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/logs", nil)
		req.Header.Set("Authorization", apiKey)
		resp, _ := app.Test(req)

		if resp.StatusCode != fiber.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType != "text/plain" {
			t.Errorf("Expected Content-Type text/plain, got %v", contentType)
		}
	})

	t.Run("missing_api_key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/logs", nil)
		resp, _ := app.Test(req)

		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %v", resp.StatusCode)
		}
	})

	t.Run("invalid_api_key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/logs", nil)
		req.Header.Set("Authorization", "invalid_key")
		resp, _ := app.Test(req)

		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %v", resp.StatusCode)
		}
	})
}

func TestHandleDeleteLogs(t *testing.T) {
	app := setupTestApp()

	apiKey := config.GetEnv("API_KEY", "test_api_key")
	os.Setenv("API_KEY", apiKey)

	t.Run("valid_request", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/logs", nil)
		req.Header.Set("Authorization", apiKey)
		resp, _ := app.Test(req)

		if resp.StatusCode != fiber.StatusOK {
			t.Errorf("Expected status OK, got %v", resp.StatusCode)
		}

		// Verify logs were deleted
		getReq := httptest.NewRequest("GET", "/logs", nil)
		getReq.Header.Set("Authorization", apiKey)
		getResp, _ := app.Test(getReq)

		body, _ := io.ReadAll(getResp.Body)
		if len(body) > 0 {
			t.Errorf("Expected empty logs after deletion, got: %s", string(body))
		}
	})

	t.Run("missing_api_key", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/logs", nil)
		resp, _ := app.Test(req)

		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %v", resp.StatusCode)
		}
	})

	t.Run("invalid_api_key", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/logs", nil)
		req.Header.Set("Authorization", "invalid_key")
		resp, _ := app.Test(req)

		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %v", resp.StatusCode)
		}
	})
}

func TestSanitizeLogLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "remove_control_chars",
			input:    "Test\x00log\x1Fentry",
			expected: "Testlogentry",
		},
		{
			name:     "escape_html",
			input:    "Test <script>alert('xss')</script>",
			expected: "Test &lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
		},
		{
			name:     "remove_email",
			input:    "Contact us at test@example.com",
			expected: "Contact us at [EMAIL REDACTED]",
		},
		{
			name:     "remove_ip",
			input:    "Request from 192.168.1.1",
			expected: "Request from [IP REDACTED]",
		},
		{
			name:     "remove_credit_card",
			input:    "CC: 1234-5678-9012-3456",
			expected: "CC: [CC REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.SanitizeLogLine(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}