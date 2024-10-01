package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestMain(m *testing.M) {
	if err := initApp(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.Exit(code)
}

func TestWriteLogs(t *testing.T) {
	app := configureFiber()
	setupRoutes(app)
	configureMiddleware(app)

	t.Run("test_write_logs", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				logEntry := LogEntry{
					Message: fmt.Sprintf("Test log entry %d", i),
					Level:   "INFO",
				}
				jsonData, err := json.Marshal(logEntry)
				if err != nil {
					t.Errorf("Failed to marshal JSON: %v", err)
					return
				}

				apiKey := getEnv("API_KEY", "")
				req := httptest.NewRequest("POST", "/log", bytes.NewBuffer(jsonData))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", apiKey)
				resp, err := app.Test(req)
				if err != nil {
					t.Errorf("Failed to send log entry: %v", err)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != fiber.StatusOK {
					body, _ := io.ReadAll(resp.Body)
					t.Errorf("Unexpected status code: %d, body: %s", resp.StatusCode, string(body))
					return
				}
			}(i)
		}

		wg.Wait()

		// Verify logs were written
		apiKey := getEnv("API_KEY", "")
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
	app := configureFiber()
	setupRoutes(app)
	configureMiddleware(app)

	apiKey := getEnv("API_KEY", "test_api_key")
	os.Setenv("API_KEY", apiKey)

	t.Run("valid_log_entry", func(t *testing.T) {
		logEntry := LogEntry{
			Message: "Test log entry",
			Level:   "INFO",
		}
		jsonData, _ := json.Marshal(logEntry)

		req := httptest.NewRequest("POST", "/log", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", apiKey)
		resp, _ := app.Test(req)

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
		logEntry := LogEntry{
			Message: "Test log entry",
			Level:   "INFO",
		}
		jsonData, _ := json.Marshal(logEntry)

		req := httptest.NewRequest("POST", "/log", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		resp, _ := app.Test(req)

		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %v", resp.StatusCode)
		}
	})

	t.Run("invalid_api_key", func(t *testing.T) {
		logEntry := LogEntry{
			Message: "Test log entry",
			Level:   "INFO",
		}
		jsonData, _ := json.Marshal(logEntry)

		req := httptest.NewRequest("POST", "/log", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "invalid_key")
		resp, _ := app.Test(req)

		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Errorf("Expected status Unauthorized, got %v", resp.StatusCode)
		}
	})
}

func TestHandleViewLogs(t *testing.T) {
	app := configureFiber()
	setupRoutes(app)
	configureMiddleware(app)

	apiKey := getEnv("API_KEY", "test_api_key")
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
			result := sanitizeLogLine(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}