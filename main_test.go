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

				authorizedUserID := getEnv("AUTHORIZED_USER_ID", "")
				url := fmt.Sprintf("/log?user_id=%s", authorizedUserID)
				req := httptest.NewRequest("POST", url, bytes.NewBuffer(jsonData))
				req.Header.Set("Content-Type", "application/json")
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
		authorizedUserID := getEnv("AUTHORIZED_USER_ID", "")
		url := fmt.Sprintf("/logs?user_id=%s", authorizedUserID)
		req := httptest.NewRequest("GET", url, nil)
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