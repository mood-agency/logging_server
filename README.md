# High-Performance Logging Server

This project implements a high-performance logging server in Go using the Fiber web framework. The server receives log entries via an HTTP API and writes them to a file.

## Features

- Fast and efficient logging using Fiber (built on top of fasthttp)
- Multi-process architecture for improved performance on multi-core systems
- Concurrent-safe log writing
- Simple JSON API for submitting log entries
- Buffered file writing for improved performance
- Request logging middleware
- CORS support
- Compression middleware
- Rate limiting
- Monitoring endpoint
- API key authentication
- Log viewing endpoint with sanitization

## Prerequisites

- Go 1.22 or later

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/mood-agency/logging_server.git
   cd high-performance-logger
   ```

2. Install dependencies:

```bash
   go mod download
```

## ENV Configuration

Before running the server, you need to configure your authorized user ID for security purposes. This is done through the `.env` file in the project root.

1. If you haven't already, create a `.env` file in the project root.

2. Add the following line to your `.env` file:

   ```txt
   AUTHORIZED_USER_ID=your-unique-user-id-here
   ```

   Replace `your-unique-user-id-here` with a unique identifier for your authorized user. This could be a UUID, a hash, or any other string that uniquely identifies the authorized user.

3. Make sure to keep this ID secure and do not share it publicly.

This ID will be used to authenticate requests to view logs, ensuring that only authorized users can access the log data.

## Running the Server

To start the server, run:

```bash
go run main.go
```

The server will start on `http://localhost:8080` with multiple worker processes, one for each CPU core.

## Running on Docker

```bash
docker build -t logging-server .
```

Run with Envs

```bash
docker run -p 8080:8080 -e AUTHORIZED_USER_ID=your-unique-user-id-here -e LOG_FILE_PATH=/app/logs.txt -e SERVER_HEADER=Go Fiber -e MAX_CONCURRENCY=262144 -e CORS_ALLOWED_ORIGINS=http://localhost:8080 -e SERVER_PORT=8080 logging-server
```

## Running Tests

To run the tests for this project, use the following command:

```bash
go test -v
```

This command will run all tests in the project and its subdirectories. Make sure you're in the root directory of the project when running this command.

## API

### Log Entry

**Endpoint:** POST `/log`

**Headers:**

- `Content-Type: application/json`
- `Authorization: your-api-key`

**Request Body:**

```json
{
  "message": "Your log message here",
  "level": "LOG_LEVEL"
}
```

Replace `LOG_LEVEL` with the appropriate log level (e.g., INFO, WARNING, ERROR).

**Response:**

- Success: "Log entry recorded" (200 OK)
- Error:
  - 400 Bad Request: "Invalid JSON"
  - 401 Unauthorized: "Unauthorized" (if API key is missing or invalid)
  - 500 Internal Server Error: "API_KEY not set" or "Failed to write log"

**Notes:**

- The API key must be provided in the `Authorization` header.
- The API key should match the one set in the `API_KEY` environment variable.
- Make sure to keep your API key secure and do not share it publicly.

**Example using cURL:**

```bash
curl -X POST http://localhost:8080/log \
  -H "Content-Type: application/json" \
  -H "Authorization: your-api-key-here" \
  -d '{"message": "This is a test log message", "level": "INFO"}'
```

Replace `your-api-key-here` with your actual API key.

### Delete Logs

**Endpoint:** DELETE `/logs`

**Headers:**

- `Authorization: your-api-key`

**Response:**

- Success: "Log file deleted successfully" (200 OK)
- Error:
  - 401 Unauthorized: "Unauthorized" (if API key is missing or invalid)
  - 404 Not Found: "Log file not found"
  - 500 Internal Server Error: "Failed to delete log file" or "Failed to reinitialize log writer"

**Notes:**

- The API key must be provided in the `Authorization` header.
- The API key should match the one set in the `API_KEY` environment variable.
- This operation will delete the entire log file and reinitialize the log writer.

### Monitoring

**Endpoint:** GET `/metrics`

**Description:** This endpoint provides metrics about the server's performance and resource usage like CPU, memory, response time and Open Connections.

## Performance Considerations

- The server uses Fiber's prefork feature to create multiple worker processes.
- Each worker process handles requests independently, utilizing all available CPU cores.
- A buffered writer is used to reduce the number of disk writes.
- A mutex ensures thread-safe access to the log file within each process.
- Request logging middleware is enabled for better observability.

## Configuration

The server writes logs to a file named `logs.txt` in the same directory as the executable. You can modify the file path in the `main.go` file if needed.

## API Usage Examples

Here are examples of how to use the logging API with different programming languages:

### Go

```go
package main

import (
  "bytes"
  "encoding/json"
  "fmt"
  "net/http"
)

func main() {
  logEntry := map[string]string{
    "message": "This is a log message from Go",
    "level":   "INFO",
  }

  jsonData, err := json.Marshal(logEntry)
  if err != nil {
    fmt.Println("Error marshaling JSON:", err)
    return
  }

  resp, err := http.Post("http://localhost:8080/log", "application/json", bytes.NewBuffer(jsonData))
  if err != nil {
    fmt.Println("Error sending request:", err)
    return
  }
  defer resp.Body.Close()

  fmt.Println("Response Status:", resp.Status)
}
```

### JavaScript (Node.js)

```javascript
const axios = require('axios');

const logEntry = {
  message: "This is a log message from JavaScript",
  level: "WARNING"
};

axios.post('http://localhost:8080/log', logEntry)
  .then(response => {
    console.log('Response Status:', response.status);
  })
  .catch(error => {
    console.error('Error:', error);
  });
```

### Python

```python
import requests

log_entry = {
    "message": "This is a log message from Python",
    "level": "ERROR"
}

response = requests.post('http://localhost:8080/log', json=log_entry)
print('Response Status:', response.status_code)
```

Make sure to install the necessary dependencies for JavaScript (`axios`) and Python (`requests`) before running these examples.

## License

This project is licensed under the MIT License.

Copyright (c) [2024] [Argenis León]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
