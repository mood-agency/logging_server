# High-Performance Logging Server

This project implements a high-performance logging server in Go using the Fiber web framework. The server receives log entries via an HTTP API and writes them to a file.

## Features

- Fast and efficient logging using Fiber (built on top of fasthttp)
- Multi-process architecture for improved performance on multi-core systems
- Concurrent-safe log writing
- Simple JSON API for submitting log entries
- Buffered file writing for improved performance
- Request logging middleware

## Prerequisites

- Go 1.22 or later

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/high-performance-logger.git
   cd high-performance-logger
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

## Running the Server

To start the server, run:
```bash
go run main.go
```

The server will start on `http://localhost:8080` with multiple worker processes, one for each CPU core.






## Running Tests

To run the tests for this project, use the following command:

```bash
go test ./...
```

This command will run all tests in the project and its subdirectories. Make sure you're in the root directory of the project when running this command.

## API

### Log Entry

**Endpoint:** POST `/log`

**Request Body:**
json
{
"message": "Your log message here",
"level": "LOG_LEVEL"
}

Replace `LOG_LEVEL` with the appropriate log level (e.g., INFO, WARNING, ERROR).

**Response:**
- Success: "Log entry recorded" (200 OK)
- Error: Appropriate error message with corresponding HTTP status code

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

## Performance Considerations

- The server uses Fiber's prefork feature to create multiple worker processes.
- Each worker process handles requests independently, utilizing all available CPU cores.
- A buffered writer is used to reduce the number of disk writes.
- A mutex ensures thread-safe access to the log file within each process.
- Request logging middleware is enabled for better observability.

## Configuration

The server writes logs to a file named `logs.txt` in the same directory as the executable. You can modify the file path in the `main.go` file if needed.


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
