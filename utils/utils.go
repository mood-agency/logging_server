package utils

import (
	"html"
	"regexp"
)

func SanitizeLogLine(line string) string {
	line = removeControlChars(line)
	line = html.EscapeString(line)
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

	// Remove potential Social Security Numbers
	s = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`).ReplaceAllString(s, "[SSN REDACTED]")

	// Remove potential API keys or tokens
	s = regexp.MustCompile(`\b([A-Za-z0-9]{32,})\b`).ReplaceAllString(s, "[API_KEY REDACTED]")

	return s
}