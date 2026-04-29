package provider

import (
	"encoding/base64"
	"strings"
)

// DecodeResult holds the result of a base64 decode operation
type DecodeResult struct {
	Data      []byte
	UsedURL   bool
	IsEncoded bool
}

// StdEncoding is the standard base64 encoding
var StdEncoding = &Encoding{
	Std: base64.StdEncoding,
	URL: base64.URLEncoding,
}

// Encoding wraps base64 encodings
type Encoding struct {
	Std *base64.Encoding
	URL *base64.Encoding
}

// Decode decodes a base64 string with automatic encoding detection
func Decode(s string) ([]byte, error) {
	// Add padding if needed
	s = addPadding(s)

	// Try standard encoding first
	if decoded, err := StdEncoding.Std.DecodeString(s); err == nil {
		return decoded, nil
	}

	// Try URL-safe encoding
	return StdEncoding.URL.DecodeString(s)
}

// DecodeString decodes a base64 string with automatic URL-safe detection
func DecodeString(s string) ([]byte, bool, error) {
	// Add padding if needed
	s = addPadding(s)

	// Try standard encoding first
	if decoded, err := StdEncoding.Std.DecodeString(s); err == nil {
		return decoded, false, nil
	}

	// Try URL-safe encoding
	decoded, err := StdEncoding.URL.DecodeString(s)
	return decoded, true, err
}

// IsBase64 checks if a string is valid base64
func IsBase64(s string) bool {
	// Clean the string
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	// Check for valid characters
	for _, c := range s {
		if !isBase64Char(c) {
			return false
		}
	}

	// Try to decode
	_, err := Decode(s)
	return err == nil
}

// IsBase64URL checks if a string is valid URL-safe base64
func IsBase64URL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	// URL-safe base64 uses - and _ instead of + and /
	for _, c := range s {
		if !isBase64URLChar(c) {
			return false
		}
	}

	// Try URL decoding
	_, err := StdEncoding.URL.DecodeString(s)
	return err == nil
}

// IsLikelyBase64 checks if a string is likely to be base64 encoded
// This is more lenient than IsBase64
func IsLikelyBase64(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 4 {
		return false
	}

	// Must have valid ending
	if !strings.HasSuffix(s, "=") && !strings.HasSuffix(s, "==") {
		// Check if length is a multiple of 4 (common for unpadded base64)
		if len(s)%4 != 0 {
			return false
		}
	}

	return IsBase64(s)
}

// DecodeAuto detects and decodes base64 encoded content
func DecodeAuto(content string) (string, bool) {
	// Clean whitespace
	content = strings.TrimSpace(content)
	if content == "" {
		return content, false
	}

	// Check minimum length
	if len(content) < 100 {
		return content, false
	}

	// Check if it looks like base64
	if !IsLikelyBase64(content) {
		return content, false
	}

	decoded, err := Decode(content)
	if err != nil {
		return content, false
	}

	return string(decoded), true
}

// addPadding adds padding characters to make the string valid base64
func addPadding(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

// isBase64Char checks if a character is valid in standard base64
func isBase64Char(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '='
}

// isBase64URLChar checks if a character is valid in URL-safe base64
func isBase64URLChar(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '='
}

// MustDecode decodes a base64 string and panics on error
// Use only when you're certain the input is valid base64
func MustDecode(s string) []byte {
	s = addPadding(s)
	decoded, err := Decode(s)
	if err != nil {
		panic("base64 decode error: " + err.Error())
	}
	return decoded
}

// Encode encodes data to base64 string
func Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// EncodeToURL encodes data to URL-safe base64 string
func EncodeToURL(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// EncodeString encodes a string to base64
func EncodeString(s string) string {
	return Encode([]byte(s))
}
