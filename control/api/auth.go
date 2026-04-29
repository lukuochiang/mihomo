package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AuthMode defines authentication mode
type AuthMode string

const (
	AuthModeBearer AuthMode = "bearer" // Bearer Token
	AuthModeAPIKey AuthMode = "apikey" // API Key (X-API-Key header)
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Mode    AuthMode // Authentication mode
	Secret  string   // Shared secret/token
	Enabled bool     // Whether auth is enabled
}

// AuthMiddleware creates an authentication middleware
func AuthMiddleware(cfg AuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			var token string

			switch cfg.Mode {
			case AuthModeBearer:
				// Extract from Authorization: Bearer <token>
				authHeader := r.Header.Get("Authorization")
				if authHeader == "" {
					http.Error(w, "missing authorization header", http.StatusUnauthorized)
					return
				}

				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
					http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
					return
				}
				token = parts[1]

			case AuthModeAPIKey:
				// Extract from X-API-Key header
				token = r.Header.Get("X-API-Key")
				if token == "" {
					http.Error(w, "missing X-API-Key header", http.StatusUnauthorized)
					return
				}

			default:
				http.Error(w, "unknown auth mode", http.StatusInternalServerError)
				return
			}

			// Constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(token), []byte(cfg.Secret)) != 1 {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OptionalAuthMiddleware creates an optional authentication middleware
// It authenticates if credentials are provided but doesn't reject if missing
func OptionalAuthMiddleware(cfg AuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			var token string

			switch cfg.Mode {
			case AuthModeBearer:
				authHeader := r.Header.Get("Authorization")
				if authHeader != "" {
					parts := strings.SplitN(authHeader, " ", 2)
					if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
						token = parts[1]
					}
				}

			case AuthModeAPIKey:
				token = r.Header.Get("X-API-Key")
			}

			// Only validate if token is provided
			if token != "" {
				if subtle.ConstantTimeCompare([]byte(token), []byte(cfg.Secret)) != 1 {
					http.Error(w, "invalid token", http.StatusUnauthorized)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
