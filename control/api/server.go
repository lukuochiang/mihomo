package api

import (
	"encoding/json"
	"net/http"

	"github.com/lukuochiang/mihomo/control"

	"go.uber.org/zap"
)

// Server is the API server
type Server struct {
	config        APIConfig
	auth          AuthConfig
	controller    *control.Controller
	logger        *zap.Logger
	mux           *http.ServeMux
	reloadHandler *control.APIReloadHandler
}

// APIConfig holds API configuration
type APIConfig struct {
	Listen string
	Secret string
}

// NewServer creates a new API server
func NewServer(cfg APIConfig, authCfg AuthConfig, ctrl *control.Controller, logger *zap.Logger) *Server {
	s := &Server{
		config:     cfg,
		auth:       authCfg,
		controller: ctrl,
		logger:     logger,
		mux:        http.NewServeMux(),
	}

	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	// Apply authentication middleware
	authHandler := AuthMiddleware(s.auth)

	// Protected routes
	protected := authHandler(http.HandlerFunc(s.handleNodes))
	s.mux.Handle("/v1/nodes", protected)

	protectedNode := authHandler(http.HandlerFunc(s.handleNodeInfo))
	s.mux.Handle("/v1/node/", protectedNode)

	protectedStats := authHandler(http.HandlerFunc(s.handleStats))
	s.mux.Handle("/v1/stats", protectedStats)

	protectedSelect := authHandler(http.HandlerFunc(s.handleSelect))
	s.mux.Handle("/v1/select", protectedSelect)

	// Reload endpoints
	protectedReload := authHandler(http.HandlerFunc(s.handleReload))
	s.mux.Handle("/v1/reload", protectedReload)

	protectedReloadStatus := authHandler(http.HandlerFunc(s.handleReloadStatus))
	s.mux.Handle("/v1/reload/status", protectedReloadStatus)

	// Health check is public
	s.mux.HandleFunc("/health", s.handleHealth)
}

// RegisterReloadHandler registers a reload handler with the API server
func (s *Server) RegisterReloadHandler(h *control.ReloadHandler) {
	if h != nil {
		s.reloadHandler = control.NewAPIReloadHandler(h, s.config.Secret)
	}
}

// Start starts the API server
func (s *Server) Start() error {
	s.logger.Info("starting API server", zap.String("addr", s.config.Listen))
	return http.ListenAndServe(s.config.Listen, s.mux)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	stats := s.controller.GetSmart().GetStats()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total": stats.TotalNodes,
		"mode":  stats.Mode,
		"best":  stats.BestNode,
	})
}

func (s *Server) handleNodeInfo(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement node info endpoint
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := s.controller.GetMetrics().GetStats()
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleSelect(w http.ResponseWriter, r *http.Request) {
	node, err := s.controller.SelectNode(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"node": node})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if s.reloadHandler == nil {
		http.Error(w, "reload not enabled", http.StatusNotFound)
		return
	}

	secret := r.Header.Get("Authorization")
	if secret != "" {
		secret = secret[7:] // Remove "Bearer " prefix
	}

	configPath := r.URL.Query().Get("path")
	if err := s.reloadHandler.HandleReload(r.Context(), secret, configPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func (s *Server) handleReloadStatus(w http.ResponseWriter, r *http.Request) {
	if s.reloadHandler == nil {
		http.Error(w, "reload not enabled", http.StatusNotFound)
		return
	}

	status := control.ReloadStatus{
		Enabled:    true,
		WatchPaths: []string{},
	}
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
