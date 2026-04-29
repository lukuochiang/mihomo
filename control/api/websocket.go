package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketConfig holds WebSocket API configuration
type WebSocketConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Path    string `yaml:"path"`   // WebSocket path, default "/api/ws"
	Secret  string `yaml:"secret"` // API secret for authentication
}

// WebSocketServer manages WebSocket API connections
type WebSocketServer struct {
	config     *WebSocketConfig
	upgrader   websocket.Upgrader
	clients    map[*WebSocketClient]bool
	mu         sync.RWMutex
	register   chan *WebSocketClient
	unregister chan *WebSocketClient
	broadcast  chan WebSocketMessage
	server     *http.Server
	router     *http.ServeMux
	handlers   map[string]WebSocketHandler
	metrics    *WebSocketMetrics
}

// WebSocketClient represents a connected WebSocket client
type WebSocketClient struct {
	conn   *websocket.Conn
	server *WebSocketServer
	send   chan WebSocketMessage
	authed bool
	groups []string
	mu     sync.Mutex
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type    string          `json:"type"`
	Group   string          `json:"group,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	ID      string          `json:"id,omitempty"`
	Time    int64           `json:"time,omitempty"`
	Error   string          `json:"error,omitempty"`
	Success bool            `json:"success"`
}

// WebSocketHandler defines a handler for WebSocket messages
type WebSocketHandler func(*WebSocketClient, WebSocketMessage) error

// WebSocketMetrics tracks WebSocket metrics
type WebSocketMetrics struct {
	mu            sync.RWMutex
	TotalClients  int64
	TotalMessages int64
	TotalBytes    int64
	ConnectedAt   time.Time
}

// NewWebSocketServer creates a new WebSocket server
func NewWebSocketServer(cfg *WebSocketConfig) *WebSocketServer {
	if cfg == nil {
		cfg = &WebSocketConfig{
			Enabled: true,
			Listen:  "127.0.0.1:9091",
			Path:    "/api/ws",
		}
	}

	ws := &WebSocketServer{
		config: cfg,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Configure for production
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		clients:    make(map[*WebSocketClient]bool),
		register:   make(chan *WebSocketClient),
		unregister: make(chan *WebSocketClient),
		broadcast:  make(chan WebSocketMessage, 256),
		router:     http.NewServeMux(),
		handlers:   make(map[string]WebSocketHandler),
		metrics: &WebSocketMetrics{
			ConnectedAt: time.Now(),
		},
	}

	// Setup routes
	ws.router.HandleFunc(cfg.Path, ws.handleWebSocket)
	ws.router.HandleFunc("/health", ws.handleHealth)

	// Setup built-in handlers
	ws.setupHandlers()

	return ws
}

// setupHandlers registers built-in message handlers
func (s *WebSocketServer) setupHandlers() {
	// Subscribe to groups
	s.handlers["subscribe"] = func(c *WebSocketClient, msg WebSocketMessage) error {
		var req struct {
			Groups []string `json:"groups"`
		}
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return err
		}
		c.groups = append(c.groups, req.Groups...)
		return c.Send(WebSocketMessage{
			Type:    "subscribed",
			Success: true,
			Data:    json.RawMessage(fmt.Sprintf(`{"groups":%s}`, string(msg.Data))),
		})
	}

	// Unsubscribe from groups
	s.handlers["unsubscribe"] = func(c *WebSocketClient, msg WebSocketMessage) error {
		var req struct {
			Groups []string `json:"groups"`
		}
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return err
		}

		groupSet := make(map[string]bool)
		for _, g := range c.groups {
			groupSet[g] = true
		}
		for _, g := range req.Groups {
			delete(groupSet, g)
		}

		c.groups = make([]string, 0, len(groupSet))
		for g := range groupSet {
			c.groups = append(c.groups, g)
		}

		return c.Send(WebSocketMessage{
			Type:    "unsubscribed",
			Success: true,
		})
	}

	// Ping/pong
	s.handlers["ping"] = func(c *WebSocketClient, msg WebSocketMessage) error {
		return c.Send(WebSocketMessage{
			Type:    "pong",
			ID:      msg.ID,
			Success: true,
			Time:    time.Now().UnixMilli(),
		})
	}
}

// RegisterHandler registers a message handler
func (s *WebSocketServer) RegisterHandler(msgType string, handler WebSocketHandler) {
	s.handlers[msgType] = handler
}

// handleWebSocket handles WebSocket upgrade requests
func (s *WebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	if s.config.Secret != "" {
		secret := r.URL.Query().Get("secret")
		if subtle.ConstantTimeCompare([]byte(secret), []byte(s.config.Secret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Upgrade connection
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("websocket upgrade failed", "error", err)
		return
	}

	client := &WebSocketClient{
		conn:   conn,
		server: s,
		send:   make(chan WebSocketMessage, 256),
	}

	s.register <- client

	// Start client goroutines
	go client.writePump()
	go client.readPump()
}

// handleHealth handles health check requests
func (s *WebSocketServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"clients":       len(s.clients),
		"total_clients": s.metrics.TotalClients,
		"uptime":        time.Since(s.metrics.ConnectedAt).String(),
	})
}

// readPump handles incoming messages from client
func (c *WebSocketClient) readPump() {
	defer func() {
		c.server.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Debug("websocket read error", "error", err)
			}
			break
		}

		// Parse message
		var msg WebSocketMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			c.Send(WebSocketMessage{
				Type:  "error",
				Error: fmt.Sprintf("invalid message: %v", err),
			})
			continue
		}

		// Handle message
		if handler, ok := c.server.handlers[msg.Type]; ok {
			if err := handler(c, msg); err != nil {
				c.Send(WebSocketMessage{
					Type:    msg.Type,
					ID:      msg.ID,
					Error:   err.Error(),
					Success: false,
				})
			}
		} else {
			c.Send(WebSocketMessage{
				Type:  "error",
				ID:    msg.ID,
				Error: fmt.Sprintf("unknown message type: %s", msg.Type),
			})
		}
	}
}

// writePump handles outgoing messages to client
func (c *WebSocketClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteJSON(message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Send sends a message to the client
func (c *WebSocketClient) Send(msg WebSocketMessage) error {
	select {
	case c.send <- msg:
		return nil
	default:
		return fmt.Errorf("send buffer full")
	}
}

// SendGroup sends a message to all clients in a group
func (s *WebSocketServer) SendGroup(group string, msg WebSocketMessage) {
	msg.Group = group
	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		for _, g := range client.groups {
			if g == group {
				if err := client.Send(msg); err != nil {
					slog.Warn("failed to send to client", "error", err)
				}
				break
			}
		}
	}
}

// Broadcast sends a message to all connected clients
func (s *WebSocketServer) Broadcast(msg WebSocketMessage) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		if err := client.Send(msg); err != nil {
			slog.Warn("failed to broadcast to client", "error", err)
		}
	}
}

// BroadcastData broadcasts data to all clients
func (s *WebSocketServer) BroadcastData(group, msgType string, data interface{}) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	s.Broadcast(WebSocketMessage{
		Type:    msgType,
		Group:   group,
		Data:    dataBytes,
		Time:    time.Now().UnixMilli(),
		Success: true,
	})
	return nil
}

// eventLoop processes client events
func (s *WebSocketServer) eventLoop() {
	for {
		select {
		case client := <-s.register:
			s.mu.Lock()
			s.clients[client] = true
			s.metrics.mu.Lock()
			s.metrics.TotalClients++
			s.metrics.mu.Unlock()
			s.mu.Unlock()

			slog.Info("websocket client connected", "clients", len(s.clients))

			// Send welcome message
			client.Send(WebSocketMessage{
				Type:    "connected",
				Success: true,
				Data:    json.RawMessage(fmt.Sprintf(`{"id":"%p","time":%d}`, client, time.Now().UnixMilli())),
			})

		case client := <-s.unregister:
			s.mu.Lock()
			if _, ok := s.clients[client]; ok {
				delete(s.clients, client)
				close(client.send)
			}
			s.mu.Unlock()

			slog.Info("websocket client disconnected", "clients", len(s.clients))

		case message := <-s.broadcast:
			s.Broadcast(message)
		}
	}
}

// Start starts the WebSocket server
func (s *WebSocketServer) Start(ctx context.Context) error {
	if !s.config.Enabled {
		return nil
	}

	// Start event loop
	go s.eventLoop()

	// Create HTTP server
	s.server = &http.Server{
		Addr:         s.config.Listen,
		Handler:      s.router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("websocket API server starting", "listen", s.config.Listen, "path", s.config.Path)

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("websocket server error", "error", err)
		}
	}()

	return nil
}

// Stop stops the WebSocket server
func (s *WebSocketServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close all client connections
	for client := range s.clients {
		close(client.send)
		client.conn.Close()
	}

	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// GetMetrics returns WebSocket metrics
func (s *WebSocketServer) GetMetrics() map[string]interface{} {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	s.mu.RLock()
	clientCount := len(s.clients)
	s.mu.RUnlock()

	return map[string]interface{}{
		"connected_clients": clientCount,
		"total_clients":     s.metrics.TotalClients,
		"total_messages":    s.metrics.TotalMessages,
		"total_bytes":       s.metrics.TotalBytes,
		"uptime":            time.Since(s.metrics.ConnectedAt).String(),
	}
}

// WebSocketSubscriptionHandler handles WebSocket subscriptions
type WebSocketSubscriptionHandler struct {
	wsServer *WebSocketServer
}

// NewWebSocketSubscriptionHandler creates a new subscription handler
func NewWebSocketSubscriptionHandler(ws *WebSocketServer) *WebSocketSubscriptionHandler {
	return &WebSocketSubscriptionHandler{wsServer: ws}
}

// SubscribeToTraffic subscribes to traffic updates
func (h *WebSocketSubscriptionHandler) SubscribeToTraffic(client *WebSocketClient) {
	client.groups = append(client.groups, "traffic")
}

// SubscribeToLogs subscribes to log updates
func (h *WebSocketSubscriptionHandler) SubscribeToLogs(client *WebSocketClient) {
	client.groups = append(client.groups, "logs")
}

// SubscribeToStats subscribes to statistics updates
func (h *WebSocketSubscriptionHandler) SubscribeToStats(client *WebSocketClient) {
	client.groups = append(client.groups, "stats")
}

// PublishTraffic publishes traffic data to subscribers
func (h *WebSocketSubscriptionHandler) PublishTraffic(uploadBytes, downloadBytes int64) {
	h.wsServer.SendGroup("traffic", WebSocketMessage{
		Type: "traffic",
		Data: json.RawMessage(fmt.Sprintf(
			`{"upload":%d,"download":%d,"time":%d}`,
			uploadBytes, downloadBytes, time.Now().UnixMilli(),
		)),
	})
}

// PublishLog publishes a log message to subscribers
func (h *WebSocketSubscriptionHandler) PublishLog(level, message string) {
	h.wsServer.SendGroup("logs", WebSocketMessage{
		Type: "log",
		Data: json.RawMessage(fmt.Sprintf(
			`{"level":"%s","message":"%s","time":%d}`,
			level, message, time.Now().UnixMilli(),
		)),
	})
}

// PublishStats publishes statistics to subscribers
func (h *WebSocketSubscriptionHandler) PublishStats(stats map[string]interface{}) {
	data, _ := json.Marshal(stats)
	h.wsServer.SendGroup("stats", WebSocketMessage{
		Type: "stats",
		Data: data,
	})
}

// ConnectionInfo represents WebSocket connection info
type ConnectionInfo struct {
	ID          string    `json:"id"`
	RemoteAddr  string    `json:"remote_addr"`
	Authed      bool      `json:"authed"`
	Groups      []string  `json:"groups"`
	ConnectedAt time.Time `json:"connected_at"`
}
