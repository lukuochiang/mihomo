package transport

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// WebSocketConfig holds WebSocket configuration
type WebSocketConfig struct {
	Enabled bool
	Path    string
	Host    string
	Headers map[string]string
	TLS     TLSConfig
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled    bool
	ServerName string
	Insecure   bool
	CertFile   string
	KeyFile    string
	MinVersion uint16
	MaxVersion uint16
}

// WebSocketConn is a WebSocket connection
type WebSocketConn struct {
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	mu        sync.Mutex
	isClient  bool
	fragments [][]byte
}

// WebSocketFrame represents a WebSocket frame
type WebSocketFrame struct {
	FIN     bool
	OpCode  byte
	Mask    bool
	MaskKey [4]byte
	Payload []byte
}

// WebSocket opcodes
const (
	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xA
)

// NewWebSocketConn creates a new WebSocket connection
func NewWebSocketConn(conn net.Conn, isClient bool) *WebSocketConn {
	return &WebSocketConn{
		conn:     conn,
		reader:   bufio.NewReader(conn),
		writer:   bufio.NewWriter(conn),
		isClient: isClient,
	}
}

// Read reads data from WebSocket
func (c *WebSocketConn) Read(b []byte) (int, error) {
	frame, err := c.ReadFrame()
	if err != nil {
		return 0, err
	}

	n := copy(b, frame.Payload)
	return n, nil
}

// ReadFrame reads a WebSocket frame
func (c *WebSocketConn) ReadFrame() (*WebSocketFrame, error) {
	// Read first two bytes
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return nil, err
	}

	frame := &WebSocketFrame{
		FIN:    (header[0] & 0x80) != 0,
		OpCode: header[0] & 0x0F,
		Mask:   (header[1] & 0x80) != 0,
	}

	// Read payload length
	payloadLen := uint64(header[1] & 0x7F)
	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, ext); err != nil {
			return nil, err
		}
		payloadLen = uint64(ext[0])<<8 | uint64(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, ext); err != nil {
			return nil, err
		}
		payloadLen = uint64(ext[0])<<56 |
			uint64(ext[1])<<48 |
			uint64(ext[2])<<40 |
			uint64(ext[3])<<32 |
			uint64(ext[4])<<24 |
			uint64(ext[5])<<16 |
			uint64(ext[6])<<8 |
			uint64(ext[7])
	}

	// Read mask key if present
	if frame.Mask {
		if _, err := io.ReadFull(c.reader, frame.MaskKey[:]); err != nil {
			return nil, err
		}
	}

	// Read payload
	if payloadLen > 0 {
		frame.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(c.reader, frame.Payload); err != nil {
			return nil, err
		}

		// Decode mask if needed
		if frame.Mask {
			for i := range frame.Payload {
				frame.Payload[i] ^= frame.MaskKey[i%4]
			}
		}
	}

	// Handle continuation frames
	if frame.OpCode == OpContinuation && !frame.FIN {
		c.fragments = append(c.fragments, frame.Payload)
		return c.ReadFrame() // Read next frame
	}

	if len(c.fragments) > 0 {
		c.fragments = append(c.fragments, frame.Payload)
		frame.Payload = bytes.Join(c.fragments, nil)
		c.fragments = nil
	}

	return frame, nil
}

// Write writes data to WebSocket
func (c *WebSocketConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	frame := &WebSocketFrame{
		FIN:     true,
		OpCode:  OpBinary,
		Payload: b,
	}

	if c.isClient {
		frame.Mask = true
		rand.Read(frame.MaskKey[:])
	}

	if err := c.WriteFrame(frame); err != nil {
		return 0, err
	}

	c.writer.Flush()
	return len(b), nil
}

// WriteFrame writes a WebSocket frame
func (c *WebSocketConn) WriteFrame(frame *WebSocketFrame) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Write header
	header := make([]byte, 2)
	if frame.FIN {
		header[0] |= 0x80
	}
	header[0] |= frame.OpCode & 0x0F

	if frame.Mask {
		header[1] |= 0x80
	}

	payloadLen := len(frame.Payload)
	switch {
	case payloadLen < 126:
		header[1] |= byte(payloadLen)
		c.writer.Write(header[:2])
	case payloadLen < 65536:
		header[1] |= 126
		c.writer.Write(header[:2])
		ext := make([]byte, 2)
		ext[0] = byte(payloadLen >> 8)
		ext[1] = byte(payloadLen)
		c.writer.Write(ext)
	default:
		header[1] |= 127
		c.writer.Write(header[:2])
		ext := make([]byte, 8)
		for i := 7; i >= 0; i-- {
			ext[i] = byte(payloadLen)
			payloadLen >>= 8
		}
		c.writer.Write(ext)
	}

	// Write mask key if needed
	if frame.Mask {
		c.writer.Write(frame.MaskKey[:])
	}

	// Write payload with mask
	if frame.Mask && len(frame.Payload) > 0 {
		masked := make([]byte, len(frame.Payload))
		for i := range frame.Payload {
			masked[i] = frame.Payload[i] ^ frame.MaskKey[i%4]
		}
		c.writer.Write(masked)
	} else {
		c.writer.Write(frame.Payload)
	}

	return c.writer.Flush()
}

// Close closes the WebSocket connection
func (c *WebSocketConn) Close() error {
	// Send close frame
	frame := &WebSocketFrame{
		FIN:     true,
		OpCode:  OpClose,
		Payload: []byte{0x03, 0xE8}, // 1000 = normal close
	}
	if c.isClient {
		frame.Mask = true
		rand.Read(frame.MaskKey[:])
	}
	c.WriteFrame(frame)
	return c.conn.Close()
}

// LocalAddr returns local address
func (c *WebSocketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (c *WebSocketConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets deadline
func (c *WebSocketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (c *WebSocketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (c *WebSocketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// WebSocketDialer dials WebSocket connections
type WebSocketDialer struct {
	Config WebSocketConfig
}

// NewWebSocketDialer creates a new WebSocket dialer
func NewWebSocketDialer(cfg WebSocketConfig) *WebSocketDialer {
	return &WebSocketDialer{Config: cfg}
}

// Dial dials a WebSocket connection
func (d *WebSocketDialer) Dial(target string) (net.Conn, error) {
	// Connect to server
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS if needed
	if d.Config.TLS.Enabled {
		tlsConfig := &tls.Config{
			ServerName:         d.Config.TLS.ServerName,
			InsecureSkipVerify: d.Config.TLS.Insecure,
		}
		conn = tls.Client(conn, tlsConfig)
	}

	// Perform WebSocket handshake
	if err := d.handshake(conn, d.Config.Path); err != nil {
		conn.Close()
		return nil, err
	}

	return NewWebSocketConn(conn, true), nil
}

func (d *WebSocketDialer) handshake(conn net.Conn, path string) error {
	// Build request
	host := d.Config.Host
	if host == "" {
		host = conn.RemoteAddr().String()
	}

	pathStr := path
	if pathStr == "" {
		pathStr = "/"
	}

	key := generateWebSocketKey()

	req := fmt.Sprintf("GET %s HTTP/1.1\r\n", pathStr)
	req += fmt.Sprintf("Host: %s\r\n", host)
	req += "Upgrade: websocket\r\n"
	req += "Connection: Upgrade\r\n"
	req += "Sec-WebSocket-Version: 13\r\n"
	req += fmt.Sprintf("Sec-WebSocket-Key: %s\r\n", key)
	req += "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"

	// Add custom headers
	for k, v := range d.Config.Headers {
		req += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 101 {
		return fmt.Errorf("WebSocket handshake failed: %d", resp.StatusCode)
	}

	return nil
}

func generateWebSocketKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// WebSocketServer is a WebSocket server
type WebSocketServer struct {
	Config  WebSocketConfig
	Handler func(net.Conn)
}

// NewWebSocketServer creates a new WebSocket server
func NewWebSocketServer(cfg WebSocketConfig) *WebSocketServer {
	return &WebSocketServer{Config: cfg}
}

// Serve serves WebSocket connections
func (s *WebSocketServer) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go s.handle(conn)
	}
}

func (s *WebSocketServer) handle(conn net.Conn) {
	defer conn.Close()

	// Read HTTP upgrade request
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	// Check WebSocket upgrade
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return
	}

	// Verify key
	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return
	}

	// Build response
	accept := computeWebSocketAccept(key)

	resp := "HTTP/1.1 101 Switching Protocols\r\n"
	resp += "Upgrade: websocket\r\n"
	resp += "Connection: Upgrade\r\n"
	resp += fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", accept)
	resp += "\r\n"

	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}

	// Handle WebSocket connection
	wsConn := NewWebSocketConn(conn, false)
	if s.Handler != nil {
		s.Handler(wsConn)
	}
}

func computeWebSocketAccept(key string) string {
	// RFC 6455: accept = BASE64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	data := key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.Sum([]byte(data))
	return base64.StdEncoding.EncodeToString(h[:])
}

// WebSocketProxy proxies WebSocket connections
type WebSocketProxy struct {
	Target string
}

// NewWebSocketProxy creates a new WebSocket proxy
func NewWebSocketProxy(target string) *WebSocketProxy {
	return &WebSocketProxy{Target: target}
}

// ServeHTTP handles HTTP upgrade for WebSocket
func (p *WebSocketProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Upgrade to WebSocket
	if _, err := io.ReadFull(r.Body, nil); err != nil && err != io.EOF {
		http.Error(w, "Bad Request", 400)
		return
	}

	// Hijack connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Not Implementable", 501)
		return
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", p.Target, 10*time.Second)
	if err != nil {
		conn.Close()
		return
	}

	// Forward request to target
	if r != nil {
		r.Write(targetConn)
	}

	// Bidirectional copy
	go io.Copy(targetConn, conn)
	go io.Copy(conn, targetConn)
}

// WithWebSocketProxy wraps a dialer with WebSocket proxy
func WithWebSocketProxy(dialer proxy.Dialer, config WebSocketConfig) proxy.Dialer {
	return &webSocketProxyDialer{
		dialer: dialer,
		config: config,
	}
}

type webSocketProxyDialer struct {
	dialer proxy.Dialer
	config WebSocketConfig
}

func (d *webSocketProxyDialer) Dial(network, addr string) (net.Conn, error) {
	wsDialer := NewWebSocketDialer(d.config)
	return wsDialer.Dial(addr)
}
