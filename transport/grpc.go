package transport

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"
)

// GRPCConfig holds gRPC configuration
type GRPCConfig struct {
	Enabled     bool
	ServiceName string
	IDleTimeout time.Duration
	HealthCheck bool
}

// GRPCConn is a gRPC connection
type GRPCConn struct {
	conn        net.Conn
	reader      *bufio.Reader
	writer      *bufio.Writer
	frameReader *hpack.Decoder
	frameWriter *hpack.Encoder
	mu          sync.Mutex
}

// NewGRPCConn creates a new gRPC connection
func NewGRPCConn(conn net.Conn) *GRPCConn {
	w := bufio.NewWriter(conn)
	return &GRPCConn{
		conn:        conn,
		reader:      bufio.NewReader(conn),
		writer:      w,
		frameReader: hpack.NewDecoder(4096, nil),
		frameWriter: hpack.NewEncoder(w),
	}
}

// GRPCFrame represents a gRPC frame
type GRPCFrame struct {
	Type     GRPCFrameType
	StreamID uint32
	Data     []byte
}

// GRPCFrameType represents gRPC frame types
type GRPCFrameType uint8

const (
	GRPCFrameData GRPCFrameType = 0x00
	GRPCFrameHead GRPCFrameType = 0x01
)

// GRPCHeader represents gRPC request/response header
type GRPCHeader struct {
	StreamID    uint32
	Flags       uint8
	Path        string
	Method      string
	Authority   string
	Timeout     string
	Status      string
	StatusMsg   string
	ContentType string
}

// GRPCDialer dials gRPC connections
type GRPCDialer struct {
	Config GRPCConfig
}

// NewGRPCDialer creates a new gRPC dialer
func NewGRPCDialer(cfg GRPCConfig) *GRPCDialer {
	return &GRPCDialer{Config: cfg}
}

// Dial dials a gRPC connection
func (d *GRPCDialer) Dial(target string) (*GRPCConn, error) {
	// Connect to server
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Initialize HTTP/2
	if err := d.initHTTP2(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return NewGRPCConn(conn), nil
}

func (d *GRPCDialer) initHTTP2(conn net.Conn) error {
	// Send HTTP/2 connection preface
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err := conn.Write(preface); err != nil {
		return err
	}

	// Send settings frame
	settings := []byte{
		0x00, 0x00, 0x00, // Length (0)
		0x04,                   // Type (SETTINGS)
		0x00,                   // Flags
		0x00, 0x00, 0x00, 0x00, // Stream ID
	}

	// Settings
	settings = append(settings,
		0x00, 0x03, // SETTINGS_HEADER_TABLE_SIZE
		0x00, 0x00, 0x40, 0x00, // 16384
		0x00, 0x01, // SETTINGS_ENABLE_PUSH
		0x00, 0x00, 0x00, 0x01, // 1 (true)
		0x00, 0x04, // SETTINGS_INITIAL_WINDOW_SIZE
		0x00, 0x00, 0x10, 0x00, // 65536
	)

	binary.BigEndian.PutUint32(settings[:3], uint32(len(settings)-9))
	if _, err := conn.Write(settings); err != nil {
		return err
	}

	return nil
}

// Read reads data from gRPC connection
func (c *GRPCConn) Read(b []byte) (int, error) {
	frame, err := c.ReadFrame()
	if err != nil {
		return 0, err
	}

	n := copy(b, frame.Data)
	return n, nil
}

// ReadFrame reads a gRPC frame
func (c *GRPCConn) ReadFrame() (*GRPCFrame, error) {
	// Read frame header
	header := make([]byte, 9)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32([]byte{0, header[0], header[1], header[2]})
	frameType := GRPCFrameType(header[3])
	_ = header[4] // flags - reserved for frame type processing
	streamID := binary.BigEndian.Uint32(header[5:9]) & 0x7FFFFFFF

	// Read frame data
	data := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(c.reader, data); err != nil {
			return nil, err
		}
	}

	return &GRPCFrame{
		Type:     frameType,
		StreamID: streamID,
		Data:     data,
	}, nil
}

// Write writes data to gRPC connection
func (c *GRPCConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Write DATA frame
	frame := c.buildDataFrame(0, 0x01, b)
	if _, err := c.writer.Write(frame); err != nil {
		return 0, err
	}

	if err := c.writer.Flush(); err != nil {
		return 0, err
	}

	return len(b), nil
}

// WriteFrame writes a gRPC frame
func (c *GRPCConn) WriteFrame(frame *GRPCFrame) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var data []byte
	switch frame.Type {
	case GRPCFrameData:
		data = c.buildDataFrame(frame.StreamID, 0x01, frame.Data)
	case GRPCFrameHead:
		data = c.buildHeadersFrame(frame.StreamID, 0x04, frame.Data)
	}

	_, err := c.writer.Write(data)
	if err != nil {
		return err
	}

	return c.writer.Flush()
}

func (c *GRPCConn) buildDataFrame(streamID uint32, flags byte, data []byte) []byte {
	frame := make([]byte, 9+len(data))

	// Length
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))

	// Frame header
	frame[4] = 0x00  // Type: DATA
	frame[5] = flags // Flags
	binary.BigEndian.PutUint32(frame[6:10], streamID)

	// Data
	copy(frame[9:], data)

	return frame
}

func (c *GRPCConn) buildHeadersFrame(streamID uint32, flags byte, data []byte) []byte {
	frame := make([]byte, 9+len(data))

	// Length
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))

	// Frame header
	frame[4] = 0x01  // Type: HEADERS
	frame[5] = flags // Flags (END_HEADERS)
	binary.BigEndian.PutUint32(frame[6:10], streamID)

	// Headers
	copy(frame[9:], data)

	return frame
}

// Close closes the connection
func (c *GRPCConn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns local address
func (c *GRPCConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (c *GRPCConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets deadline
func (c *GRPCConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (c *GRPCConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (c *GRPCConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// GRPCClient is a gRPC client
type GRPCClient struct {
	conn     *GRPCConn
	streamID uint32
	mu       sync.Mutex
}

// NewGRPCClient creates a new gRPC client
func NewGRPCClient(conn *GRPCConn) *GRPCClient {
	return &GRPCClient{
		conn: conn,
	}
}

// Invoke invokes a gRPC method
func (c *GRPCClient) Invoke(method string, req []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Allocate new stream
	c.streamID += 2
	if c.streamID == 0 {
		c.streamID = 2
	}

	// Build request headers
	headers := c.buildRequestHeaders(c.streamID, method)
	if err := c.conn.WriteFrame(&GRPCFrame{
		Type:     GRPCFrameHead,
		StreamID: c.streamID,
		Data:     headers,
	}); err != nil {
		return nil, err
	}

	// Send request data
	if err := c.conn.WriteFrame(&GRPCFrame{
		Type:     GRPCFrameData,
		StreamID: c.streamID,
		Data:     req,
	}); err != nil {
		return nil, err
	}

	// Read response headers
	respHeaders, err := c.readHeaders(c.streamID)
	if err != nil {
		return nil, err
	}

	// Check status
	if status := respHeaders.Status; status != "" && status != "200" {
		return nil, fmt.Errorf("gRPC error: %s", respHeaders.StatusMsg)
	}

	// Read response data
	respData, err := c.readData(c.streamID)
	if err != nil {
		return nil, err
	}

	return respData, nil
}

func (c *GRPCClient) buildRequestHeaders(streamID uint32, method string) []byte {
	var buf bytes.Buffer
	encoder := hpack.NewEncoder(&buf)

	// :method
	encoder.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})

	// :scheme
	encoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})

	// :path
	encoder.WriteField(hpack.HeaderField{Name: ":path", Value: method})

	// :authority
	encoder.WriteField(hpack.HeaderField{Name: ":authority", Value: ""})

	// te: trailers
	encoder.WriteField(hpack.HeaderField{Name: "te", Value: "trailers"})

	// content-type: application/grpc
	encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})

	// user-agent
	encoder.WriteField(hpack.HeaderField{Name: "user-agent", Value: "mihomo-grpc/1.0"})

	return buf.Bytes()
}

func (c *GRPCClient) readHeaders(streamID uint32) (*GRPCHeader, error) {
	for {
		frame, err := c.conn.ReadFrame()
		if err != nil {
			return nil, err
		}

		if frame.StreamID != streamID {
			continue
		}

		if frame.Type != GRPCFrameHead {
			continue
		}

		return c.parseHeaders(frame.Data), nil
	}
}

func (c *GRPCClient) readData(streamID uint32) ([]byte, error) {
	var data []byte

	for {
		frame, err := c.conn.ReadFrame()
		if err != nil {
			return nil, err
		}

		if frame.StreamID != streamID {
			continue
		}

		data = append(data, frame.Data...)

		// Check if this is the last frame
		// (In real implementation, check END_STREAM flag)
		if len(data) > 0 {
			break
		}
	}

	return data, nil
}

func (c *GRPCClient) parseHeaders(data []byte) *GRPCHeader {
	headers := &GRPCHeader{}

	decoder := hpack.NewDecoder(4096, func(h hpack.HeaderField) {
		switch strings.ToLower(h.Name) {
		case ":status":
			headers.Status = h.Value
		case "content-type":
			headers.ContentType = h.Value
		}
	})

	decoder.Write(data)

	return headers
}

// GRPCServer is a gRPC server
type GRPCServer struct {
	Listener net.Listener
	Handler  GRPCHandler
}

// GRPCHandler handles gRPC requests
type GRPCHandler interface {
	HandleGRPC(method string, data []byte) ([]byte, error)
}

// NewGRPCServer creates a new gRPC server
func NewGRPCServer(listener net.Listener, handler GRPCHandler) *GRPCServer {
	return &GRPCServer{
		Listener: listener,
		Handler:  handler,
	}
}

// Serve starts the gRPC server
func (s *GRPCServer) Serve() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}

		go s.handleConn(conn)
	}
}

func (s *GRPCServer) handleConn(conn net.Conn) {
	defer conn.Close()

	grpcConn := NewGRPCConn(conn)
	client := NewGRPCClient(grpcConn)

	for {
		frame, err := grpcConn.ReadFrame()
		if err != nil {
			return
		}

		if frame.Type != GRPCFrameHead {
			continue
		}

		// Parse method from headers
		method := s.parseMethod(frame.Data)
		if method == "" {
			continue
		}

		// Read request data
		reqData, err := client.readData(frame.StreamID)
		if err != nil {
			continue
		}

		// Handle request
		respData, err := s.Handler.HandleGRPC(method, reqData)
		if err != nil {
			respData = []byte(err.Error())
		}

		// Send response
		headers := client.buildResponseHeaders(frame.StreamID, "200")
		grpcConn.WriteFrame(&GRPCFrame{
			Type:     GRPCFrameHead,
			StreamID: frame.StreamID,
			Data:     headers,
		})

		grpcConn.WriteFrame(&GRPCFrame{
			Type:     GRPCFrameData,
			StreamID: frame.StreamID,
			Data:     respData,
		})
	}
}

func (s *GRPCServer) parseMethod(data []byte) string {
	var method string

	decoder := hpack.NewDecoder(4096, func(h hpack.HeaderField) {
		if h.Name == ":path" {
			method = h.Value
		}
	})

	decoder.Write(data)
	return method
}

func (c *GRPCClient) buildResponseHeaders(streamID uint32, status string) []byte {
	var buf bytes.Buffer
	encoder := hpack.NewEncoder(&buf)

	encoder.WriteField(hpack.HeaderField{Name: ":status", Value: status})
	encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})

	return buf.Bytes()
}

// GRPCGunConfig holds gRPC-GUN configuration
type GRPCGunConfig struct {
	Enabled     bool
	ServiceName string
	HealthCheck bool
}

// GRPCGunConn is a gRPC-GUN connection
type GRPCGunConn struct {
	*GRPCConn
	serviceName string
}

// NewGRPCGunConn creates a new gRPC-GUN connection
func NewGRPCGunConn(conn net.Conn, serviceName string) *GRPCGunConn {
	return &GRPCGunConn{
		GRPCConn:    NewGRPCConn(conn),
		serviceName: serviceName,
	}
}

// GRPCMux implements HTTP/2 gRPC multiplexing
type GRPCMux struct {
	conns    map[uint32]*GRPCConn
	handlers map[uint32]chan []byte
	mu       sync.RWMutex
}

// NewGRPCMux creates a new gRPC multiplexer
func NewGRPCMux() *GRPCMux {
	return &GRPCMux{
		conns:    make(map[uint32]*GRPCConn),
		handlers: make(map[uint32]chan []byte),
	}
}

// Handle handles a stream
func (m *GRPCMux) Handle(streamID uint32) <-chan []byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	ch := make(chan []byte, 1)
	m.handlers[streamID] = ch
	return ch
}

// Send sends data to a stream
func (m *GRPCMux) Send(streamID uint32, data []byte) error {
	m.mu.RLock()
	ch, ok := m.handlers[streamID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("stream not found: %d", streamID)
	}

	select {
	case ch <- data:
		return nil
	default:
		return nil
	}
}

// Close closes a stream
func (m *GRPCMux) Close(streamID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.handlers, streamID)
}
