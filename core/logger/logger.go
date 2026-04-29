package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger provides structured logging with levels
type Logger struct {
	*zap.Logger
	level  zapcore.Level
	output io.Writer
	file   *os.File
	mu     sync.RWMutex
}

// LogLevel defines log levels
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
	LevelFatal LogLevel = "fatal"
)

// Config holds logger configuration
type Config struct {
	Level      LogLevel
	Output     string // "stdout", "stderr", or file path
	FilePath   string
	MaxSize    int    // Max file size in MB
	MaxBackups int    // Max number of backup files
	MaxAge     int    // Max age in days
	Compress   bool   // Compress old log files
	Format     string // "json", "console"
}

// DefaultConfig returns default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:      LevelInfo,
		Output:     "stderr",
		Format:     "console",
		MaxSize:    10,
		MaxBackups: 3,
		MaxAge:     7,
		Compress:   true,
	}
}

// New creates a new logger
func New(cfg *Config) (*Logger, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Determine log level
	var level zapcore.Level
	switch cfg.Level {
	case LevelDebug:
		level = zapcore.DebugLevel
	case LevelInfo:
		level = zapcore.InfoLevel
	case LevelWarn:
		level = zapcore.WarnLevel
	case LevelError:
		level = zapcore.ErrorLevel
	case LevelFatal:
		level = zapcore.FatalLevel
	default:
		level = zapcore.InfoLevel
	}

	// Determine encoder
	var encoder zapcore.Encoder
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	if cfg.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Determine output
	var writeSyncer zapcore.WriteSyncer
	if cfg.Output == "stdout" {
		writeSyncer = zapcore.AddSync(os.Stdout)
	} else if cfg.Output == "stderr" || cfg.Output == "" {
		writeSyncer = zapcore.AddSync(os.Stderr)
	} else {
		// File output
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writeSyncer = zapcore.AddSync(f)
	}

	core := zapcore.NewCore(
		encoder,
		writeSyncer,
		level,
	)

	zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &Logger{
		Logger: zapLogger,
		level:  level,
	}, nil
}

// WithComponent returns a logger with component field
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{
		Logger: l.With(zap.String("component", component)),
		level:  l.level,
	}
}

// WithFields returns a logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	zapFields := make([]zap.Field, 0, len(fields))
	for k, v := range fields {
		zapFields = append(zapFields, zap.Any(k, v))
	}
	return &Logger{
		Logger: l.With(zapFields...),
		level:  l.level,
	}
}

// SetLevel changes the log level
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var zapLevel zapcore.Level
	switch level {
	case LevelDebug:
		zapLevel = zapcore.DebugLevel
	case LevelInfo:
		zapLevel = zapcore.InfoLevel
	case LevelWarn:
		zapLevel = zapcore.WarnLevel
	case LevelError:
		zapLevel = zapcore.ErrorLevel
	case LevelFatal:
		zapLevel = zapcore.FatalLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	l.level = zapLevel
	// Note: changing level at runtime requires core replacement
}

// FileLogger provides file-based logging with rotation
type FileLogger struct {
	logger   *zap.Logger
	filePath string
	maxSize  int64
	maxAge   int
	mu       sync.Mutex
}

// NewFileLogger creates a new rotating file logger
func NewFileLogger(filePath string, maxSizeMB, maxAge int) (*FileLogger, error) {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	cfg := &Config{
		Level:    LevelInfo,
		FilePath: filePath,
		MaxSize:  maxSizeMB,
		MaxAge:   maxAge,
	}

	logger, err := New(cfg)
	if err != nil {
		return nil, err
	}

	return &FileLogger{
		logger:   logger.Logger,
		filePath: filePath,
		maxSize:  int64(maxSizeMB) * 1024 * 1024,
		maxAge:   maxAge,
	}, nil
}

// Rotate rotates the log file
func (l *FileLogger) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check file size
	info, err := os.Stat(l.filePath)
	if err != nil {
		return err
	}

	if info.Size() < l.maxSize {
		return nil
	}

	// Rotate file
	now := time.Now()
	backupPath := fmt.Sprintf("%s.%s", l.filePath, now.Format("20060102150405"))

	if err := os.Rename(l.filePath, backupPath); err != nil {
		return err
	}

	// Clean old backups
	l.cleanOldBackups()

	return nil
}

func (l *FileLogger) cleanOldBackups() {
	if l.maxAge <= 0 {
		return
	}

	dir := filepath.Dir(l.filePath)
	base := filepath.Base(l.filePath)
	pattern := filepath.Join(dir, base+".*")

	// This would use filepath.Glob in real implementation
	_ = pattern
}

// Sync implements zap.Syncer
func (l *FileLogger) Sync() error {
	return l.logger.Sync()
}

// Writer returns an io.Writer for the file logger
func (l *FileLogger) Writer() io.Writer {
	return &zapWriter{logger: l.logger}
}

type zapWriter struct {
	logger *zap.Logger
}

func (w *zapWriter) Write(p []byte) (n int, err error) {
	w.logger.Info(string(p))
	return len(p), nil
}

// Global logger instance
var globalLogger *Logger
var globalOnce sync.Once

// Init initializes the global logger
func Init(cfg *Config) error {
	var err error
	globalOnce.Do(func() {
		globalLogger, err = New(cfg)
	})
	return err
}

// Get returns the global logger
func Get() *Logger {
	if globalLogger == nil {
		globalLogger, _ = New(DefaultConfig())
	}
	return globalLogger
}

// Debug logs a debug message
func Debug(msg string, fields ...zap.Field) {
	Get().Debug(msg, fields...)
}

// Info logs an info message
func Info(msg string, fields ...zap.Field) {
	Get().Info(msg, fields...)
}

// Warn logs a warning message
func Warn(msg string, fields ...zap.Field) {
	Get().Warn(msg, fields...)
}

// Error logs an error message
func Error(msg string, fields ...zap.Field) {
	Get().Error(msg, fields...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, fields ...zap.Field) {
	Get().Fatal(msg, fields...)
}

// Sync flushes any buffered log entries
func Sync() {
	if globalLogger != nil {
		globalLogger.Sync()
	}
}
