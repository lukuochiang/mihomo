package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/mihomo/smart/config"
	"github.com/mihomo/smart/control"
	"github.com/mihomo/smart/control/api"
	"github.com/mihomo/smart/core/dns"
	"github.com/mihomo/smart/core/metrics"
	"github.com/mihomo/smart/core/outbound"
	"github.com/mihomo/smart/core/policy/smart"
	"github.com/mihomo/smart/dashboard"
	"github.com/mihomo/smart/listener"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Build variables (set via ldflags)
	version  = "dev"      // e.g., "alpha", "beta", "v1.0.0"
	branch   = "smart"    // e.g., "smart", "main"
	commit   = "none"     // git commit hash
	date     = "unknown"  // build date
)

// getVersionString returns the formatted version string
// Format: mihomo-{os}-{arch}-{version}-{branch}-{commit}
func getVersionString() string {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	shortCommit := commit
	if len(shortCommit) > 7 {
		shortCommit = shortCommit[:7]
	}
	if version == "dev" {
		return fmt.Sprintf("mihomo-%s-%s-dev-%s-%s", osName, arch, branch, shortCommit)
	}
	return fmt.Sprintf("mihomo-%s-%s-%s-%s-%s", osName, arch, version, branch, shortCommit)
}

var (
	flagConfig        = flag.String("config", "config.yaml", "config file path")
	flagTestConfig    = flag.Bool("t", false, "test config only")
	flagVersion       = flag.Bool("v", false, "print version")
	flagExtractConfig = flag.String("extract-config", "", "extract config to a directory")
)

func main() {
	flag.Parse()

	// Version info
	if *flagVersion {
		fmt.Println(getVersionString())
		os.Exit(0)
	}

	// Initialize logger
	logger, err := initLogger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger failed: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting mihomo",
		zap.String("version", getVersionString()),
		zap.String("commit", commit),
	)

	// Load config
	cfg, err := control.LoadConfig(*flagConfig)
	if err != nil {
		logger.Fatal("load config failed", zap.Error(err))
	}

	// Test config mode
	if *flagTestConfig {
		logger.Info("config is valid")
		os.Exit(0)
	}

	// Extract config mode
	if *flagExtractConfig != "" {
		if err := control.ExtractConfig(*flagExtractConfig); err != nil {
			logger.Fatal("extract config failed", zap.Error(err))
		}
		logger.Info("config extracted", zap.String("dir", *flagExtractConfig))
		os.Exit(0)
	}

	// Initialize metrics collector
	metricsCollector := metrics.NewCollector()
	logger.Info("metrics collector initialized")

	// Initialize Smart policy engine with default config
	// Smart can be used in proxy-groups with type: smart
	smartPolicy := smart.NewSmart(smart.Config{
		MetricsCollector: metricsCollector,
		LearningEnabled:  false,
		SelectionMode:    smart.ModeAuto,
		UpdateInterval:   5 * time.Second,
	})
	logger.Info("smart policy engine initialized",
		zap.String("mode", "auto"),
	)

	// Initialize controller
	ctrl, err := control.NewController(cfg, logger, smartPolicy, metricsCollector)
	if err != nil {
		logger.Fatal("init controller failed", zap.Error(err))
	}

	// Start DNS server
	var dnsServer *dns.Server
	if cfg.DNS.Enable {
		dnsServer = dns.NewServer(dns.ServerConfig{
			Listen:       cfg.DNS.Listen,
			Servers:      cfg.DNS.Nameserver,
			Strategy:     cfg.DNS.Strategy,
			EnhancedMode: cfg.DNS.EnhancedMode != "" && cfg.DNS.EnhancedMode != "off",
			FakeIPRange:  cfg.DNS.FakeIPRange,
		})
		if err := dnsServer.Start(); err != nil {
			logger.Warn("failed to start DNS server", zap.Error(err))
		} else {
			logger.Info("DNS server started", zap.String("listen", cfg.DNS.Listen))
		}
	}

	// Start Dashboard server
	var dashboardServer *dashboard.Dashboard
	if cfg.Dashboard.Enabled {
		dashboardServer = dashboard.NewSimpleDashboard(cfg.Dashboard.Listen)
		go func() {
			if err := dashboardServer.Start(); err != nil {
				logger.Warn("dashboard server error", zap.Error(err))
			}
		}()
		logger.Info("dashboard server started", zap.String("listen", cfg.Dashboard.Listen))
	}

	// Start API server
	if cfg.API.Enabled {
		apiServer := api.NewServer(api.APIConfig{
			Listen: cfg.API.Listen,
			Secret: cfg.API.Secret,
		}, api.AuthConfig{
			Mode:    api.AuthModeBearer,
			Secret:  cfg.API.Secret,
			Enabled: cfg.API.Secret != "",
		}, ctrl, logger)

		// Register reload handler with API
		reloadCfg := &control.HotReloadConfig{
			Enabled:       true,
			WatchPaths:    []string{*flagConfig},
			DebounceDelay: 500,
		}
		reloadHandler, err := control.NewReloadHandler(reloadCfg, func(newCfg *config.Config) error {
			// Re-initialize controller with new config
			return nil
		})
		if err == nil && reloadHandler != nil {
			apiServer.RegisterReloadHandler(reloadHandler)
		}

		go func() {
			if err := apiServer.Start(); err != nil {
				logger.Error("api server error", zap.Error(err))
			}
		}()
		logger.Info("api server started", zap.String("addr", cfg.API.Listen))
	}

	// Start proxy servers (HTTP/SOCKS5)
	var proxyServer *listener.ProxyServer
	httpEnabled := cfg.HTTPPort > 0
	socksEnabled := cfg.SOCKSPort > 0
	if httpEnabled || socksEnabled || cfg.MixedPort > 0 {
		// Create outbound manager for proxy
		outboundManager := outbound.NewManager(smartPolicy, metricsCollector)

		// Register all outbounds as nodes
		for _, ob := range cfg.Outbounds {
			node := &outbound.Node{
				ID:       ob.Name,
				Name:     ob.Name,
				Type:     ob.Type,
				Address:  ob.Server,
				Port:     ob.Port,
				UUID:     ob.UUID,
				Cipher:   ob.Cipher,
				Password: ob.Password,
				Username: ob.Username,
				Protocol: ob.Protocol,
				OBFS:     ob.OBFS,
			}

			// Handle SSH private key (use PrivateKeyPath for file-based keys)
			if ob.PrivateKeyPath != "" {
				keyBytes, err := os.ReadFile(ob.PrivateKeyPath)
				if err == nil {
					node.PrivateKey = keyBytes
					node.PrivateKeyPassphrase = ob.PrivateKeyPass
				}
			}

			outboundManager.AddNode(node)
		}

		// Create dialer
		dialer := outbound.NewDialer(outboundManager)

		// Create proxy server
		proxyServer = listener.NewProxyServer(&listener.ProxyConfig{
			HTTPEnabled:  httpEnabled,
			HTTPPort:     cfg.HTTPPort,
			HTTPBind:     cfg.BindAddress,
			SOCKSEnabled: socksEnabled,
			SOCKSPort:    cfg.SOCKSPort,
			SOCKSBind:    cfg.BindAddress,
		}, dialer, smartPolicy)

		if err := proxyServer.Start(); err != nil {
			logger.Fatal("failed to start proxy server", zap.Error(err))
		}

		if httpEnabled {
			logger.Info("HTTP proxy server started",
				zap.String("bind", cfg.BindAddress),
				zap.Int("port", cfg.HTTPPort),
			)
		}
		if socksEnabled {
			logger.Info("SOCKS5 proxy server started",
				zap.String("bind", cfg.BindAddress),
				zap.Int("port", cfg.SOCKSPort),
			)
		}
		if cfg.MixedPort > 0 {
			logger.Info("Mixed proxy server started",
				zap.String("bind", cfg.BindAddress),
				zap.Int("port", cfg.MixedPort),
			)
		}
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		cancel()

		// Shutdown with timeout
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		// Close DNS server first
		if dnsServer != nil {
			dnsServer.Stop()
		}

		// Close dashboard server
		if dashboardServer != nil {
			dashboardServer.Close()
		}

		// Close proxy server
		if proxyServer != nil {
			proxyServer.Close()
		}

		if err := ctrl.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", zap.Error(err))
		}
	}()

	// Start main loop
	logger.Info("mihomo smart is running")
	<-ctx.Done()
	logger.Info("mihomo smart stopped")
}

func initLogger() (*zap.Logger, error) {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseColorLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.InfoLevel),
		Development:      false,
		Encoding:         "console",
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return config.Build()
}
