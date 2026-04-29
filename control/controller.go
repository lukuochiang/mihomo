package control

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/lukuochiang/mihomo/config"
	"github.com/lukuochiang/mihomo/core/metrics"
	"github.com/lukuochiang/mihomo/core/policy"
	"github.com/lukuochiang/mihomo/core/policy/smart"

	"go.uber.org/zap"
)

// Controller is the main controller
type Controller struct {
	config      *config.Config
	logger      *zap.Logger
	smartEngine *smart.Smart
	metrics     *metrics.Collector
	policies    map[string]policy.Policy
}

// NewController creates a new controller
func NewController(cfg *config.Config, logger *zap.Logger, sm *smart.Smart, m *metrics.Collector) (*Controller, error) {
	ctrl := &Controller{
		config:      cfg,
		logger:      logger,
		smartEngine: sm,
		metrics:     m,
		policies:    make(map[string]policy.Policy),
	}

	// Initialize policies
	if err := ctrl.initPolicies(); err != nil {
		return nil, err
	}

	// Register outbounds as nodes
	for _, ob := range cfg.Outbounds {
		sm.RegisterNode(ob.Name, ob.Name, ob.Server)
		ctrl.logger.Info("registered node",
			zap.String("name", ob.Name),
			zap.String("address", ob.Server),
		)
	}

	return ctrl, nil
}

func (c *Controller) initPolicies() error {
	for i, rule := range c.config.Routing.Rules {
		p, err := policy.NewPolicy(policy.Config{
			Type: policy.PolicyType(rule.Type),
		})
		if err != nil {
			return err
		}
		ruleName := fmt.Sprintf("rule-%d", i)
		if rule.Type != "" {
			ruleName = rule.Type + "-" + strconv.Itoa(i)
		}
		c.policies[ruleName] = p
	}
	return nil
}

// GetSmart returns the Smart engine
func (c *Controller) GetSmart() *smart.Smart {
	return c.smartEngine
}

// GetMetrics returns the metrics collector
func (c *Controller) GetMetrics() *metrics.Collector {
	return c.metrics
}

// GetPolicy returns a policy by name
func (c *Controller) GetPolicy(name string) (policy.Policy, bool) {
	p, ok := c.policies[name]
	return p, ok
}

// SelectNode selects a node using Smart policy
func (c *Controller) SelectNode(ctx context.Context) (string, error) {
	return c.smartEngine.SelectNode(ctx)
}

// Shutdown gracefully shuts down the controller
func (c *Controller) Shutdown(ctx context.Context) error {
	c.logger.Info("shutting down controller")

	// Close Smart
	if err := c.smartEngine.Close(); err != nil {
		c.logger.Error("failed to close smart", zap.Error(err))
	}

	// Close policies
	for name, p := range c.policies {
		if err := p.Close(); err != nil {
			c.logger.Error("failed to close policy", zap.String("name", name), zap.Error(err))
		}
	}

	c.logger.Info("controller shutdown complete")
	return nil
}

// LoadConfig loads configuration from file
func LoadConfig(path string) (*config.Config, error) {
	return config.Load(path)
}

// ExtractConfig extracts default config to directory
func ExtractConfig(dir string) error {
	// TODO: Implement config extraction
	return nil
}

// ConfigPath returns config file path
func ConfigPath(name string) string {
	return filepath.Join("config", name)
}
