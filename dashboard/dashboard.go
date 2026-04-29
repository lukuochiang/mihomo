package dashboard

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// Dashboard provides embedded web dashboard
type Dashboard struct {
	server *http.Server
}

// NewDashboard creates a new dashboard server
func NewDashboard(addr string, staticFS embed.FS) (*Dashboard, error) {
	mux := http.NewServeMux()

	// Create a sub-filesystem for the "static" directory
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		// If no embedded files, use a simple message handler
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(dashboardHTML))
		})
	} else {
		// Serve static files
		mux.Handle("/", http.FileServer(http.FS(staticContent)))
	}

	// Wrap with SPA routing support
	handler := spaHandler(mux)

	return &Dashboard{
		server: &http.Server{
			Addr:    addr,
			Handler: handler,
		},
	}, nil
}

// NewSimpleDashboard creates a simple dashboard server without embedded files
func NewSimpleDashboard(addr string) *Dashboard {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(dashboardHTML))
	})

	return &Dashboard{
		server: &http.Server{
			Addr:    addr,
			Handler: mux,
		},
	}
}

// spaHandler handles Single Page Application routing
func spaHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the path doesn't have a file extension, serve index.html
		if !strings.Contains(path.Ext(r.URL.Path), ".") {
			r.URL.Path = "/"
		}

		// Try to serve the file
		next.ServeHTTP(w, r)
	})
}

// Start starts the dashboard server
func (d *Dashboard) Start() error {
	return d.server.ListenAndServe()
}

// Close closes the dashboard server
func (d *Dashboard) Close() error {
	return d.server.Close()
}

// dashboardHTML is a simple built-in dashboard when no static files are embedded
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mihomo smart Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
        }
        h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
        }
        .status {
            background: #f0f0f0;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .status-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #ddd;
        }
        .status-item:last-child { border-bottom: none; }
        .status-label { color: #666; }
        .status-value { color: #333; font-weight: 500; }
        .status-value.online { color: #22c55e; }
        .status-value.offline { color: #ef4444; }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin-top: 10px;
        }
        .btn:hover { opacity: 0.9; }
        .api-section {
            margin-top: 20px;
            text-align: left;
        }
        .api-title {
            font-weight: 600;
            margin-bottom: 10px;
            color: #333;
        }
        code {
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 13px;
        }
        .version {
            margin-top: 20px;
            color: #999;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 mihomo smart</h1>
        <p class="subtitle">智能代理管理面板</p>
        
        <div class="status">
            <div class="status-item">
                <span class="status-label">运行状态</span>
                <span class="status-value online">在线</span>
            </div>
            <div class="status-item">
                <span class="status-label">代理端口</span>
                <span class="status-value">7890</span>
            </div>
            <div class="status-item">
                <span class="status-label">SOCKS5 端口</span>
                <span class="status-value">7891</span>
            </div>
            <div class="status-item">
                <span class="status-label">节点数量</span>
                <span class="status-value" id="nodeCount">-</span>
            </div>
            <div class="status-item">
                <span class="status-label">策略引擎</span>
                <span class="status-value">Smart</span>
            </div>
        </div>
        
        <div class="api-section">
            <div class="api-title">📡 API 接口</div>
            <div class="status-item">
                <span class="status-label">获取节点列表</span>
                <code>GET /v1/nodes</code>
            </div>
            <div class="status-item">
                <span class="status-label">选择节点</span>
                <code>POST /v1/select</code>
            </div>
            <div class="status-item">
                <span class="status-label">获取统计</span>
                <code>GET /v1/stats</code>
            </div>
        </div>
        
        <a href="https://github.com/metacubex/mihomo-web" target="_blank" class="btn">
            🌐 访问完整 Dashboard
        </a>
        
        <p class="version">Version 1.0.0</p>
    </div>
    
    <script>
        // Fetch status from API
        fetch('/v1/stats')
            .then(r => r.json())
            .then(data => {
                if (data.nodes) {
                    document.getElementById('nodeCount').textContent = data.nodes.length;
                }
            })
            .catch(() => {});
    </script>
</body>
</html>
`

// StaticDashboard serves static dashboard files
type StaticDashboard struct {
	addr string
	FS   embed.FS
	dir  string
}

// NewStaticDashboard creates a dashboard that serves files from an embedded FS
func NewStaticDashboard(addr string, fs embed.FS, dir string) *StaticDashboard {
	return &StaticDashboard{
		addr: addr,
		FS:   fs,
		dir:  dir,
	}
}

// Start starts the static dashboard server
func (d *StaticDashboard) Start() error {
	subFS, err := fs.Sub(d.FS, d.dir)
	if err != nil {
		return fmt.Errorf("failed to create sub filesystem: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(subFS)))

	server := &http.Server{
		Addr:    d.addr,
		Handler: mux,
	}

	return server.ListenAndServe()
}
