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

// dashboardHTML is a comprehensive built-in dashboard
const dashboardHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mihomo smart - Dashboard</title>
    <style>
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --bg-hover: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border: #334155;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        .header {
            background: var(--bg-card);
            padding: 1rem 2rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .logo { display: flex; align-items: center; gap: 0.75rem; }
        
        .logo-icon {
            width: 36px; height: 36px;
            background: linear-gradient(135deg, var(--primary), #a855f7);
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-size: 20px;
        }
        
        .logo-text { font-size: 1.25rem; font-weight: 700; }
        
        .header-status { display: flex; align-items: center; gap: 1rem; }
        
        .status-badge {
            display: flex; align-items: center; gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: var(--bg-hover);
            border-radius: 20px;
            font-size: 0.875rem;
        }
        
        .status-dot {
            width: 8px; height: 8px; border-radius: 50%;
            background: var(--success);
            animation: pulse 2s infinite;
        }
        
        .status-dot.offline { background: var(--danger); animation: none; }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .nav {
            background: var(--bg-card);
            padding: 0 2rem;
            display: flex;
            gap: 0.25rem;
            border-bottom: 1px solid var(--border);
        }
        
        .nav-tab {
            padding: 1rem 1.5rem;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }
        
        .nav-tab:hover { color: var(--text-primary); }
        .nav-tab.active { color: var(--primary); border-bottom-color: var(--primary); }
        
        .main { padding: 2rem; max-width: 1400px; margin: 0 auto; }
        .section { display: none; }
        .section.active { display: block; }
        
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .card-title { font-size: 1rem; font-weight: 600; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.25rem;
            border: 1px solid var(--border);
        }
        
        .stat-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }
        
        .stat-value { font-size: 1.75rem; font-weight: 700; }
        
        .node-list { display: flex; flex-direction: column; gap: 0.75rem; }
        
        .node-item {
            display: grid;
            grid-template-columns: 1fr auto auto auto;
            align-items: center;
            gap: 1rem;
            padding: 1rem;
            background: var(--bg-hover);
            border-radius: 10px;
            transition: all 0.2s;
        }
        
        .node-item:hover { background: #3b4a5e; }
        .node-info { display: flex; flex-direction: column; gap: 0.25rem; }
        .node-name { font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
        .node-type { font-size: 0.75rem; color: var(--text-secondary); }
        
        .node-region {
            font-size: 0.75rem;
            padding: 0.125rem 0.5rem;
            background: var(--primary);
            border-radius: 4px;
        }
        
        .node-latency { font-size: 0.875rem; font-weight: 600; min-width: 80px; text-align: center; }
        .node-latency.good { color: var(--success); }
        .node-latency.medium { color: var(--warning); }
        .node-latency.bad { color: var(--danger); }
        .node-latency.unknown { color: var(--text-secondary); }
        
        .node-status {
            padding: 0.375rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        .node-status.active { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .node-status.inactive { background: rgba(148, 163, 184, 0.2); color: var(--text-secondary); }
        .node-actions { display: flex; gap: 0.5rem; }
        
        .btn {
            padding: 0.5rem 1rem;
            border-radius: 8px;
            border: none;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover { background: var(--primary-dark); }
        .btn-secondary { background: var(--bg-hover); color: var(--text-primary); }
        .btn-secondary:hover { background: #4a5568; }
        
        .btn-icon {
            padding: 0.5rem;
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-secondary);
            border-radius: 6px;
            cursor: pointer;
        }
        
        .btn-icon:hover { background: var(--bg-hover); color: var(--text-primary); }
        
        .config-editor {
            width: 100%;
            min-height: 500px;
            background: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            color: var(--text-primary);
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.875rem;
            resize: vertical;
        }
        
        .config-actions { display: flex; gap: 0.75rem; margin-top: 1rem; }
        
        .traffic-chart {
            height: 300px;
            background: var(--bg-hover);
            border-radius: 8px;
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
            padding: 1rem;
            gap: 0.5rem;
        }
        
        .chart-bar {
            flex: 1;
            background: linear-gradient(to top, var(--primary), #a855f7);
            border-radius: 4px 4px 0 0;
            min-height: 4px;
            transition: height 0.3s ease;
        }
        
        .logs-container {
            max-height: 400px;
            overflow-y: auto;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.8rem;
            background: var(--bg-dark);
            border-radius: 8px;
            padding: 1rem;
        }
        
        .log-entry {
            padding: 0.25rem 0;
            border-bottom: 1px solid var(--border);
            display: flex;
            gap: 1rem;
        }
        
        .log-time { color: var(--text-secondary); }
        .log-level { font-weight: 600; }
        .log-level.info { color: var(--primary); }
        .log-level.warn { color: var(--warning); }
        .log-level.error { color: var(--danger); }
        
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            color: var(--text-secondary);
        }
        
        .spinner {
            width: 24px; height: 24px;
            border: 2px solid var(--border);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 0.75rem;
        }
        
        @keyframes spin { to { transform: rotate(360deg); } }
        
        @media (max-width: 768px) {
            .header { padding: 1rem; flex-direction: column; gap: 1rem; }
            .nav { padding: 0 1rem; overflow-x: auto; }
            .main { padding: 1rem; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .node-item { grid-template-columns: 1fr; gap: 0.75rem; }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">
            <div class="logo-icon">🚀</div>
            <span class="logo-text">mihomo smart</span>
        </div>
        <div class="header-status">
            <div class="status-badge">
                <div class="status-dot" id="statusDot"></div>
                <span id="statusText">连接中...</span>
            </div>
            <button class="btn btn-secondary" onclick="reloadConfig()">🔄 重载配置</button>
        </div>
    </header>
    
    <nav class="nav">
        <button class="nav-tab active" data-tab="overview">概览</button>
        <button class="nav-tab" data-tab="nodes">节点</button>
        <button class="nav-tab" data-tab="config">配置</button>
        <button class="nav-tab" data-tab="logs">日志</button>
    </nav>
    
    <main class="main">
        <section id="overview" class="section active">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">总节点数</div>
                    <div class="stat-value" id="totalNodes">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">在线节点</div>
                    <div class="stat-value" id="onlineNodes">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">平均延迟</div>
                    <div class="stat-value" id="avgLatency">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">当前策略</div>
                    <div class="stat-value" id="currentPolicy" style="font-size: 1.25rem;">Smart</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span class="card-title">📊 流量统计</span>
                    <button class="btn btn-secondary" onclick="refreshTraffic()">刷新</button>
                </div>
                <div class="traffic-chart" id="trafficChart">
                    <div class="loading"><div class="spinner"></div>加载中...</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span class="card-title">🎯 智能推荐</span>
                </div>
                <div id="smartRecommendations" class="node-list">
                    <div class="loading"><div class="spinner"></div>加载中...</div>
                </div>
            </div>
        </section>
        
        <section id="nodes" class="section">
            <div class="card">
                <div class="card-header">
                    <span class="card-title">🌐 代理节点</span>
                    <div>
                        <button class="btn btn-secondary" onclick="testAllNodes()">🧪 测速全部</button>
                        <button class="btn btn-primary" onclick="refreshNodes()">🔄 刷新</button>
                    </div>
                </div>
                <div class="node-list" id="nodeList">
                    <div class="loading"><div class="spinner"></div>加载中...</div>
                </div>
            </div>
        </section>
        
        <section id="config" class="section">
            <div class="card">
                <div class="card-header">
                    <span class="card-title">📝 配置文件</span>
                    <span style="color: var(--text-secondary); font-size: 0.875rem;">config.yaml</span>
                </div>
                <textarea class="config-editor" id="configEditor" spellcheck="false"></textarea>
                <div class="config-actions">
                    <button class="btn btn-secondary" onclick="loadConfig()">📥 加载</button>
                    <button class="btn btn-primary" onclick="saveConfig()">💾 保存</button>
                    <button class="btn btn-secondary" onclick="reloadConfig()">🔄 重载</button>
                </div>
            </div>
        </section>
        
        <section id="logs" class="section">
            <div class="card">
                <div class="card-header">
                    <span class="card-title">📋 运行日志</span>
                    <button class="btn btn-secondary" onclick="clearLogs()">🗑️ 清空</button>
                </div>
                <div class="logs-container" id="logsContainer">
                    <div class="loading"><div class="spinner"></div>加载中...</div>
                </div>
            </div>
        </section>
    </main>
    
    <script>
        let ws = null;
        let nodesData = [];
        
        document.addEventListener('DOMContentLoaded', function() {
            initTabs();
            initWebSocket();
            loadData();
            setInterval(loadData, 30000);
        });
        
        function initTabs() {
            document.querySelectorAll('.nav-tab').forEach(function(tab) {
                tab.addEventListener('click', function() {
                    document.querySelectorAll('.nav-tab').forEach(function(t) { t.classList.remove('active'); });
                    document.querySelectorAll('.section').forEach(function(s) { s.classList.remove('active'); });
                    tab.classList.add('active');
                    document.getElementById(tab.dataset.tab).classList.add('active');
                    if (tab.dataset.tab === 'logs') loadLogs();
                });
            });
        }
        
        function initWebSocket() {
            var wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            try {
                ws = new WebSocket(wsProtocol + '//' + location.host + '/api/ws');
                ws.onopen = function() {
                    updateStatus(true);
                    ws.send(JSON.stringify({ type: 'subscribe', channels: ['stats', 'nodes', 'logs'] }));
                };
                ws.onmessage = function(event) {
                    try { handleWebSocketMessage(JSON.parse(event.data)); } catch (e) {}
                };
                ws.onclose = function() { updateStatus(false); setTimeout(initWebSocket, 5000); };
                ws.onerror = function() { ws.close(); };
            } catch (e) { setTimeout(initWebSocket, 10000); }
        }
        
        function handleWebSocketMessage(data) {
            switch (data.type) {
                case 'stats': updateStats(data); break;
                case 'nodes': updateNodeList(data.nodes); break;
                case 'log': appendLog(data); break;
                case 'traffic': updateTrafficChart(data); break;
            }
        }
        
        function updateStatus(online) {
            var dot = document.getElementById('statusDot');
            var text = document.getElementById('statusText');
            if (online) { dot.classList.remove('offline'); text.textContent = '在线'; }
            else { dot.classList.add('offline'); text.textContent = '离线'; }
        }
        
        async function loadData() {
            await Promise.all([loadStats(), loadNodes(), loadConfig()]);
        }
        
        async function loadStats() {
            try {
                var resp = await fetch('/v1/stats');
                if (resp.ok) updateStats(await resp.json());
            } catch (e) {}
        }
        
        function updateStats(data) {
            if (data.nodes) {
                nodesData = data.nodes;
                document.getElementById('totalNodes').textContent = data.nodes.length;
                var online = data.nodes.filter(function(n) { return n.status === 'active'; }).length;
                document.getElementById('onlineNodes').textContent = online;
                var latencies = data.nodes.filter(function(n) { return n.latency; }).map(function(n) { return n.latency; });
                if (latencies.length > 0) {
                    var avg = Math.round(latencies.reduce(function(a, b) { return a + b; }, 0) / latencies.length);
                    document.getElementById('avgLatency').textContent = avg + 'ms';
                }
                updateSmartRecommendations(data.nodes);
            }
            if (data.currentPolicy) document.getElementById('currentPolicy').textContent = data.currentPolicy;
        }
        
        async function loadNodes() {
            try {
                var resp = await fetch('/v1/nodes');
                if (resp.ok) updateNodeList((await resp.json()).nodes || []);
            } catch (e) {}
        }
        
        function refreshNodes() { loadNodes(); }
        
        function updateNodeList(nodes) {
            var container = document.getElementById('nodeList');
            if (!nodes || nodes.length === 0) { container.innerHTML = '<div class="loading">暂无节点数据</div>'; return; }
            var html = '';
            for (var i = 0; i < nodes.length; i++) {
                var node = nodes[i];
                var latencyClass = getLatencyClass(node.latency);
                var statusClass = node.status === 'active' ? 'active' : 'inactive';
                html += '<div class="node-item"><div class="node-info"><span class="node-name">' + escHtml(node.name) + ' <span class="node-region">' + escHtml(node.region || 'Unknown') + '</span></span><span class="node-type">' + escHtml(node.type || 'unknown') + '</span></div><div class="node-latency ' + latencyClass + '">' + (node.latency ? node.latency + 'ms' : 'N/A') + '</div><div class="node-status ' + statusClass + '">' + (node.status === 'active' ? '✓ 在线' : '○ 离线') + '</div><div class="node-actions"><button class="btn-icon" onclick="testNode(\'' + escHtml(node.name) + '\')">🧪</button><button class="btn-icon" onclick="selectNode(\'' + escHtml(node.name) + '\')">✓</button></div></div>';
            }
            container.innerHTML = html;
        }
        
        function escHtml(str) {
            var div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }
        
        function getLatencyClass(latency) {
            if (!latency) return 'unknown';
            if (latency < 100) return 'good';
            if (latency < 300) return 'medium';
            return 'bad';
        }
        
        function updateSmartRecommendations(nodes) {
            var container = document.getElementById('smartRecommendations');
            if (!nodes || nodes.length === 0) { container.innerHTML = '<div class="loading">暂无推荐</div>'; return; }
            var medals = ['🥇', '🥈', '🥉'];
            var recommended = nodes.filter(function(n) { return n.status === 'active'; }).sort(function(a, b) { return (a.latency || 9999) - (b.latency || 9999); }).slice(0, 3);
            var html = '';
            for (var i = 0; i < recommended.length; i++) {
                var node = recommended[i];
                html += '<div class="node-item"><div class="node-info"><span class="node-name">' + medals[i] + ' ' + escHtml(node.name) + ' <span class="node-region">' + escHtml(node.region || 'Unknown') + '</span></span><span class="node-type">智能推荐 - 延迟最低</span></div><div class="node-latency good">' + (node.latency || 'N/A') + 'ms</div><button class="btn btn-primary" onclick="selectNode(\'' + escHtml(node.name) + '\')">选择</button></div>';
            }
            container.innerHTML = html;
        }
        
        var trafficHistory = [];
        
        function refreshTraffic() { updateTrafficChart({ history: trafficHistory }); }
        
        function updateTrafficChart(data) {
            if (data.history) trafficHistory = data.history;
            var container = document.getElementById('trafficChart');
            var bars = trafficHistory.slice(-20);
            if (bars.length === 0) { container.innerHTML = '<div class="loading">暂无流量数据</div>'; return; }
            var max = Math.max.apply(null, bars.map(function(b) { return Math.max(b.upload || 0, b.download || 0); }).concat([1]));
            var html = '';
            for (var i = 0; i < bars.length; i++) {
                var bar = bars[i];
                var upH = ((bar.upload || 0) / max * 100).toFixed(1);
                var downH = ((bar.download || 0) / max * 100).toFixed(1);
                html += '<div style="display: flex; flex-direction: column; justify-content: flex-end; height: 100%; gap: 2px;"><div class="chart-bar" style="height: ' + upH + '%;" title="上传: ' + formatBytes(bar.upload) + '"></div><div class="chart-bar" style="height: ' + downH + '%; opacity: 0.7;" title="下载: ' + formatBytes(bar.download) + '"></div></div>';
            }
            container.innerHTML = html;
        }
        
        function formatBytes(bytes) {
            if (!bytes) return '0 B';
            var k = 1024;
            var sizes = ['B', 'KB', 'MB', 'GB'];
            var i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }
        
        async function loadConfig() {
            try {
                var resp = await fetch('/v1/config');
                if (resp.ok) document.getElementById('configEditor').value = await resp.text();
            } catch (e) { document.getElementById('configEditor').value = '# 配置文件加载失败'; }
        }
        
        async function saveConfig() {
            var config = document.getElementById('configEditor').value;
            try {
                var resp = await fetch('/v1/config', { method: 'PUT', headers: { 'Content-Type': 'text/plain' }, body: config });
                alert(resp.ok ? '配置已保存' : '保存失败');
            } catch (e) { alert('保存失败: ' + e.message); }
        }
        
        async function reloadConfig() {
            try {
                var resp = await fetch('/v1/reload', { method: 'POST' });
                if (resp.ok) { alert('配置已重载'); loadData(); }
            } catch (e) { alert('重载失败: ' + e.message); }
        }
        
        function appendLog(entry) {
            var container = document.getElementById('logsContainer');
            var time = new Date(entry.time || Date.now()).toLocaleTimeString();
            var levelClass = entry.level || 'info';
            var logEl = document.createElement('div');
            logEl.className = 'log-entry';
            logEl.innerHTML = '<span class="log-time">' + time + '</span><span class="log-level ' + levelClass + '">' + (entry.level ? entry.level.toUpperCase() : 'INFO') + '</span><span class="log-message">' + escHtml(entry.message || '') + '</span>';
            container.insertBefore(logEl, container.firstChild);
            while (container.children.length > 100) container.removeChild(container.lastChild);
        }
        
        async function loadLogs() {
            try {
                var resp = await fetch('/v1/logs');
                if (resp.ok) {
                    var data = await resp.json();
                    var container = document.getElementById('logsContainer');
                    container.innerHTML = '';
                    if (data.logs) {
                        for (var i = 0; i < data.logs.length; i++) {
                            appendLog(data.logs[i]);
                        }
                    }
                }
            } catch (e) {}
        }
        
        function clearLogs() { document.getElementById('logsContainer').innerHTML = ''; }
        
        async function testNode(name) { try { await fetch('/v1/nodes/' + encodeURIComponent(name) + '/test', { method: 'POST' }); } catch (e) {} }
        async function testAllNodes() { try { await fetch('/v1/nodes/test-all', { method: 'POST' }); } catch (e) {} }
        
        async function selectNode(name) {
            try {
                var resp = await fetch('/v1/select', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ node: name }) });
                if (resp.ok) loadNodes();
            } catch (e) {}
        }
    </script>
</body>
</html>`

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
