# Smart 策略引擎架构文档

## 概述

Smart 是一个智能代理节点选择策略引擎，基于机器学习和统计分析动态选择最优代理节点。

## 核心组件

```
Smart
├── Scorer     (评分器)    - 根据多维度指标计算节点得分
├── Selector   (选择器)    - 根据不同模式选择最佳节点
├── Predictor  (预测器)    - 基于历史数据预测未来性能
├── Learner    (学习器)    - 机器学习模式，持续优化决策
└── Metrics    (指标收集)  - 收集和存储节点性能指标
```

## 选择模式 (SelectionMode)

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| `auto` | 自动选择 | 根据网络状况自动调整策略 (默认) |
| `fast` | 低延迟优先 | 游戏、视频通话等实时应用 |
| `stable` | 高稳定优先 | 重要业务、文件传输 |
| `balanced` | 均衡模式 | 综合考虑所有指标 |
| `learning` | 学习模式 | 使用机器学习预测最佳节点 |

## 评分体系

### 评分权重 (默认)

```go
type Weights struct {
    Latency:   0.35,   // 延迟权重 (越低越好)
    Jitter:    0.20,   // 抖动权重 (越低越好)
    Stability: 0.25,   // 稳定性权重 (成功率越高越好)
    Bandwidth: 0.10,   // 带宽权重 (越高越好)
    Region:    0.10,   // 区域匹配权重
}
```

### 评分计算

```
总分 = 0.35 × 延迟分 + 0.20 × 抖动分 + 0.25 × 稳定性分 + 0.10 × 带宽分
```

- **延迟分**: 0ms = 100分, 500ms+ = 0分
- **抖动分**: 0ms = 100分, 100ms+ = 0分
- **稳定性分**: 成功率 × 100

## 节点指标 (NodeMetrics)

```go
type NodeMetrics struct {
    ID          string          // 节点唯一标识
    Name        string          // 节点名称
    Address     string          // 节点地址
    LastLatency time.Duration   // 上次延迟
    AvgLatency  time.Duration   // 平均延迟
    Jitter      time.Duration   // 抖动
    PacketLoss  float64         // 丢包率
    SuccessRate float64         // 成功率 (0-1)
    Bandwidth   int64           // 带宽 (bytes/s)
    LastCheck   time.Time        // 最后检查时间
    Score       float64         // 当前评分 (0-100)
    History     *LatencyHistory  // 延迟历史
}
```

## 自动模式决策逻辑

```go
func (s *Selector) selectAuto(nodes []*NodeMetrics) (string, error) {
    // 1. 计算各指标分布
    lowLatencyCount  // 低延迟节点数量 (<100ms)
    stableCount       // 稳定节点数量 (成功率 >95%)

    // 2. 决策
    if 低延迟节点占比 > 50% {
        return selectFast()    // 优先低延迟
    }
    if 稳定节点占比 < 30% {
        return selectStable()  // 网络不稳定，优先稳定
    }
    return selectBalanced()    // 默认均衡选择
}
```

## 区域匹配

Smart 支持智能区域匹配，可根据目标服务自动选择最优地区节点。

### 支持的地区代码

| 代码 | 地区 | 代码 | 地区 |
|------|------|------|------|
| `jp` | 日本 | `us` | 美国 |
| `hk` | 香港 | `sg` | 新加坡 |
| `kr` | 韩国 | `uk` | 英国 |
| `de` | 德国 | `au` | 澳大利亚 |
| `tw` | 台湾 | `cn` | 中国大陆 |

### 服务自动识别

Smart 可自动识别常见服务并推荐地区：

| 服务 | 推荐地区 |
|------|----------|
| Netflix, YouTube, Google | `us` |
| GitHub, Spotify | `us` |
| 百度, 阿里云, 腾讯 | `cn`/`hk` |

## 配置示例

```yaml
# config.yaml
smart:
  enabled: true
  learning-enabled: true        # 启用学习模式
  selection-mode: auto          # 选择模式
  update-interval: 5s           # 更新间隔

  # 可选：自定义评分权重
  weights:
    latency: 0.35
    jitter: 0.20
    stability: 0.25
    bandwidth: 0.10
    region: 0.10
```

## Proxy Groups 中使用 Smart

Smart 可以作为代理组类型使用，实现智能节点选择：

```yaml
proxy-groups:
  # 基础 Smart 组
  - name: smart-proxy
    type: smart                    # 使用 Smart 策略
    proxies:
      - node-us-01
      - node-jp-01
      - node-sg-01
    smart-mode: auto               # auto, fast, stable, balanced, learning
    target-region: ""               # 可选：优先选择特定地区

  # 针对流媒体优化的 Smart 组
  - name: streaming
    type: smart
    proxies:
      - node-us-01
      - node-jp-01
    smart-mode: fast               # 低延迟优先
    target-region: us              # 优先美国节点

  # 针对游戏优化的 Smart 组
  - name: gaming
    type: smart
    proxies:
      - node-jp-01
      - node-kr-01
      - node-sg-01
    smart-mode: fast               # 最低延迟
    target-region: jp              # 优先日本节点

  # 针对稳定连接优化的 Smart 组
  - name: stable-proxy
    type: smart
    proxies:
      - node-us-01
      - node-jp-01
    smart-mode: stable             # 稳定性优先
```

### Smart 组参数说明

| 参数 | 说明 | 可选值 |
|------|------|--------|
| `type` | 组类型，必须设为 `smart` | - |
| `proxies` | 包含的节点列表 | 节点名称数组 |
| `smart-mode` | 选择模式 | `auto`, `fast`, `stable`, `balanced`, `learning` |
| `target-region` | 优先地区 | `us`, `jp`, `hk`, `sg`, `kr`, `tw`, `cn` 等 |

## API 接口

### 获取统计信息

```bash
GET /v1/stats

Response:
{
    "total_nodes": 5,
    "avg_score": 78.5,
    "best_score": 92.3,
    "best_node": "node-jp-01",
    "mode": "auto"
}
```

### 健康检查

```bash
GET /health

Response:
{"status": "ok"}
```

## 工作流程

```
1. 节点注册
   └── RegisterNode(id, name, address)

2. 指标更新
   └── UpdateMetrics(id, latency, success)
       ├── 更新延迟历史
       ├── 计算平均值、抖动
       └── 计算评分

3. 节点选择
   └── SelectNode(ctx)
       ├── 根据模式选择策略
       ├── 计算各节点评分
       └── 返回最优节点

4. 持续学习 (learning-enabled)
   └── Learner 分析历史数据
       └── 优化未来决策
```

## 代码使用示例

```go
import "github.com/mihomo/smartplus/core/policy/smart"

// 1. 初始化 Smart 引擎
policy := smart.NewSmart(smart.Config{
    LearningEnabled: true,
    SelectionMode:   smart.ModeAuto,
    UpdateInterval:  5 * time.Second,
})

// 2. 注册节点
policy.RegisterNode("node-hk-01", "香港节点", "hk.example.com")
policy.RegisterNode("node-jp-01", "日本节点", "jp.example.com")

// 3. 设置节点地区 (可选)
selector := smart.NewSelector()
selector.SetNodeRegion("node-hk-01", "hk")
selector.SetNodeRegion("node-jp-01", "jp")

// 4. 更新指标 (健康检查后调用)
policy.UpdateMetrics("node-hk-01", 120*time.Millisecond, true)

// 5. 选择最优节点
ctx := context.Background()
bestNode, err := policy.SelectNode(ctx)

// 6. 按目标选择 (如 Netflix 选美国节点)
bestNode, err := policy.SelectNodeForTarget(ctx, "netflix")

// 7. 获取统计
stats := policy.GetStats()
fmt.Printf("最优节点: %s (评分: %.2f)\n", stats.BestNode, stats.BestScore)

// 8. 获取评分详情
scorer := smart.NewScorer()
breakdown := scorer.GetBreakdown(nodeMetrics)
fmt.Printf("延迟分: %.2f, 稳定性分: %.2f\n", breakdown.LatencyScore, breakdown.StabilityScore)
```

## 扩展点

### 1. 自定义评分权重

```go
scorer.SetWeights(smart.Weights{
    Latency:   0.5,    // 更重视延迟
    Jitter:    0.1,
    Stability: 0.3,
    Bandwidth: 0.1,
})
```

### 2. 目标区域匹配

```go
selector.SetTargetRegion("netflix.com", "us")
// 选择美国节点访问 Netflix
```

### 3. Top-N 节点

```go
topNodes := selector.GetTopN(nodes, 3)
// 获取评分前3的节点
```

### 4. 延迟预测

```go
predictedLatency, ok := policy.PredictLatency("node-hk-01")
if ok {
    fmt.Printf("预测延迟: %v\n", predictedLatency)
}
```

## 性能考虑

- 使用读写锁保护节点指标
- 延迟历史限制为100条记录
- 后台定时刷新评分 (默认5秒)
- 预测功能要求至少10条历史数据

## 与其他组件关系

```
Smart
    │
    ├── outbound.Manager
    │   └── 使用 Smart 选择节点
    │
    ├── metrics.Collector
    │   └── 提供性能指标数据
    │
    └── control.Controller
        └── 通过 API 暴露状态
```
