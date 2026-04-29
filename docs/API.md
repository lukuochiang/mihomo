openapi: 3.0.3
info:
  title: mihomo smart API
  description: |
    RESTful API for mihomo smart proxy kernel.
    
    All endpoints (except `/health`) require Bearer token authentication.
    Include the header: `Authorization: Bearer YOUR_SECRET`
  version: 1.0.0
  contact:
    name: mihomo smart
    url: https://github.com/mihomo/smart
  license:
    name: MIT

servers:
  - url: http://localhost:9090
    description: Default server

security:
  - BearerAuth: []

tags:
  - name: Health
    description: Health check endpoints
  - name: Nodes
    description: Node management
  - name: Statistics
    description: Statistics and metrics
  - name: Configuration
    description: Configuration management
  - name: WebSocket
    description: Real-time updates

paths:
  /health:
    get:
      summary: Health check
      description: Check if the server is running
      operationId: healthCheck
      tags:
        - Health
      security: []
      responses:
        '200':
          description: Server is healthy
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    example: ok
                  version:
                    type: string
                    example: "1.0.0"

  /v1/nodes:
    get:
      summary: List all nodes
      description: Get a list of all available proxy nodes with their current status and metrics
      operationId: listNodes
      tags:
        - Nodes
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                type: object
                properties:
                  nodes:
                    type: array
                    items:
                      $ref: '#/components/schemas/Node'
                  total:
                    type: integer
                    example: 5

  /v1/nodes/{nodeId}:
    get:
      summary: Get node details
      description: Get detailed information about a specific node
      operationId: getNode
      tags:
        - Nodes
      parameters:
        - name: nodeId
          in: path
          required: true
          description: Node ID (name)
          schema:
            type: string
            example: node-us-01
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NodeDetail'
        '404':
          description: Node not found

  /v1/stats:
    get:
      summary: Get Smart policy statistics
      description: Get statistics from the Smart policy engine including best node, scores, and current mode
      operationId: getStats
      tags:
        - Statistics
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SmartStats'

  /v1/select:
    post:
      summary: Select a node manually
      description: |
        Manually select a specific node for the next connection.
        The selected node will be used until another selection is made.
      operationId: selectNode
      tags:
        - Nodes
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - node
              properties:
                node:
                  type: string
                  description: Node name to select
                  example: node-us-01
      responses:
        '200':
          description: Node selected successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  node:
                    type: string
                    example: node-us-01
        '400':
          description: Invalid node name
        '404':
          description: Node not found

  /v1/select/auto:
    post:
      summary: Auto select best node
      description: Let Smart policy engine automatically select the best node
      operationId: autoSelectNode
      tags:
        - Nodes
      requestBody:
        required: false
        content:
          application/json:
            schema:
              type: object
              properties:
                mode:
                  type: string
                  enum: [auto, fast, stable, balanced, learning]
                  description: Selection mode
                  default: auto
                target:
                  type: string
                  description: Target service hint (e.g., "netflix", "jp")
      responses:
        '200':
          description: Node selected
          content:
            application/json:
              schema:
                type: object
                properties:
                  node:
                    type: string
                    example: node-us-01
                  score:
                    type: number
                    format: float
                    example: 92.5
                  mode:
                    type: string
                    example: auto

  /v1/reload:
    post:
      summary: Trigger config hot reload
      description: Trigger a configuration hot reload without restarting the service
      operationId: reloadConfig
      tags:
        - Configuration
      requestBody:
        required: false
        content:
          application/json:
            schema:
              type: object
              properties:
                config_path:
                  type: string
                  description: Optional path to new config file
      responses:
        '200':
          description: Reload initiated
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  message:
                    type: string
                    example: "Configuration reloaded successfully"

  /v1/reload/status:
    get:
      summary: Get reload status
      description: Get the current status of the last reload operation
      operationId: getReloadStatus
      tags:
        - Configuration
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    enum: [idle, in_progress, success, failed]
                  last_reload:
                    type: string
                    format: date-time
                  error:
                    type: string
                    nullable: true

  /api/ws:
    get:
      summary: WebSocket connection
      description: |
        Establish a WebSocket connection for real-time updates.
        
        The server will push:
        - Node metrics updates
        - Connection events
        - Policy changes
        
        Authentication is done via query parameter: `/api/ws?token=YOUR_SECRET`
      operationId: websocketConnect
      tags:
        - WebSocket
      security: []
      parameters:
        - name: token
          in: query
          required: true
          description: Bearer token for authentication
          schema:
            type: string
      responses:
        '101':
          description: Switching Protocols - WebSocket connection established
        '401':
          description: Unauthorized

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: API secret token

  schemas:
    Node:
      type: object
      properties:
        id:
          type: string
          description: Node unique identifier
          example: node-us-01
        name:
          type: string
          description: Node display name
          example: US Node 01
        type:
          type: string
          description: Protocol type
          example: vmess
        address:
          type: string
          description: Server address
          example: us.example.com
        port:
          type: integer
          description: Server port
          example: 443
        online:
          type: boolean
          description: Whether node is online
          example: true
        metrics:
          $ref: '#/components/schemas/NodeMetrics'

    NodeDetail:
      allOf:
        - $ref: '#/components/schemas/Node'
        - type: object
          properties:
            region:
              type: string
              description: Detected region
              example: us
            tags:
              type: array
              items:
                type: string
              description: Node tags
              example: [streaming, gaming]
            history:
              type: array
              items:
                $ref: '#/components/schemas/MetricPoint'

    NodeMetrics:
      type: object
      properties:
        latency:
          type: number
          format: float
          description: Current latency in milliseconds
          example: 120.5
        avg_latency:
          type: number
          format: float
          description: Average latency
          example: 115.2
        jitter:
          type: number
          format: float
          description: Latency jitter
          example: 5.3
        packet_loss:
          type: number
          format: float
          description: Packet loss rate (0-1)
          example: 0.001
        success_rate:
          type: number
          format: float
          description: Success rate (0-1)
          example: 0.998
        bandwidth:
          type: integer
          format: int64
          description: Current bandwidth in bytes/s
          example: 1048576
        score:
          type: number
          format: float
          description: Overall score (0-100)
          example: 92.5
        last_check:
          type: string
          format: date-time

    MetricPoint:
      type: object
      properties:
        timestamp:
          type: string
          format: date-time
        latency:
          type: number
          format: float
        success:
          type: boolean

    SmartStats:
      type: object
      properties:
        total_nodes:
          type: integer
          example: 5
        online_nodes:
          type: integer
          example: 4
        avg_score:
          type: number
          format: float
          example: 78.5
        best_score:
          type: number
          format: float
          example: 92.3
        best_node:
          type: string
          example: node-us-01
        mode:
          type: string
          enum: [auto, fast, stable, balanced, learning]
          example: auto
        learning_enabled:
          type: boolean
          example: true
        predictions:
          type: object
          description: ML predictions for each node
          additionalProperties:
            type: object
            properties:
              predicted_latency:
                type: number
              confidence:
                type: number
          example:
            node-us-01:
              predicted_latency: 118
              confidence: 0.85

    Error:
      type: object
      properties:
        error:
          type: string
          description: Error message
        code:
          type: integer
          description: Error code
          example: 404
