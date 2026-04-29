.PHONY: all build clean test lint run install

# Variables
BINARY_NAME=mihomo
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GO_LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_TIME}"

# Go commands
GO=go
GOTEST=$(GO) test
GOBUILD=$(GO) build
GOCLEAN=$(GO) clean
GOMOD=$(GO) mod

# Directories
BUILD_DIR=./build
CMD_DIR=.

# Build targets
all: clean test build

build:
	@echo "Building ${BINARY_NAME}..."
	@mkdir -p ${BUILD_DIR}
	CGO_ENABLED=0 ${GOBUILD} ${GO_LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME} ${CMD_DIR}

build-linux:
	@echo "Building ${BINARY_NAME} for Linux..."
	@mkdir -p ${BUILD_DIR}
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 ${GOBUILD} ${GO_LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-amd64 ${CMD_DIR}

build-arm:
	@echo "Building ${BINARY_NAME} for ARM..."
	@mkdir -p ${BUILD_DIR}
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 ${GOBUILD} ${GO_LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-arm64 ${CMD_DIR}

# gvisor build (optional - adds ~10MB to binary size)
build-gvisor:
	@echo "Building ${BINARY_NAME} with gvisor support..."
	@mkdir -p ${BUILD_DIR}
	CGO_ENABLED=0 ${GOBUILD} -tags with_gvisor ${GO_LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-gvisor ${CMD_DIR}

clean:
	@echo "Cleaning..."
	@rm -rf ${BUILD_DIR}
	@${GOCLEAN}

test:
	@echo "Running tests..."
	${GOTEST} -v -race -cover ./...

test-coverage:
	@echo "Running tests with coverage..."
	${GOTEST} -v -race -coverprofile=coverage.out ./...
	${GO} tool cover -html=coverage.out -o coverage.html

lint:
	@echo "Running linter..."
	golangci-lint run ./...

fmt:
	@echo "Formatting code..."
	${GO} fmt ./...

vet:
	@echo "Running go vet..."
	${GO} vet ./...

run:
	@echo "Running ${BINARY_NAME}..."
	${GO} run ${CMD_DIR} -config config.yaml

install:
	@echo "Installing ${BINARY_NAME}..."
	${GOBUILD} ${GO_LDFLAGS} -o /usr/local/bin/${BINARY_NAME} ${CMD_DIR}

deps:
	@echo "Downloading dependencies..."
	${GOMOD} download
	${GOMOD} tidy

deps-update:
	@echo "Updating dependencies..."
	${GOMOD} update
	${GOMOD} tidy

# Docker
docker-build:
	docker build -t mihomo:${VERSION} .

docker-run:
	docker run -p 7890:7890 -p 9090:9090 -v $(PWD)/config.yaml:/app/config.yaml mihomo:${VERSION}

# Development
dev:
	@echo "Running in development mode..."
	${GO} run ${CMD_DIR} -config config.yaml.example

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Clean, test, and build"
	@echo "  build        - Build binary"
	@echo "  build-linux  - Build for Linux"
	@echo "  build-arm    - Build for ARM"
	@echo "  build-gvisor - Build with gvisor TUN stack"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  vet          - Run go vet"
	@echo "  run          - Run binary"
	@echo "  install      - Install binary"
	@echo "  deps         - Download dependencies"
	@echo "  deps-update  - Update dependencies"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  dev          - Run in development mode"
	@echo "  help         - Show this help"
