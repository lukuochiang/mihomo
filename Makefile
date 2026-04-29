.PHONY: all build clean test lint run install set-version build-linux build-arm build-gvisor

# Variables
BINARY_NAME=mihomo
BINDIR=bin

# Git info
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
BRANCH=smart

# Version info from VERSION.txt (SemVer format)
# Can be overridden: make set-version VERSION=v1.0.0
-include .version.local

# Try VERSION.txt first, then fall back to git-based versioning
VERSION_FILE := $(shell cat VERSION.txt 2>/dev/null || echo "")
ifneq ($(VERSION_FILE),)
    # Use VERSION.txt + branch + commit for complete version
    VERSION := $(VERSION_FILE)-$(BRANCH)-$(COMMIT)
else
    # Version logic (aligned with vernesong/mihomo)
    # Based on branch name: Alpha -> alpha-smart, Beta -> beta, others -> commit hash
    ifeq ($(BRANCH),Alpha)
        VERSION = alpha-smart-$(COMMIT)
    else ifeq ($(BRANCH),Beta)
        VERSION = beta-$(COMMIT)
    else ifeq ($(BRANCH),)
        # detached HEAD or no git
        VERSION = $(shell git describe --tags 2>/dev/null || echo "$(COMMIT)")
    else
        VERSION = $(COMMIT)
    endif
endif

# ldflags for version info (aligned with vernesong/mihomo)
GO_LDFLAGS=-ldflags '-X "github.com/lukuochiang/mihomo/constant.Version=$(VERSION)" \
	-X "github.com/lukuochiang/mihomo/constant.BuildTime=$(BUILD_TIME)" \
	-X main.commit=$(COMMIT) \
	-X main.branch=$(BRANCH) \
	-w -s -buildid='

# Go commands
GO=go
GOTEST=$(GO) test
GOBUILD=$(GO) build
GOCLEAN=$(GO) clean
GOMOD=$(GO) mod

# Directories
BUILD_DIR=./build
CMD_DIR=.

# Platform settings
GOAMD64?=v3

# Build targets
all: clean build

# Set version (usage: make set-version VERSION=v1.0.0)
set-version:
	@echo "Setting version to $(VERSION)"
	@echo "Use git tag and branch for automatic versioning:"
	@echo "  - Alpha branch -> alpha-smart-{hash}"
	@echo "  - Beta branch  -> beta-{hash}"
	@echo "  - Other branch -> {hash}"
	@echo "Done! Run 'make build' to rebuild."

# Default build (darwin)
build:
	@echo "Building ${BINARY_NAME} (darwin, GOAMD64=$(GOAMD64))..."
	@mkdir -p ${BUILD_DIR}
	CGO_ENABLED=0 GOAMD64=$(GOAMD64) ${GOBUILD} -tags with_gvisor -trimpath ${GO_LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME} ${CMD_DIR}

# Darwin builds
darwin-amd64:
	@mkdir -p ${BINDIR}
	GOOS=darwin GOARCH=amd64 GOAMD64=v3 CGO_ENABLED=0 ${GOBUILD} -tags with_gvisor -trimpath ${GO_LDFLAGS} -o ${BINDIR}/${BINARY_NAME}-darwin-amd64-v3-${VERSION} ${CMD_DIR}

darwin-arm64:
	@mkdir -p ${BINDIR}
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 ${GOBUILD} -tags with_gvisor -trimpath ${GO_LDFLAGS} -o ${BINDIR}/${BINARY_NAME}-darwin-arm64-${VERSION} ${CMD_DIR}

# Linux builds
build-linux:
	@echo "Building ${BINARY_NAME} for Linux..."
	@mkdir -p ${BINDIR}
	GOOS=linux GOARCH=amd64 GOAMD64=v3 CGO_ENABLED=0 ${GOBUILD} -tags with_gvisor -trimpath ${GO_LDFLAGS} -o ${BINDIR}/${BINARY_NAME}-linux-amd64-v3-${VERSION} ${CMD_DIR}

linux-amd64:
	@mkdir -p ${BINDIR}
	GOOS=linux GOARCH=amd64 GOAMD64=v3 CGO_ENABLED=0 ${GOBUILD} -tags with_gvisor -trimpath ${GO_LDFLAGS} -o ${BINDIR}/${BINARY_NAME}-linux-amd64-v3-${VERSION} ${CMD_DIR}

linux-arm64:
	@mkdir -p ${BINDIR}
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 ${GOBUILD} -tags with_gvisor -trimpath ${GO_LDFLAGS} -o ${BINDIR}/${BINARY_NAME}-linux-arm64-${VERSION} ${CMD_DIR}

# Windows builds
windows-amd64:
	@mkdir -p ${BINDIR}
	GOOS=windows GOARCH=amd64 GOAMD64=v3 CGO_ENABLED=0 ${GOBUILD} -tags with_gvisor -trimpath ${GO_LDFLAGS} -o ${BINDIR}/${BINARY_NAME}-windows-amd64-v3-${VERSION}.exe ${CMD_DIR}

windows-arm64:
	@mkdir -p ${BINDIR}
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 ${GOBUILD} -tags with_gvisor -trimpath ${GO_LDFLAGS} -o ${BINDIR}/${BINARY_NAME}-windows-arm64-${VERSION}.exe ${CMD_DIR}

# gvisor build (optional - adds ~10MB to binary size)
build-gvisor:
	@echo "Building ${BINARY_NAME} with gvisor support..."
	@mkdir -p ${BUILD_DIR}
	CGO_ENABLED=0 GOAMD64=$(GOAMD64) ${GOBUILD} -tags with_gvisor -trimpath ${GO_LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-gvisor ${CMD_DIR}

# All platforms (for release)
all-platforms: darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-amd64 windows-arm64
	@echo "All platforms built successfully!"

clean:
	@echo "Cleaning..."
	@rm -rf ${BUILD_DIR}
	@rm -rf ${BINDIR}
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
	${GOBUILD} -tags with_gvisor -trimpath ${GO_LDFLAGS} -o /usr/local/bin/${BINARY_NAME} ${CMD_DIR}

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
	docker build -t mihomo:$(VERSION) .

docker-run:
	docker run -p 7890:7890 -p 9090:9090 -v $(PWD)/config.yaml:/app/config.yaml mihomo:$(VERSION)

# Development
dev:
	@echo "Running in development mode..."
	${GO} run ${CMD_DIR} -config config.yaml.example

# Help
help:
	@echo "Available targets:"
	@echo "  all             - Clean, test, and build (default)"
	@echo "  build           - Build binary for current platform"
	@echo "  darwin-amd64    - Build for Darwin AMD64"
	@echo "  darwin-arm64    - Build for Darwin ARM64"
	@echo "  linux-amd64     - Build for Linux AMD64"
	@echo "  linux-arm64     - Build for Linux ARM64"
	@echo "  windows-amd64   - Build for Windows AMD64"
	@echo "  windows-arm64   - Build for Windows ARM64"
	@echo "  build-gvisor    - Build with gvisor TUN stack"
	@echo "  all-platforms   - Build all platforms for release"
	@echo "  clean           - Clean build artifacts"
	@echo "  test            - Run tests"
	@echo "  test-coverage   - Run tests with coverage report"
	@echo "  lint            - Run linter"
	@echo "  fmt             - Format code"
	@echo "  vet             - Run go vet"
	@echo "  run             - Run binary"
	@echo "  install         - Install binary to /usr/local/bin"
	@echo "  deps            - Download dependencies"
	@echo "  deps-update     - Update dependencies"
	@echo "  docker-build    - Build Docker image"
	@echo "  docker-run      - Run Docker container"
	@echo "  dev             - Run in development mode"
	@echo "  help            - Show this help"
