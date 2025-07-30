# Embrace Chaos Makefile

# Variables
GO_VERSION := 1.21
BINARY_NAME := embrace-chaos-api
API_GATEWAY_BINARY := api-gateway
BUILD_DIR := build
DOCKER_IMAGE := embrace-chaos/api-gateway
VERSION := $(shell git describe --tags --always --dirty)

# Go related variables
GOFILES := $(shell find . -name '*.go' -type f)
GOPACKAGES := $(shell go list ./...)

# Default target
.PHONY: all
all: deps test build

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy
	go mod vendor

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run tests with verbose output
.PHONY: test-verbose
test-verbose:
	@echo "Running tests with verbose output..."
	go test -v -race -coverprofile=coverage.out ./...

# Run linting
.PHONY: lint
lint:
	@echo "Running linter..."
	golangci-lint run ./...

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .

# Build all services
.PHONY: build
build: build-api-gateway

# Build API Gateway
.PHONY: build-api-gateway
build-api-gateway:
	@echo "Building API Gateway..."
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags "-X main.version=$(VERSION) -w -s" \
		-o $(BUILD_DIR)/$(API_GATEWAY_BINARY) \
		./cmd/api-gateway

# Build for local development
.PHONY: build-local
build-local:
	@echo "Building for local development..."
	mkdir -p $(BUILD_DIR)
	go build \
		-ldflags "-X main.version=$(VERSION)" \
		-o $(BUILD_DIR)/$(API_GATEWAY_BINARY) \
		./cmd/api-gateway

# Run API Gateway locally
.PHONY: run-api-gateway
run-api-gateway: build-local
	@echo "Running API Gateway locally..."
	./$(BUILD_DIR)/$(API_GATEWAY_BINARY) \
		--port=8080 \
		--host=localhost \
		--db-dsn="postgres://postgres:password@localhost/embrace_chaos?sslmode=disable" \
		--jwt-secret="your-secret-key" \
		--enable-cors

# Run with Docker Compose
.PHONY: run-local
run-local:
	@echo "Starting services with Docker Compose..."
	docker-compose up -d postgres
	sleep 5
	$(MAKE) run-api-gateway

# Docker build
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(VERSION) -t $(DOCKER_IMAGE):latest .

# Docker run
.PHONY: docker-run
docker-run:
	@echo "Running Docker container..."
	docker run -p 8080:8080 --env-file .env $(DOCKER_IMAGE):latest

# Generate OpenAPI documentation
.PHONY: docs
docs:
	@echo "Generating API documentation..."
	swagger generate spec -o ./api/openapi/swagger.yaml --scan-models

# Database migrations
.PHONY: migrate-up
migrate-up:
	@echo "Running database migrations..."
	migrate -path ./internal/adapters/storage/migrations -database "postgres://postgres:password@localhost/embrace_chaos?sslmode=disable" up

.PHONY: migrate-down
migrate-down:
	@echo "Rolling back database migrations..."
	migrate -path ./internal/adapters/storage/migrations -database "postgres://postgres:password@localhost/embrace_chaos?sslmode=disable" down

.PHONY: migrate-create
migrate-create:
	@echo "Creating new migration..."
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir ./internal/adapters/storage/migrations $$name

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	go clean -testcache
	go clean -modcache

# Security scanning
.PHONY: security-scan
security-scan:
	@echo "Running security scan..."
	gosec ./...

# Dependency check
.PHONY: deps-check
deps-check:
	@echo "Checking for dependency vulnerabilities..."
	nancy sleuth

# Generate mocks
.PHONY: mocks
mocks:
	@echo "Generating mocks..."
	mockgen -source=internal/core/ports/experiment.go -destination=internal/core/ports/mocks/experiment.go
	mockgen -source=internal/core/ports/execution.go -destination=internal/core/ports/mocks/execution.go
	mockgen -source=internal/core/ports/provider.go -destination=internal/core/ports/mocks/provider.go
	mockgen -source=internal/core/ports/store.go -destination=internal/core/ports/mocks/store.go

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all              - Install deps, run tests, and build"
	@echo "  deps             - Install Go dependencies"
	@echo "  test             - Run tests with coverage"
	@echo "  test-verbose     - Run tests with verbose output"
	@echo "  lint             - Run linter"
	@echo "  fmt              - Format code"
	@echo "  build            - Build all services"
	@echo "  build-api-gateway - Build API Gateway service"
	@echo "  build-local      - Build for local development"
	@echo "  run-api-gateway  - Run API Gateway locally"
	@echo "  run-local        - Run with Docker Compose"
	@echo "  docker-build     - Build Docker image"
	@echo "  docker-run       - Run Docker container"
	@echo "  docs             - Generate API documentation"
	@echo "  migrate-up       - Run database migrations"
	@echo "  migrate-down     - Roll back database migrations"
	@echo "  migrate-create   - Create new migration"
	@echo "  clean            - Clean build artifacts"
	@echo "  security-scan    - Run security scanner"
	@echo "  deps-check       - Check for dependency vulnerabilities"
	@echo "  mocks            - Generate mocks for testing"
	@echo "  help             - Show this help message"

# Check if required tools are installed
.PHONY: check-tools
check-tools:
	@echo "Checking required tools..."
	@which go > /dev/null || (echo "Go is not installed" && exit 1)
	@which docker > /dev/null || (echo "Docker is not installed" && exit 1)
	@which migrate > /dev/null || (echo "golang-migrate is not installed" && exit 1)
	@echo "All required tools are installed"