package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/embrace-chaos/internal/adapters/http"
	"github.com/embrace-chaos/internal/adapters/http/middleware"
	"github.com/embrace-chaos/internal/adapters/storage"
	"github.com/embrace-chaos/internal/adapters/providers/aws"
	"github.com/embrace-chaos/internal/core/services"
	"github.com/embrace-chaos/internal/core/parsers"
	"github.com/embrace-chaos/internal/core/orchestrator"
	"github.com/embrace-chaos/internal/core/safety"
)

const (
	version = "1.0.0"
)

func main() {
	// Parse command line flags
	var (
		port     = flag.Int("port", 8080, "HTTP server port")
		host     = flag.String("host", "0.0.0.0", "HTTP server host")
		dbDSN    = flag.String("db-dsn", "", "Database connection string")
		jwtSecret = flag.String("jwt-secret", "", "JWT secret key")
		enableCORS = flag.Bool("enable-cors", true, "Enable CORS")
	)
	flag.Parse()

	// Validate required flags
	if *dbDSN == "" {
		log.Fatal("Database DSN is required (--db-dsn)")
	}
	if *jwtSecret == "" {
		log.Fatal("JWT secret is required (--jwt-secret)")
	}

	// Create logger
	logger := &defaultLogger{}

	// Setup dependencies
	ctx := context.Background()
	
	// Database
	dbAdapter, err := storage.NewPostgresAdapter(*dbDSN)
	if err != nil {
		log.Fatalf("Failed to create database adapter: %v", err)
	}
	defer dbAdapter.Close()

	// Connect to database
	if err := dbAdapter.Connect(ctx, *dbDSN); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Create store
	store := storage.NewPostgresRepository(dbAdapter)

	// Provider (using AWS as default)
	provider, err := aws.NewAWSProvider(aws.Config{
		Region: "us-east-1", // Default region
	})
	if err != nil {
		log.Printf("Warning: Failed to initialize AWS provider: %v", err)
		provider = nil // Continue without provider
	}

	// Core services
	parser := parsers.NewYAMLParser()
	orchestrator := orchestrator.NewSagaOrchestrator(store, provider, logger)
	safetyController := safety.NewSafetyController(store, provider, logger)

	experimentService := services.NewExperimentService(store, parser, logger)
	executionService := services.NewExecutionService(store, orchestrator, safetyController, logger)
	targetService := services.NewTargetService(store, provider, logger)

	// HTTP server configuration
	serverConfig := http.ServerConfig{
		Port:            *port,
		Host:            *host,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 30 * time.Second,
	}

	// Router configuration
	routerConfig := http.RouterConfig{
		JWTSecret:   []byte(*jwtSecret),
		Version:     version,
		EnableCORS:  *enableCORS,
		CORSOrigins: []string{}, // Allow all origins in development
	}

	// Create router and server
	router := http.NewRouter(
		routerConfig,
		experimentService,
		executionService,
		targetService,
		store,
		provider,
		logger,
	)

	server := http.NewServer(serverConfig, router, logger)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal")
		cancel()
	}()

	// Start server
	logger.Info("Starting Embrace Chaos API Gateway",
		middleware.Field{Key: "version", Value: version},
		middleware.Field{Key: "port", Value: *port},
		middleware.Field{Key: "host", Value: *host},
	)

	if err := server.Start(ctx); err != nil {
		log.Fatalf("Server failed: %v", err)
	}

	logger.Info("API Gateway shutdown complete")
}

// Simple logger implementation for the main function
type defaultLogger struct{}

func (l *defaultLogger) Info(msg string, fields ...middleware.Field) {
	logStr := "INFO: " + msg
	for _, field := range fields {
		logStr += fmt.Sprintf(" %s=%v", field.Key, field.Value)
	}
	log.Println(logStr)
}

func (l *defaultLogger) Error(msg string, fields ...middleware.Field) {
	logStr := "ERROR: " + msg
	for _, field := range fields {
		logStr += fmt.Sprintf(" %s=%v", field.Key, field.Value)
	}
	log.Println(logStr)
}

func (l *defaultLogger) Warn(msg string, fields ...middleware.Field) {
	logStr := "WARN: " + msg
	for _, field := range fields {
		logStr += fmt.Sprintf(" %s=%v", field.Key, field.Value)
	}
	log.Println(logStr)
}