package http

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/embrace-chaos/internal/adapters/http/middleware"
)

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Port            int
	Host            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Port:            8080,
		Host:            "0.0.0.0",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 30 * time.Second,
	}
}

// Server represents the HTTP server
type Server struct {
	config     ServerConfig
	httpServer *http.Server
	router     *Router
	logger     middleware.Logger
}

// NewServer creates a new HTTP server instance
func NewServer(
	config ServerConfig,
	router *Router,
	logger middleware.Logger,
) *Server {
	return &Server{
		config: config,
		router: router,
		logger: logger,
	}
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	// Setup routes
	handler := s.router.SetupRoutes()
	
	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.config.Host, s.config.Port),
		Handler:      handler,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}
	
	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		s.logger.Info("Starting HTTP server",
			middleware.Field{Key: "host", Value: s.config.Host},
			middleware.Field{Key: "port", Value: s.config.Port},
		)
		
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("failed to start HTTP server: %w", err)
		}
	}()
	
	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		return s.Shutdown()
	case err := <-serverErr:
		return err
	}
}

// Shutdown gracefully shuts down the HTTP server
func (s *Server) Shutdown() error {
	if s.httpServer == nil {
		return nil
	}
	
	s.logger.Info("Shutting down HTTP server")
	
	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
	defer cancel()
	
	// Shutdown server
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Error("Failed to shutdown HTTP server gracefully",
			middleware.Field{Key: "error", Value: err.Error()},
		)
		return fmt.Errorf("failed to shutdown HTTP server: %w", err)
	}
	
	s.logger.Info("HTTP server shutdown complete")
	return nil
}

// Health returns the server health status
func (s *Server) Health() error {
	if s.httpServer == nil {
		return fmt.Errorf("server not started")
	}
	return nil
}