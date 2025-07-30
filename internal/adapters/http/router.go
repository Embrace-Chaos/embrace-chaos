package http

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
	"github.com/embrace-chaos/internal/core/ports"
	"github.com/embrace-chaos/internal/adapters/http/handlers"
	"github.com/embrace-chaos/internal/adapters/http/middleware"
)

// RouterConfig holds configuration for the HTTP router
type RouterConfig struct {
	JWTSecret []byte
	Version   string
	EnableCORS bool
	CORSOrigins []string
}

// Router handles HTTP routing and middleware setup
type Router struct {
	config            RouterConfig
	experimentService ports.ExperimentService
	executionService  ports.ExecutionService
	targetService     ports.TargetService
	store             ports.Store
	provider          ports.Provider
	logger            middleware.Logger
}

// NewRouter creates a new HTTP router with all handlers and middleware
func NewRouter(
	config RouterConfig,
	experimentService ports.ExperimentService,
	executionService ports.ExecutionService,
	targetService ports.TargetService,
	store ports.Store,
	provider ports.Provider,
	logger middleware.Logger,
) *Router {
	return &Router{
		config:            config,
		experimentService: experimentService,
		executionService:  executionService,
		targetService:     targetService,
		store:             store,
		provider:          provider,
		logger:            logger,
	}
}

// SetupRoutes configures all routes and middleware
func (r *Router) SetupRoutes() http.Handler {
	router := mux.NewRouter()
	
	// Create middleware
	authMiddleware := middleware.NewAuthMiddleware(r.config.JWTSecret)
	loggingMiddleware := middleware.NewLoggingMiddleware(r.logger)
	validator := middleware.NewRequestValidator()
	
	// Create handlers
	experimentHandler := handlers.NewExperimentHandler(
		r.experimentService,
		r.executionService,
		validator,
	)
	executionHandler := handlers.NewExecutionHandler(
		r.executionService,
		validator,
	)
	targetHandler := handlers.NewTargetHandler(
		r.targetService,
		validator,
	)
	healthHandler := handlers.NewHealthHandler(
		r.store,
		r.provider,
		r.config.Version,
	)
	
	// API version prefix
	apiRouter := router.PathPrefix("/v1").Subrouter()
	
	// Health endpoints (no auth required)
	router.HandleFunc("/health", healthHandler.HealthCheck).Methods("GET")
	router.HandleFunc("/health/ready", healthHandler.ReadinessCheck).Methods("GET")
	
	// OpenAPI spec endpoint (no auth required)
	router.HandleFunc("/openapi.yaml", r.serveOpenAPISpec).Methods("GET")
	router.HandleFunc("/swagger.yaml", r.serveOpenAPISpec).Methods("GET")
	
	// Experiment routes
	experimentRoutes := apiRouter.PathPrefix("/experiments").Subrouter()
	experimentRoutes.HandleFunc("", experimentHandler.ListExperiments).Methods("GET")
	experimentRoutes.HandleFunc("", experimentHandler.CreateExperiment).Methods("POST")
	experimentRoutes.HandleFunc("/{experimentId}", experimentHandler.GetExperiment).Methods("GET")
	experimentRoutes.HandleFunc("/{experimentId}", experimentHandler.UpdateExperiment).Methods("PUT")
	experimentRoutes.HandleFunc("/{experimentId}", experimentHandler.DeleteExperiment).Methods("DELETE")
	experimentRoutes.HandleFunc("/{experimentId}/execute", experimentHandler.ExecuteExperiment).Methods("POST")
	experimentRoutes.HandleFunc("/{experimentId}/validate", experimentHandler.ValidateExperiment).Methods("POST")
	
	// Execution routes
	executionRoutes := apiRouter.PathPrefix("/executions").Subrouter()
	executionRoutes.HandleFunc("", executionHandler.ListExecutions).Methods("GET")
	executionRoutes.HandleFunc("/{executionId}", executionHandler.GetExecution).Methods("GET")
	executionRoutes.HandleFunc("/{executionId}/cancel", executionHandler.CancelExecution).Methods("POST")
	executionRoutes.HandleFunc("/{executionId}/logs", executionHandler.GetExecutionLogs).Methods("GET")
	
	// Target routes
	targetRoutes := apiRouter.PathPrefix("/targets").Subrouter()
	targetRoutes.HandleFunc("", targetHandler.ListTargets).Methods("GET")
	targetRoutes.HandleFunc("/discover", targetHandler.DiscoverTargets).Methods("POST")
	
	// Apply middleware in order
	var handler http.Handler = router
	
	// CORS middleware (if enabled)
	if r.config.EnableCORS {
		corsOptions := []handlers.CORSOption{
			handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
			handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "X-Request-ID"}),
			handlers.ExposedHeaders([]string{"X-Request-ID"}),
		}
		
		if len(r.config.CORSOrigins) > 0 {
			corsOptions = append(corsOptions, handlers.AllowedOrigins(r.config.CORSOrigins))
		} else {
			corsOptions = append(corsOptions, handlers.AllowedOriginValidator(func(origin string) bool {
				return true // Allow all origins for development
			}))
		}
		
		handler = handlers.CORS(corsOptions...)(handler)
	}
	
	// Authentication middleware (applied to API routes only)
	apiRouter.Use(authMiddleware.Middleware)
	
	// Logging middleware (applied to all routes)
	handler = loggingMiddleware.Middleware(handler)
	
	// Recovery middleware
	handler = handlers.RecoveryHandler(handlers.PrintRecoveryStack(true))(handler)
	
	return handler
}

// serveOpenAPISpec serves the OpenAPI specification
func (r *Router) serveOpenAPISpec(w http.ResponseWriter, req *http.Request) {
	// In a real implementation, this would read the actual OpenAPI spec file
	// For now, we'll redirect to the spec file location
	http.Redirect(w, req, "/api/openapi/swagger.yaml", http.StatusTemporaryRedirect)
}