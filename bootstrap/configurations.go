package bootstrap

import (
	"net/http"
	"strings"
	"time"

	config "auth_server/config"
	view "auth_server/view"

	"github.com/labstack/echo-contrib/prometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

/*
   |--------------------------------------------------------------------------
   | Configurations
   |--------------------------------------------------------------------------
*/
func InitConfigurations(app *echo.Echo) {
	// Error Handler
	app.HTTPErrorHandler = config.CustomHTTPErrorHandler

	// Rate limit config
	config := middleware.RateLimiterConfig{
		Skipper: middleware.DefaultSkipper,
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{
				Rate:      10,
				Burst:     30,
				ExpiresIn: 3 * time.Minute,
			},
		),
		IdentifierExtractor: func(ctx echo.Context) (string, error) {
			id := ctx.RealIP()
			return id, nil
		},
		ErrorHandler: func(ctx echo.Context, err error) error {
			return view.ApiView(http.StatusForbidden, ctx, &view.Response{
				Success: false,
				Message: "Forbidden",
				Payload: nil,
			})
		},
		DenyHandler: func(ctx echo.Context, identifier string, err error) error {
			return view.ApiView(http.StatusTooManyRequests, ctx, &view.Response{
				Success: false,
				Message: "Too many requests",
				Payload: nil,
			})
		},
	}

	// Logger Middleware
	app.Logger.SetLevel(log.INFO)
	app.Use(middleware.Logger())

	// Body Limit
	app.Use(middleware.BodyLimit("5M"))

	// Gzip middleware
	app.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
		Skipper: func(c echo.Context) bool {
			return strings.Contains(c.Path(), "metrics") ||
				strings.Contains(c.Path(), "openapi")
		},
	}))

	// Recover Middleware
	app.Use(middleware.Recover())

	// Rate Limiter Middleware
	app.Use(middleware.RateLimiterWithConfig(config))

	// Secure Headers Middleware
	app.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            3600,
		ContentSecurityPolicy: "default-src 'self' 'unsafe-inline'",
	}))

	// CORS Middleware
	app.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{
			echo.HeaderOrigin,
			echo.HeaderContentType,
			echo.HeaderAccept,
			echo.HeaderXRequestID,
			echo.HeaderAuthorization,
		},
		AllowMethods: []string{
			http.MethodOptions,
			http.MethodHead,
			http.MethodGet,
			http.MethodPut,
			http.MethodPost,
			http.MethodDelete,
		},
	}))

	// Timeout
	app.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: 30 * time.Second,
	}))

	// Prometheus
	prometheus_metrics := prometheus.NewPrometheus("emigapi", nil)
	prometheus_metrics.Use(app)
}
