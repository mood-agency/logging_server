package middleware

import (
	"fmt"
	"loggingserver/config"


	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func ConfigureMiddleware(app *fiber.App) {
	// Add CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins:     config.GetEnv("CORS_ALLOWED_ORIGINS", "http://localhost:8080"),
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))

	// Add compression middleware
	app.Use(compress.New())

	// Add logger middleware
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${method} ${path}\n",
	}))

	// // Add rate limiting middleware
	// app.Use(limiter.New(limiter.Config{
	// 	Max:        config.GetRateLimitMax(),
	// 	Expiration: config.GetRateLimitExpiration(),
	// 	KeyGenerator: func(c *fiber.Ctx) string {
	// 		return c.IP()
	// 	},
	// 	LimitReached: func(c *fiber.Ctx) error {
	// 		return c.Status(fiber.StatusTooManyRequests).SendString("Rate limit exceeded")
	// 	},
	// }))

	// Add security headers
	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Set("Content-Security-Policy", "default-src 'self'")
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		return c.Next()
	})

	// Add verbose logging middleware
	app.Use(verboseLogging)
}

func verboseLogging(c *fiber.Ctx) error {
	if config.Verbose {
		fmt.Printf("Endpoint hit: %s %s\n", c.Method(), c.Path())
	}
	return c.Next()
}