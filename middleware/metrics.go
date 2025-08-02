package middle

import (
	"net/http"
	"time"

	"reg/internal/metrics"

	"github.com/labstack/echo/v4"
)

func MetricsMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		err := next(c)
		duration := time.Since(start)

		path := c.Path()
		method := c.Request().Method
		status := c.Response().Status

		metrics.RequestCount.WithLabelValues(method, path, http.StatusText(status)).Inc()
		metrics.RequestDuration.WithLabelValues(method, path).Observe(duration.Seconds())

		return err
	}
}
