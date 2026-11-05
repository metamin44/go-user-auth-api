package middle

import (
	"net/http"
	"strconv"
	"time"

	"reg/internal/metrics"

	"github.com/labstack/echo/v4"
)

func MetricsMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()

		err := next(c)

		// Handle the error before reading the response status.
		if err != nil {
			c.Error(err)
		}

		duration := time.Since(start)

		path := c.Path()
		if path == "" {
			path = "unmatched"
		}

		method := c.Request().Method
		status := c.Response().Status

		if status == 0 {
			status = http.StatusOK
		}

		metrics.RequestCount.WithLabelValues(
			method,
			path,
			strconv.Itoa(status),
		).Inc()

		metrics.RequestDuration.WithLabelValues(
			method,
			path,
		).Observe(duration.Seconds())

		return nil
	}
}
