package middle

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"go.uber.org/zap"
)

func RateLimiter(rateStr string) (echo.MiddlewareFunc, error) {
	rate, err := limiter.NewRateFromFormatted(rateStr)
	if err != nil {
		zap.L().Error("Failed to parse rate limiter format", zap.String("rateStr", rateStr), zap.Error(err))
		return nil, err
	}

	store := memory.NewStore()
	limiterInstance := limiter.New(store, rate)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			logger := zap.L()

			ip := c.RealIP()
			if ip == "" {
				ip = "unknown"
			}

			context, err := limiterInstance.Get(c.Request().Context(), ip)
			if err != nil {
				logger.Error("Rate limiter failure", zap.String("ip", ip), zap.Error(err))
				return echo.NewHTTPError(http.StatusInternalServerError, "Rate limiter failed")
			}

			// Set rate limit headers
			c.Response().Header().Set("X-RateLimit-Limit", intToStr(context.Limit))
			c.Response().Header().Set("X-RateLimit-Remaining", intToStr(context.Remaining))
			c.Response().Header().Set("X-RateLimit-Reset", intToStr(int64(context.Reset)))

			if context.Reached {
				logger.Warn("Too many requests",
					zap.String("ip", ip),
					zap.String("path", c.Request().URL.Path),
					zap.Int64("limit", context.Limit),
					zap.Int64("remaining", context.Remaining),
				)
				return echo.NewHTTPError(http.StatusTooManyRequests, "Too many requests – slow down.")
			}

			logger.Debug("Request allowed by rate limiter",
				zap.String("ip", ip),
				zap.String("path", c.Request().URL.Path),
				zap.Int64("remaining", context.Remaining),
			)

			return next(c)
		}
	}, nil
}

func intToStr(i int64) string {
	return strconv.FormatInt(i, 10)

}
