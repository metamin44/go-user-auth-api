package middle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestRateLimiterIgnoresForwardedForHeader(t *testing.T) {
	e := echo.New()
	e.IPExtractor = echo.ExtractIPDirect()

	limiter, err := RateLimiter("2-M")
	require.NoError(t, err)

	handler := limiter(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	sendRequest := func(forwardedFor string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.0.2.10:12345"

		if forwardedFor != "" {
			req.Header.Set(echo.HeaderXForwardedFor, forwardedFor)
		}

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler(c)
		if err != nil {
			e.HTTPErrorHandler(err, c)
		}

		return rec
	}

	first := sendRequest("198.51.100.1")
	require.Equal(t, http.StatusOK, first.Code)

	second := sendRequest("203.0.113.2")
	require.Equal(t, http.StatusOK, second.Code)

	third := sendRequest("198.51.100.3")
	require.Equal(t, http.StatusTooManyRequests, third.Code)
}
