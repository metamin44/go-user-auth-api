# ADR 0005: Rate Limiting

- **Status:** Accepted
- **Date:** 2026-11-10

## Context

Authentication and password management endpoints are sensitive to
abuse, including brute-force login attempts, repeated password reset
requests, and excessive refresh token requests.

The application needs request limits to reduce abuse and protect
these endpoints from excessive traffic.

The service runs multiple application instances. Therefore, the
rate-limiting design must also document how limits behave when
requests are distributed across instances.

## Decision

The application uses the `ulule/limiter/v3` library with its
in-memory store.

Each rate-limited endpoint gets its own limiter instance.
Requests are identified by the client IP address obtained through
Echo's `c.RealIP()`.

The router configures Echo to use `echo.ExtractIPDirect()`.
Forwarded IP headers are therefore not trusted for client IP
extraction.

Rate limits are configurable through environment variables.

## Configured Limits

The default values in `.env.example` are:

| Endpoint | Environment variable | Default limit |
|---|---|---|
| Register | `RATE_LIMIT_REGISTER` | 3 requests per minute |
| Login | `RATE_LIMIT_LOGIN` | 5 requests per minute |
| Forgot password | `RATE_LIMIT_FORGOT_PASSWORD` | 2 requests per minute |
| Refresh token | `RATE_LIMIT_REFRESH` | 10 requests per minute |
| Reset password | `RATE_LIMIT_RESET_PASSWORD` | 5 requests per minute |

## Implementation Details

The `RateLimiter` middleware:

1. Parses the configured rate using `limiter.NewRateFromFormatted`.
2. Creates an in-memory store using `memory.NewStore()`.
3. Uses the request's client IP as the rate-limit key.
4. Retrieves the current rate-limit context.
5. Adds rate-limit information to the response headers.
6. Returns HTTP 429 when the request limit has been reached.
7. Otherwise, passes the request to the next handler.

The response headers are:

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

The middleware is applied to registration, login, refresh token,
forgot-password, and reset-password endpoints.

## Multi-Instance Behavior and Limitation

The current implementation uses an in-memory store.
Each application process maintains its own rate-limit state.

Consequently, when multiple instances run behind a load balancer,
requests routed to different instances are counted independently.

For example, a client may receive a separate request allowance
from each application instance. The configured limit is therefore
not a globally shared limit across all instances.

This implementation provides per-instance rate limiting, not
distributed rate limiting.

## Future Improvement

If a shared rate limit across application instances is required,
the in-memory store should be replaced with a shared store such as
Redis.

A shared store would allow all application instances to use the
same rate-limit state and enforce a consistent limit across the
deployment.

This is a future improvement and is not part of the current
implementation.

## Test Coverage

The middleware tests cover the following behaviors:

- `TestRateLimiterIgnoresForwardedForHeader` verifies that a
  forwarded IP header does not override the directly extracted
  client IP.
- `TestRateLimiterUsesIndependentBucketsPerIP` verifies that
  requests from the same IP share a rate-limit bucket, while
  requests from a different IP use an independent bucket.
  The test also verifies that an IP receives HTTP 429 after
  exceeding its configured limit, while another IP can still
  receive HTTP 200.

## Consequences

### Benefits

- Limits excessive requests to sensitive authentication endpoints.
- Uses configurable limits rather than hard-coded endpoint values.
- Separates limits for different endpoint categories.
- Returns HTTP 429 when a limit is reached.
- Exposes rate-limit information through response headers.
- Avoids trusting forwarded IP headers for client identification.

### Trade-offs

- In-memory state is local to each application process.
- Limits are not shared across multiple application instances.
- Rate-limit state is lost when an application process restarts.
- A shared store is required for consistent distributed enforcement.

## Related Code

- `middleware/ratelimiter.go`: `RateLimiter`
- `middleware/ratelimiter_test.go`: `TestRateLimiterIgnoresForwardedForHeader`
- `router/router.go`: rate limiter initialization and route configuration
- `config/config.go`: rate-limit configuration
- `.env.example`: default rate-limit values
