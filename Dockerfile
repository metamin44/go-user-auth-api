# Build stage: compile a static binary (all deps, incl. bcrypt and MySQL driver, are pure Go).
FROM golang:1.27.4-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/main .

# Runtime stage: minimal image, no toolchain or source code, non-root user.
FROM alpine:3.22

# ca-certificates is required for SMTP TLS; busybox wget (included) serves the healthcheck.
RUN apk add --no-cache ca-certificates \
    && addgroup -S appgroup \
    && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /out/main ./main

# The app writes rotated logs to logs/app.log; the non-root user must own it.
RUN mkdir -p /app/logs && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8082

CMD ["./main"]