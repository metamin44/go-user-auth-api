# Security & Code-Quality Remediation Report — Go User Auth API

Date: 2026-11-21
Scope: all 23 findings from the prior audit, re-verified against current source before fixing.
Skills applied: `security-best-practices` (no Go-specific reference files ship with the skill; well-known Go/Echo/JWT guidance applied) and `go-quality` (gofmt, go vet; golangci-lint/staticcheck availability noted below).

## Executive summary

All 23 findings were re-verified: 20 were confirmed and fixed, 3 are intentionally deferred with justification (shared rate-limit store, trusted-proxy extractor, query combining). No false positives. No commits or pushes were made. All unit and integration tests pass, and the full stack was validated live in Docker (non-root image, stdout logs, auth/refresh/logout/admin flows, CORS denial, body limits, rate limiting).

## Finding status

| # | Finding | Classification | Status |
|---|---------|----------------|--------|
| 1 | Empty rate-limit env defaults crash startup (`log.Fatal`) | Confirmed bug | Fixed — valid defaults `3-M/5-M/2-M` in config; formats validated at startup |
| 2 | Deleted user → 500 instead of 401 in JWT middleware | Confirmed bug | Fixed — `gorm.ErrRecordNotFound` mapped to 401; verified live |
| 3 | ChangePassword maps every DB error to 500 "user not found" | Confirmed bug | Fixed — 404 for missing user, 500 with correct message otherwise |
| 4 | Login does not normalize email (Register does) | Confirmed bug | Fixed — trim + lowercase in Login; verified live with mixed-case email |
| 5 | `helpertest.go` (imports `testing`) compiled into production binary | Confirmed bug | Fixed — renamed to `helper_test.go` |
| 6 | Dead `_ "net/http/pprof"` import (DefaultServeMux never served) | Confirmed dead code (not exposed) | Fixed — import removed |
| 7 | `EnableLogs` config loaded but never used | Confirmed dead config | Fixed — field removed from config, `.env.example`, CI |
| 8 | Access TTL hardcoded to 24h | Confirmed security issue | Fixed — `JWT_ACCESS_TTL` (default 15m) / `JWT_REFRESH_TTL` (default 168h), validated (positive, access ≤ refresh) |
| 9 | CORS allows all origins by default | Confirmed security issue | Fixed — same-origin only unless `CORS_ALLOWED_ORIGINS` whitelist set; `*` rejected; verified live |
| 10 | In-memory rate-limit store per instance | Recommended improvement | Deferred — Redis forbidden by task constraints; documented in README (already listed as production requirement) |
| 11 | `ExtractIPDirect` breaks behind reverse proxy | Recommended improvement | Deferred — task forbids changing trusted-proxy behavior without explicit security config; documented in router comment + README |
| 12 | No request body size limit | Confirmed security issue | Fixed — `middleware.BodyLimit("1M")`; verified live (2MB body → 413) |
| 13 | Public `/metrics`, `/swagger`; GET `/reset-password` unthrottled; app ports on all interfaces | Confirmed security issue | Fixed — Swagger gated by `ENABLE_SWAGGER` (default off); GET reset page shares reset limiter; compose app ports bound to `127.0.0.1` (Prometheus still scrapes via Docker network) |
| 14 | No logout endpoint | Confirmed missing control | Fixed — `POST /auth/logout` revokes the current session (idempotent); access + refresh die immediately; verified live on both instances |
| 15 | Login timing side-channel (user enumeration) | Confirmed security issue | Fixed — dummy bcrypt compare at equal cost for unknown emails |
| 16 | No fail-fast config validation (empty JWT keys → runtime 500s) | Confirmed security issue | Fixed — `LoadConfig() (*Config, error)` validates ports, DB fields, JWT key length ≥ 32, TTLs, rate formats, email completeness; errors never contain secret values |
| 17 | Two DB queries per authenticated request | Recommended improvement | Deferred — combining risks the auth path for marginal gain (two PK lookups); task forbids weakening security for performance. Both checks retained |
| 18 | Single-stage root Dockerfile; `logs/app.log` baked into image | Confirmed security issue | Fixed — multi-stage, `CGO_ENABLED=0`, static binary, alpine runtime, non-root `appuser`, `logs/` added to `.dockerignore`; verified `whoami` = appuser |
| 19 | Logger writes only to file (no `docker logs`) | Confirmed ops/security issue | Fixed — zap tee to file + stdout; verified live JSON logs |
| 20 | Expired/revoked sessions accumulate forever | Recommended improvement | Fixed — `DeleteExpiredSessions` + hourly cleanup goroutine in main (cancelled before DB close); deleting dead sessions weakens no check |
| 21 | Reset TTL duplicated (token.go + handler) | Recommended improvement | Fixed — shared `tokenutil.ResetTokenTTL` constant; unit test asserts exp−iat |
| 22 | No admin demote, no bootstrap path, no actor audit | Recommended improvement | Fixed — `PUT /admin/demote` (self-demotion blocked, token version bumped), promote/demote log `acted_by_user_id`, README documents SQL bootstrap of first admin |
| 23 | Tests require live MySQL; fragile helper | Recommended improvement | Fixed — `//go:build integration` tags separate unit vs integration; CI updated; helper fails fast on errors |

## Files modified

Source: `config/config.go`, `tokenutil/token.go`, `repository/user.go`, `middleware/jwtmiddleware.go`, `handler/userhandler.go`, `router/router.go`, `main.go`, `logger/logger.go`, `validationuser/validator.go` (lint: error-string conventions)
Tests: `handler/helper_test.go` (renamed from `helpertest.go`), all 12 existing `handler/*_test.go` + `repository/user_test.go` (build tag + LoadConfig signature), `middleware/jwtmiddleware_test.go` (new cases)
New tests: `config/config_test.go`, `tokenutil/token_test.go`, `handler/logout_test.go`, `handler/demoteadmin_test.go`, `handler/loginmapping_test.go`, `repository/session_cleanup_test.go`
Infra/docs: `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `.env.example`, `.github/workflows/go.yml`, `README.md`
Local only (gitignored): `.env` — appended `ENABLE_SWAGGER=true` to preserve local Swagger behavior.

## Tests added or modified

- Config: 15 validation failure cases + defaults/whitelist/custom-TTL success cases (unit).
- Tokenutil: round-trips for all 3 token types, type-confusion rejection, wrong key, expired, tampered signature, `alg=none` attack, input validation, shared reset TTL (unit).
- Middleware: deleted-user → 401 case; `session_id` context assertion (unit).
- Logout: session revocation kills access + refresh; idempotent revoke; missing session context → 401 (integration).
- Demote: success + token-version bump, self-demotion 400, non-admin target 400, non-admin actor 403 (integration).
- Login: mixed-case/whitespace email login; unknown email uniform 401; ChangePassword deleted user → 404 (integration).
- Repository: global cleanup keeps only active sessions; revoke idempotency (integration).

## Validation results

| Check | Result |
|-------|--------|
| `go build ./...` | pass |
| `go vet ./...` and `go vet -tags=integration ./...` | pass |
| `gofmt -l .` | clean (docs/ generated files excluded, pre-existing) |
| `go test -count=1 ./...` (unit) | pass — config, middleware, tokenutil, validationuser |
| `go test -p 1 -count=1 -tags=integration ./...` (MySQL 8 in Docker) | pass — all 6 packages, run 3× consecutively |
| Docker build (multi-stage) + `compose up app1 app2` | both healthy; migration completed on app1 |
| Runtime user / stdout logs | `appuser` (non-root); JSON logs visible in `docker logs` |
| Live flows | register → login (normalized email) → profile → refresh → reuse detection 401 → logout → access/refresh 401; admin bootstrap → dashboard 200 → self-demote 400; account delete → token 401 |
| CORS / body limit / rate limit | no CORS headers for foreign origin; 2MB body → 413; `X-RateLimit-Limit: 5` on GET reset page |
| Ports | app1/app2 published on `127.0.0.1` only |
| `-race` | not runnable on this Windows host (no gcc/cgo); CI runs `-race` on Ubuntu |
| golangci-lint v2.15.0 (go1.27.3; errcheck, govet, ineffassign, staticcheck, unused) | **0 issues** after fixing 3 errcheck sites in `refreshhandler_test.go` and 3 ST1005 error-string issues in `validationuser/validator.go` |
| staticcheck (preinstalled 2025.1.1) | cannot analyze go1.27 export data (built with go1.24); superseded by the staticcheck bundled in golangci-lint v2.15.0 |
| govulncheck (freshly installed, go1.27-compatible) | installed successfully, but vulnerability DB fetch blocked: `vuln.go.dev` returned **403 Forbidden** from this network. CVE scan is a verification gap — re-run `govulncheck ./...` from an unrestricted network |

Tooling note: the preinstalled staticcheck and govulncheck binaries were built with Go 1.24 and could not process this Go 1.27 module. golangci-lint v2.15.0 and a current govulncheck were installed successfully; lint is clean, but the govulncheck database download is network-blocked (403). Re-run `govulncheck ./...` as a follow-up.

## Remaining risks / intentionally deferred

1. **#10 Shared rate-limit store** — per-instance memory store means effective limits multiply by instance count and reset on restart. Requires Redis (excluded by task constraints). Already documented as a production requirement in README.
2. **#11 Trusted proxy** — behind a reverse proxy, all client IPs collapse to the proxy IP and rate limiting will throttle everyone. Needs an explicit trusted-proxy CIDR configuration before such a deployment; documented.
3. **#17 Query combining** — two indexed PK lookups per authenticated request retained deliberately; any merge must preserve both revocation checks atomically.
4. **Access tokens remain stateless between checks** — revocation granularity is per-request DB checks (unchanged, security preserved).
5. **Dependency CVE scan** — govulncheck installed but `vuln.go.dev` is network-blocked (403); scan pending from an unrestricted network.
6. **Local `.env` hygiene** — the local Grafana admin password is weak; rotate it (Grafana is localhost-bound, not committed).

## Configuration / environment changes required

- New optional env vars (secure defaults apply): `JWT_ACCESS_TTL=15m`, `JWT_REFRESH_TTL=168h`, `CORS_ALLOWED_ORIGINS=` (empty = same-origin only), `ENABLE_SWAGGER` (default off; local `.env` set to `true`).
- **Breaking for existing deployments:** JWT keys must now be ≥ 32 characters (current local keys are 64 — unaffected); startup aborts on invalid config instead of failing at runtime; cross-origin browser clients must be whitelisted explicitly; app ports are localhost-bound in compose (put a TLS proxy in front for external access).
- Removed: `ENABLE_LOGS` (was dead config).
- CI: longer test-only JWT keys; test step now `-tags=integration`.
- Run integration tests with `docker compose up -d db` first; unit tests need no dependencies.

---

# Final Independent Review (2026-11-21)

Scope: full git diff vs original implementation, regression/compatibility check, test-tag isolation, CI, lifecycle, authorization, diff hygiene, config consistency. No code changes made in this phase.

## Validation results (all re-run)

| Check | Result |
|-------|--------|
| `go build ./...` | pass |
| `go vet ./...` + `go vet -tags=integration ./...` | pass |
| `go test -count=1 ./...` (unit) | pass — only config, middleware, tokenutil, validationuser compile; handler/repository have **0** test files without the tag (verified via `go list`) |
| `go test -p 1 -count=1 -tags=integration ./...` | pass — all 6 packages against MySQL 8 |
| `go test -race` | not runnable on this Windows host (`-race requires cgo`, no gcc). CI confirmed: `ubuntu-24.04` + `go test -p 1 -race -count=1 -tags=integration ./...` (.github/workflows/go.yml:15,69) |
| `golangci-lint run --build-tags=integration` (v2.15.0) | **0 issues** |
| `docker compose config --quiet` | valid; app1/app2 healthy |
| Diff hygiene | no secrets (only explicitly test-only CI fixtures), no logs, no binaries, no generated-file changes; untracked = 7 new test files + this report; `.env` untracked; `helpertest.go` → `helper_test.go` rename complete |

## Review confirmations

- **Lifecycle:** defer order in `run()` is LIFO — `stopCleanup()` runs before `repo.Close()`; cleanup goroutine checks `ctx.Err()` after each delete and selects on `ctx.Done()`; `DeleteExpiredSessions` uses `WithContext(ctx)`. No goroutine leak, no use-after-close.
- **Authorization:** `RevokeSession` is scoped to `user_id AND session_id` taken from validated middleware context (no cross-user revocation); logout is idempotent without state oracle; demote requires `RequireRole("admin")`, blocks self-demotion, bumps `token_version` (invalidates all target tokens); deleted-user path returns the same generic 401 as invalid tokens (no existence oracle).
- **API compatibility:** response shapes unchanged; changes are additive (logout/demote) or intentional bug fixes (ChangePassword 404/500 mapping, deleted-user 401). Minor client-visible text change: 72-byte password error lowercased without trailing period (validationuser/validator.go:53,114). Documented breaking config changes: CORS default-deny, Swagger opt-in, 15m access TTL, localhost-bound ports.
- **Config consistency:** `.env.example` ↔ config defaults ↔ CI ↔ compose ↔ Dockerfile aligned; `ENABLE_LOGS` removed everywhere except the local `.env` cleanup already applied; compose `environment` overrides (`DB_HOST=db`) correctly take precedence over `env_file`.

## New findings

### F-1 (HIGH): Vulnerable dependencies — govulncheck now succeeded (network unblocked)

14 symbol-level vulnerabilities affect the code:

| Module | Found | Fixed in | CVEs |
|--------|-------|----------|------|
| `github.com/labstack/echo/v4` (go.mod:10) | v4.13.4 | v4.16.0 | GO-2026-6883, 6881, 6879, 6877, 6876, 6873 (6) |
| `github.com/labstack/echo/v4` | v4.13.4 | **N/A** | GO-2026-6875 (ReverseProxy X-Real-IP), GO-2026-6872 (rate-limiter XFF spoofing) (2) |
| `net/http` stdlib (go.mod:3 `go 1.27.3`, Dockerfile:2) | go1.27.3 | go1.27.4 | GO-2026-6859 (1) |
| `golang.org/x/net` (go.mod:53) | v0.40.0 | v0.60.0 | GO-2026-6617, 6612, 6611, 6603 (4) |
| `golang.org/x/text` (go.mod:55) | v0.25.0 | v0.39.0 | GO-2026-5970 (1) |

Exploitability context: the app uses none of Echo's Static/JSONP/MethodOverride/HTTPSRedirect/CSRF/ReverseProxy middlewares, and `e.IPExtractor = echo.ExtractIPDirect()` (router/router.go:26) ignores X-Forwarded-For, which mitigates GO-2026-6872 in the current configuration. The upgrade is still required for the core-routing issues and defense in depth.

Recommended remediation (awaiting approval — modifies go.mod/go.sum/Dockerfile):
`go get github.com/labstack/echo/v4@v4.16.0 golang.org/x/net@v0.60.0 golang.org/x/text@v0.39.0 && go mod tidy`; bump `go` directive and builder image to 1.27.4; re-run full validation and rebuild images.

### F-2 (LOW): Generated Swagger docs are stale

`docs/swagger.json` and `docs/docs.go` do not contain `/auth/logout` and `/admin/demote` (annotations exist in handler/userhandler.go). `swag` CLI is installed; regeneration (`swag init`) is a one-command fix, deferred pending approval to keep this review change-free.

## Production-readiness assessment

The remediated codebase is **functionally complete and verified**: all 20 in-scope fixes are in place, lint/vet/build are clean, unit and integration suites pass, the Docker stack runs healthy as non-root with stdout logging, and auth/refresh/rotation/logout/admin flows were validated live.

**Remaining blockers before production:**
1. **F-1 dependency/toolchain upgrades (HIGH)** — Echo ≥ v4.16.0, x/net ≥ v0.60.0, x/text ≥ v0.39.0, Go ≥ 1.27.4.
2. Deployment prerequisites (documented, unchanged): TLS termination, shared rate-limit store for multi-instance, explicit trusted-proxy configuration if behind a reverse proxy, strong Grafana admin password.
3. F-2 Swagger regeneration (LOW, cosmetic).
4. `-race` coverage relies on CI (cannot run on this host).

---

# F-1 / F-2 Remediation (2026-11-21, approved)

## F-1: Dependency upgrades — RESOLVED (12 of 14; 2 unfixable upstream, mitigated)

| Module | Before | After | Vulnerabilities resolved |
|--------|--------|-------|--------------------------|
| `github.com/labstack/echo/v4` | v4.13.4 | **v4.16.0** | GO-2026-6883, 6881, 6879, 6877, 6876, 6873 (6) |
| Go toolchain (`go` directive + Dockerfile builder) | 1.27.3 | **1.27.4** | GO-2026-6859 (stdlib net/http) |
| `golang.org/x/net` | v0.40.0 | **v0.60.0** | GO-2026-6617, 6612, 6611, 6603 (4) |
| `golang.org/x/text` | v0.25.0 | **v0.42.0** | GO-2026-5970 (1) |

x/text landed on v0.42.0 (not v0.39.0) because x/net v0.60.0 transitively requires ≥ v0.42.0 — still above the fixed version. Other bumps (x/crypto v0.57.0, x/sys, x/time, x/tools, gommon v0.5.0, testify v1.11.1, go-colorable/isatty) are all MVS transitive requirements of the targeted upgrades, not arbitrary changes.

**govulncheck after upgrade: 14 → 2 affecting vulnerabilities**, both unfixable upstream (`Fixed in: N/A`):

1. **GO-2026-6875** — Echo `ReverseProxy` middleware forwards attacker-supplied `X-Real-IP`. **Not reachable:** this project never uses Echo's ReverseProxy middleware (verified by source grep). Residual risk: none in current code; would apply only if that middleware is adopted later.
2. **GO-2026-6872** — Rate-limiter bypass via spoofed `X-Forwarded-For` under Echo's *default* IP extraction. **Mitigated by configuration:** `e.IPExtractor = echo.ExtractIPDirect()` (router/router.go:26) uses the direct connection IP and ignores forwarded headers, so `c.RealIP()` used by the rate limiter cannot be spoofed. Residual risk: appears only if a future change switches to an XFF-trusting extractor without a trusted-proxy allowlist (already documented as a deployment prerequisite).

**Compatibility fix required by the upgrade:** Echo v4.16.0 deprecates `middleware.LoggerWithConfig` (staticcheck SA1019). Migrated to `middleware.RequestLoggerWithConfig` in router/router.go with a custom `LogValuesFunc` that preserves the historical access-log format (`time=… method=… path=… status=… latency=… remote_ip=…`) and stdout destination. The `path` field uses `LogURIPath`/`v.URIPath`, which equals the legacy `${path}` tag (`req.URL.Path`) for both matched and unmatched (404) requests and excludes the query string; an initial `RoutePath`-based version logged an empty path for 404s and was corrected in the final pre-commit pass. No security control touched.

## F-2: Swagger regeneration — RESOLVED

Regenerated with the project's existing process: `swag init` (swag v1.16.4, matching go.mod). Files: `docs/docs.go`, `docs/swagger.json`, `docs/swagger.yaml`.

Endpoint inventory verified: all 11 original paths retained, plus **POST /auth/logout** and **PUT /admin/demote** (13 total). No existing documentation removed.

## Changed files (this phase)

`go.mod`, `go.sum`, `Dockerfile` (builder → golang:1.27.4-alpine), `router/router.go` (request-logger migration), `docs/docs.go`, `docs/swagger.json`, `docs/swagger.yaml`. CI needs no change (`go-version-file: go.mod` follows automatically).

## Validation (this phase)

| Check | Result |
|-------|--------|
| `go build ./...` | pass |
| `go vet ./...` + `-tags=integration` | pass |
| `gofmt` | clean |
| `golangci-lint run --build-tags=integration` | **0 issues** |
| `go test -count=1 ./...` (unit) | pass (4 packages) |
| `go test -p 1 -count=1 -tags=integration ./...` | pass (6 packages) — auth, sessions, JWT, refresh rotation, password reset, rate limiting all exercised |
| `govulncheck ./...` | 2 remaining, both N/A upstream and mitigated (see above) |
| `docker compose config --quiet` | valid |
| Docker rebuild (Go 1.27.4) + healthchecks | pass — app1/app2 healthy, non-root `appuser`, access-log format preserved, live register→login→refresh→logout→401 flow verified, served `/swagger/doc.json` has 13 paths incl. both new endpoints |
| Swagger JSON | 13 paths incl. both new endpoints |

## Remaining concerns

- The 2 unfixable Echo advisories above (mitigated; re-check on future Echo releases).
- Deployment prerequisites unchanged: TLS, shared rate-limit store for multi-instance, explicit trusted-proxy config, strong Grafana password.
- `-race` runs in CI only (no cgo on this host).