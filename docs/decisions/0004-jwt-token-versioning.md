# ADR 0004: JWT Token Versioning

- **Status:** Accepted
- **Date:** 2026-11-10

## Context

JWTs are stateless by design. A previously issued token can remain
cryptographically valid until its expiration time, even after
a security-sensitive account change.

The application needs a way to invalidate previously issued access
and refresh tokens when a user's credentials or privileges change.

## Decision

The application uses a per-user `token_version` value.

The current version is stored in the user's database record and
included in newly issued access and refresh JWTs.

When a security-sensitive operation occurs, the application
increments the stored version. Tokens containing an older version
are then rejected.

## Implementation Details

### Token issuance

Access and refresh tokens include the `token_version` claim.

New tokens use the current version stored in the user record.

### Version increment

The repository increments `token_version` when:

- A user changes their password.
- A user successfully resets their password.
- A user is promoted to the admin role.

The increment is performed in the database using:

    token_version = token_version + 1

Password changes and password resets also clear stored password
reset token data.

### Access token validation

The JWT middleware:

1. Validates the access token signature and token type.
2. Extracts and validates `user_id` and `token_version`.
3. Reads the user's current token version from the database.
4. Rejects the request if the token version does not match.

A version mismatch returns HTTP 401 Unauthorized.

### Refresh token validation

The refresh handler:

1. Validates the refresh token and its claims.
2. Extracts the user ID, token version, and session ID.
3. Retrieves the current user record.
4. Compares the token's version with the current database version.
5. Rejects stale refresh tokens before issuing new tokens.

A version mismatch returns HTTP 401 Unauthorized.

## Test Coverage

The handler tests verify token invalidation after a password change:

- `TestAccessTokenRevokedAfterPasswordChange` verifies that the
  token version increases and the old access token is rejected.
- `TestRefreshTokenRevokedAfterPasswordChange` verifies that the
  token version increases and the old refresh token is rejected.

Repository tests also verify version increments for the relevant
security-sensitive operations.

## Consequences

### Benefits

- Previously issued access tokens are rejected after a version change.
- Previously issued refresh tokens cannot be used to obtain new tokens.
- Token invalidation works across application instances sharing
  the same database.
- The mechanism supports invalidation after password changes,
  password resets, and admin privilege changes.

### Trade-offs

- Access token validation requires a database lookup for the
  current token version.
- Refresh token processing also requires current user data from
  the database.
- Authentication availability and latency depend partly on
  database availability.

## Related Code

- `tokenutil/token.go`: access and refresh token generation
- `middleware/jwtmiddleware.go`: `JWTMiddleware`
- `handler/userhandler.go`: `RefreshToken`
- `repository/user.go`: `UpdatePassword`
- `repository/user.go`: `CompletePasswordReset`
- `repository/user.go`: `PromoteUserToAdmin`
- `repository/user.go`: `GetTokenVersion`
- `handler/tokenrevocation_test.go`
