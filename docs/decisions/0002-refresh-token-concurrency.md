# ADR 0002: Concurrent Refresh Token Requests

- **Status:** Accepted
- **Date:** 2026-11-10

## Context

Two or more requests may attempt to refresh the same session using
the same refresh token at nearly the same time.

Without concurrency control, multiple requests could validate the
same token before either request updates the stored token hash.
This could result in multiple valid refresh tokens for one session.

The application must serialize refresh operations for each session
and detect reuse of a token that has already been rotated.

## Decision

The application uses a database transaction and a row-level lock
to serialize refresh operations on the same session.

The repository uses GORM's `SELECT ... FOR UPDATE` through
`clause.Locking{Strength: "UPDATE"}` when loading the session.

The stored refresh token hash is checked while the row lock is held.
Only a request presenting the currently stored token can rotate
the session successfully.

If another request presents the old token after it has been rotated,
the mismatch is treated as refresh token reuse and the session
is revoked.

## Implementation Details

The `RotateSession` repository operation:

1. Starts a database transaction.
2. Acquires a row-level update lock on the matching session.
3. Checks the session's existence, revocation status, and expiration.
4. Compares the stored refresh token hash with the supplied token hash.
5. Updates the stored hash when the token is valid.
6. Revokes the session when a previously rotated token is reused.

The transaction ensures that concurrent refresh operations for
the same session cannot both rotate the same stored token.

## Test Coverage

The handler test `TestConcurrentRefreshToken` in
`handler/resetpassword_test.go` starts two concurrent refresh
requests using the same old refresh token.

The test verifies that:

- Both requests complete without an unexpected handler error.
- The HTTP responses are limited to `200 OK` or `401 Unauthorized`.
- The session is revoked after the concurrent refresh requests.

The test does not explicitly assert that exactly one request returns
each status code. It verifies the allowed outcomes and the final
revocation state.

## Consequences

### Benefits

- Concurrent refresh operations on the same session are serialized.
- The same refresh token cannot successfully rotate the session twice.
- Reuse detection revokes the affected session.
- The concurrency behavior is covered by a handler-level test.

### Trade-offs

- Row-level locking can make concurrent requests wait for one another.
- Refresh operations require database availability.
- A replay detected during concurrent requests can revoke the session,
  requiring the user to authenticate again.

## Related Code

- `repository/user.go`: `RotateSession`
- `handler/resetpassword_test.go`: `TestConcurrentRefreshToken`
