# ADR 0001: Refresh Token Rotation

- **Status:** Accepted
- **Date:** 2026-11-10

## Context

Long-lived refresh tokens can remain useful to an attacker if they
are stolen. Reusing the same refresh token indefinitely also makes
it difficult to detect token theft or replay.

The application needs a mechanism to renew access while limiting
the lifetime and reuse of refresh tokens.

## Decision

The application uses refresh token rotation.

Whenever a valid refresh token is used, the server generates a new
refresh token and replaces the stored token hash for that session.

The application stores only the SHA-256 hash of each refresh token,
not the raw token.

Each session is associated with a user ID, session ID, token hash,
expiration time, and session status.

## Implementation Details

The `RotateSession` repository operation:

1. Validates the supplied rotation parameters.
2. Computes SHA-256 hashes of the old and new refresh tokens.
3. Starts a database transaction.
4. Locks the matching session row using `SELECT ... FOR UPDATE`.
5. Checks whether the session exists, is not revoked, and has not expired.
6. Compares the stored token hash with the old token hash using
   `subtle.ConstantTimeCompare`.
7. Replaces the stored hash and updates expiration and last-used time.
8. Commits the transaction.

If the stored hash does not match the supplied old token hash,
the session is revoked and the operation returns
`ErrRefreshTokenReuse` after the revocation transaction commits.

## Consequences

### Benefits

- Previously used refresh tokens cannot be used successfully again.
- Only token hashes are stored in the database.
- Reuse of an old refresh token triggers session revocation.
- Session expiration and revocation are checked during rotation.
- Database transactions protect the token replacement operation.

### Trade-offs

- Refresh token rotation requires a database write.
- Refresh requests depend on database availability.
- A client must securely store and replace its refresh token
  after every successful refresh operation.
- Reuse detection revokes the affected session, requiring the user
  to authenticate again.

## Related Code

- `repository/user.go`: `hashRefreshToken`
- `repository/user.go`: `CreateSession`
- `repository/user.go`: `RotateSession`
