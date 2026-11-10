# ADR 0003: Password Reset Security

- **Status:** Accepted
- **Date:** 2026-11-10

## Context

Password reset is a sensitive authentication operation. A reset token
may be exposed, stolen, or reused if it is not properly protected.

The application needs to ensure that reset tokens are short-lived,
stored securely, validated before use, and consumed only once.

The password reset request must also avoid revealing whether an
email address belongs to an existing account.

## Decision

The application uses short-lived, signed JWTs for password reset.

Each reset token:

- Is signed with a dedicated reset signing key.
- Uses the `reset` token type.
- Has a 15-minute expiration time.
- Contains the user's email as its subject.

Only the SHA-256 hash of the reset token is stored in the database.
The raw token is sent to the user through the configured email service.

The application validates both the JWT and its corresponding
database record before accepting a password reset.

## Implementation Details

### Requesting a password reset

1. The application generates a signed reset JWT.
2. The token is hashed using SHA-256.
3. Only the token hash and its expiration time are stored.
4. If email delivery is enabled, the raw token is sent to the user.
5. The endpoint returns a generic response regardless of whether
   the email exists or the reset email can be delivered.

The generic response is:

    If the email exists, a password reset link will be sent.

### Completing a password reset

The reset handler:

1. Parses and validates the JWT using the dedicated reset key.
2. Requires the expected reset token type.
3. Extracts the email from the token subject.
4. Retrieves the corresponding user.
5. Hashes the submitted token and compares it with the stored hash.
6. Checks the database expiration time.
7. Validates the new password.
8. Hashes the new password using bcrypt.
9. Calls `CompletePasswordReset` to consume the token and update
   the password.

### Atomic token consumption

`CompletePasswordReset` performs a conditional database update.

The update succeeds only when all of the following conditions hold:

- The user ID matches.
- The stored reset token hash matches the submitted token hash.
- The reset token expiration time is later than the current time.

The same update:

- Replaces the password hash.
- Clears the stored reset token.
- Clears the reset token expiration.
- Increments the user's `token_version`.

If no row is affected, the operation returns
`ErrInvalidOrExpiredResetToken`.

This prevents a reset token from being successfully consumed more
than once, including when multiple requests attempt to use it.

## Consequences

### Benefits

- Reset tokens have a limited 15-minute lifetime.
- A dedicated signing key separates reset tokens from other JWT types.
- Raw reset tokens are not stored in the database.
- Both JWT validation and database validation are required.
- Conditional token consumption prevents successful token replay.
- Successful password reset invalidates existing tokens through
  token version increment.
- Generic responses reduce account enumeration through the
  password reset request endpoint.

### Trade-offs

- Password reset depends on database availability.
- Email delivery must be configured for users to receive reset links.
- Reset tokens are single-use; users must request a new link if
  a token expires or has already been consumed.

## Related Code

- `tokenutil/token.go`: `GenerateResetToken`
- `handler/userhandler.go`: `hashResetToken`
- `handler/userhandler.go`: `ForgotPassword`
- `handler/userhandler.go`: `ResetPassword`
- `handler/userhandler.go`: `passwordResetResponse`
- `repository/user.go`: `SavePasswordResetToken`
- `repository/user.go`: `CompletePasswordReset`
- `handler/resetpassword_test.go`: password reset tests
