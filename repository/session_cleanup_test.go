//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"reg/model"
	"reg/tokenutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteExpiredSessions(t *testing.T) {
	repo, userID := setupRepositoryTest(t)

	newSessionID := func() string {
		t.Helper()
		id, err := tokenutil.GenerateSessionID()
		require.NoError(t, err)
		return id
	}

	activeID := newSessionID()
	expiredID := newSessionID()
	revokedID := newSessionID()

	// Active session: created through the normal path.
	require.NoError(t, repo.CreateSession(userID, activeID, "active-refresh-token", time.Now().Add(time.Hour)))

	// Expired session: inserted directly because CreateSession rejects past expiry.
	expired := model.UserSession{
		UserID:           userID,
		SessionID:        expiredID,
		RefreshTokenHash: hashRefreshToken("expired-refresh-token"),
		ExpiresAt:        time.Now().Add(-time.Hour),
	}
	require.NoError(t, repo.DB.Create(&expired).Error)

	// Revoked session: created active, then revoked.
	require.NoError(t, repo.CreateSession(userID, revokedID, "revoked-refresh-token", time.Now().Add(time.Hour)))
	require.NoError(t, repo.RevokeSession(userID, revokedID))

	deleted, err := repo.DeleteExpiredSessions(context.Background())
	require.NoError(t, err)
	// Cleanup is global; the shared test database may contain other dead
	// sessions, so only assert that at least our two were removed.
	assert.GreaterOrEqual(t, deleted, int64(2))

	// Only the active session survives.
	active, err := repo.IsSessionActive(userID, activeID)
	require.NoError(t, err)
	assert.True(t, active)

	var count int64
	require.NoError(t, repo.DB.Model(&model.UserSession{}).
		Where("user_id = ?", userID).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

func TestRevokeSessionIdempotent(t *testing.T) {
	repo, userID := setupRepositoryTest(t)

	sessionID, err := tokenutil.GenerateSessionID()
	require.NoError(t, err)

	require.NoError(t, repo.CreateSession(userID, sessionID, "some-refresh-token", time.Now().Add(time.Hour)))

	require.NoError(t, repo.RevokeSession(userID, sessionID))
	require.NoError(t, repo.RevokeSession(userID, sessionID))

	// Revoking a missing session is also a no-op, not an error.
	require.NoError(t, repo.RevokeSession(userID, "missing-session"))

	active, err := repo.IsSessionActive(userID, sessionID)
	require.NoError(t, err)
	assert.False(t, active)
}
