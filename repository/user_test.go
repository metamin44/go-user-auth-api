package repository

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"reg/config"
	"reg/model"

	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func setupRepositoryTest(t *testing.T) (*UserRepo, uint) {
	t.Helper()

	// Load .env if available (local development).
	// CI environments provide configuration through environment variables.
	if err := godotenv.Load("../.env"); err != nil {
		if !os.IsNotExist(err) {
			t.Fatalf("failed to load .env: %v", err)
		}
	}

	cfg := config.LoadConfig()
	cfg.Database.Host = "127.0.0.1"
	cfg.Database.Port = "3320"

	logger := zap.NewNop()

	repo, err := NewUserRepo(cfg)
	if err != nil {
		t.Fatalf("failed to connect to database: %v", err)
	}

	t.Cleanup(func() {
		if err := repo.Close(); err != nil {
			t.Errorf("failed to close database: %v", err)
		}
	})

	// Create a dedicated user for repository tests.
	user := model.User{
		Name:     "Repository Test User",
		Email:    fmt.Sprintf("repo-test-%d@example.com", time.Now().UnixNano()),
		Phone:    fmt.Sprintf("09%09d", time.Now().UnixNano()%1_000_000_000),
		Password: "test-password-hash",
	}

	// Use the test logger for this repository instance.
	repo.Logger = logger

	if err := repo.CreateUser(&user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	t.Cleanup(func() {
		if err := repo.DB.Where("user_id = ?", user.ID).
			Delete(&model.UserSession{}).Error; err != nil {
			t.Errorf("failed to delete test sessions: %v", err)
		}

		if err := repo.DB.Delete(&model.User{}, user.ID).Error; err != nil {
			t.Errorf("failed to delete test user: %v", err)
		}
	})

	return repo, user.ID
}

func TestUpdateUserProfile(t *testing.T) {
	t.Run("update profile successfully", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		newPhone := fmt.Sprintf(
			"09%09d",
			time.Now().UnixNano()%1_000_000_000,
		)

		err := repo.UpdateUserProfile(
			userID,
			"Updated Test User",
			newPhone,
		)
		if err != nil {
			t.Fatalf("expected profile update to succeed, got: %v", err)
		}

		user, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to retrieve updated user: %v", err)
		}

		if user.Name != "Updated Test User" {
			t.Errorf("expected updated name, got %q", user.Name)
		}

		if user.Phone != newPhone {
			t.Errorf("expected phone %q, got %q", newPhone, user.Phone)
		}
	})

	t.Run("same profile values", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		user, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to retrieve user: %v", err)
		}

		err = repo.UpdateUserProfile(userID, user.Name, user.Phone)
		if err != nil {
			t.Fatalf("updating with same values should succeed, got: %v", err)
		}
	})

	t.Run("zero user ID", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		err := repo.UpdateUserProfile(0, "Test User", "09123456789")
		if err == nil {
			t.Fatal("expected error for zero user ID")
		}
	})

	t.Run("non-existent user", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		err := repo.UpdateUserProfile(
			999999999,
			"Test User",
			"09123456789",
		)
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("expected gorm.ErrRecordNotFound, got: %v", err)
		}
	})
}

func TestCreateSession(t *testing.T) {
	t.Run("valid session", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		sessionID := fmt.Sprintf("session-%d", time.Now().UnixNano())
		refreshToken := fmt.Sprintf("refresh-%d", time.Now().UnixNano())

		expiresAt := time.Now().Add(24 * time.Hour)

		err := repo.CreateSession(
			userID,
			sessionID,
			refreshToken,
			expiresAt,
		)

		if err != nil {
			t.Fatalf("expected session creation to succeed, got: %v", err)
		}

		var session model.UserSession
		err = repo.DB.Where("session_id = ?", sessionID).
			First(&session).Error

		if err != nil {
			t.Fatalf("failed to retrieve created session: %v", err)
		}

		if session.UserID != userID {
			t.Errorf("expected user ID %d, got %d", userID, session.UserID)
		}

		if session.RefreshTokenHash == refreshToken {
			t.Error("raw refresh token must not be stored")
		}

		if session.RefreshTokenHash != hashRefreshToken(refreshToken) {
			t.Error("stored refresh token hash does not match expected hash")
		}
	})

	t.Run("zero user ID", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		err := repo.CreateSession(
			0,
			"session-test",
			"refresh-test",
			time.Now().Add(time.Hour),
		)

		if err == nil {
			t.Fatal("expected error for zero user ID")
		}
	})

	t.Run("empty session ID", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		err := repo.CreateSession(
			userID,
			"",
			"refresh-test",
			time.Now().Add(time.Hour),
		)

		if err == nil {
			t.Fatal("expected error for empty session ID")
		}
	})

	t.Run("empty refresh token", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		err := repo.CreateSession(
			userID,
			"session-test",
			"",
			time.Now().Add(time.Hour),
		)

		if err == nil {
			t.Fatal("expected error for empty refresh token")
		}
	})

	t.Run("expired session", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		err := repo.CreateSession(
			userID,
			"session-expired",
			"refresh-test",
			time.Now().Add(-time.Hour),
		)

		if err == nil {
			t.Fatal("expected error for expired session")
		}
	})
}

func TestRotateSession(t *testing.T) {
	t.Run("successful rotation", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		sessionID := fmt.Sprintf("session-%d", time.Now().UnixNano())
		oldToken := fmt.Sprintf("old-refresh-%d", time.Now().UnixNano())
		newToken := fmt.Sprintf("new-refresh-%d", time.Now().UnixNano())

		oldExpiry := time.Now().Add(24 * time.Hour)
		newExpiry := time.Now().Add(48 * time.Hour)

		if err := repo.CreateSession(
			userID,
			sessionID,
			oldToken,
			oldExpiry,
		); err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		err := repo.RotateSession(
			userID,
			sessionID,
			oldToken,
			newToken,
			newExpiry,
		)

		if err != nil {
			t.Fatalf("expected rotation to succeed, got: %v", err)
		}

		var session model.UserSession
		if err := repo.DB.Where("session_id = ?", sessionID).
			First(&session).Error; err != nil {
			t.Fatalf("failed to retrieve session: %v", err)
		}

		if session.RefreshTokenHash != hashRefreshToken(newToken) {
			t.Error("refresh token hash was not updated")
		}

		if session.RefreshTokenHash == hashRefreshToken(oldToken) {
			t.Error("old refresh token hash should no longer be stored")
		}

		if !session.ExpiresAt.Equal(newExpiry.UTC().Round(time.Millisecond)) {
			t.Errorf(
				"expected expiration %v, got %v",
				newExpiry.UTC(),
				session.ExpiresAt,
			)
		}

		if session.LastUsedAt == nil {
			t.Error("expected LastUsedAt to be updated")
		}

		if session.RevokedAt != nil {
			t.Error("session should not be revoked after successful rotation")
		}
	})
}

func TestRotateSessionDetectsTokenReuse(t *testing.T) {
	repo, userID := setupRepositoryTest(t)

	sessionID := fmt.Sprintf("reuse-session-%d", time.Now().UnixNano())
	oldToken := fmt.Sprintf("old-token-%d", time.Now().UnixNano())
	newToken := fmt.Sprintf("new-token-%d", time.Now().UnixNano())

	if err := repo.CreateSession(
		userID,
		sessionID,
		oldToken,
		time.Now().Add(24*time.Hour),
	); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// First rotation: old token becomes invalid.
	if err := repo.RotateSession(
		userID,
		sessionID,
		oldToken,
		newToken,
		time.Now().Add(48*time.Hour),
	); err != nil {
		t.Fatalf("first rotation failed: %v", err)
	}

	// Replay the old token.
	err := repo.RotateSession(
		userID,
		sessionID,
		oldToken,
		"another-new-token",
		time.Now().Add(48*time.Hour),
	)

	if !errors.Is(err, ErrRefreshTokenReuse) {
		t.Fatalf(
			"expected ErrRefreshTokenReuse, got: %v",
			err,
		)
	}

	// Verify that the session was revoked in the database.
	var session model.UserSession
	if err := repo.DB.Where("session_id = ?", sessionID).
		First(&session).Error; err != nil {
		t.Fatalf("failed to retrieve session: %v", err)
	}

	if session.RevokedAt == nil {
		t.Fatal("session should be revoked after refresh token reuse")
	}
}

func TestRotateSessionRejectsInvalidSessions(t *testing.T) {

	t.Run("expired session", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		sessionID := fmt.Sprintf("expired-session-%d", time.Now().UnixNano())
		token := "expired-refresh-token"

		if err := repo.CreateSession(
			userID,
			sessionID,
			token,
			time.Now().Add(24*time.Hour),
		); err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		// Simulate an expired session directly in the database.
		expiredAt := time.Now().Add(-time.Hour)

		if err := repo.DB.Model(&model.UserSession{}).
			Where("session_id = ?", sessionID).
			Update("expires_at", expiredAt).Error; err != nil {
			t.Fatalf("failed to expire session: %v", err)
		}

		err := repo.RotateSession(
			userID,
			sessionID,
			token,
			"new-refresh-token",
			time.Now().Add(48*time.Hour),
		)

		if !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("expected ErrSessionExpired, got: %v", err)
		}
	})

	t.Run("revoked session", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		sessionID := fmt.Sprintf("revoked-session-%d", time.Now().UnixNano())
		token := "revoked-refresh-token"

		if err := repo.CreateSession(
			userID,
			sessionID,
			token,
			time.Now().Add(24*time.Hour),
		); err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		now := time.Now()

		if err := repo.DB.Model(&model.UserSession{}).
			Where("session_id = ?", sessionID).
			Update("revoked_at", &now).Error; err != nil {
			t.Fatalf("failed to revoke session: %v", err)
		}

		err := repo.RotateSession(
			userID,
			sessionID,
			token,
			"new-refresh-token",
			time.Now().Add(48*time.Hour),
		)

		if !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("expected ErrSessionRevoked, got: %v", err)
		}
	})
}

func TestRotateSessionInvalidParameters(t *testing.T) {
	repo, userID := setupRepositoryTest(t)

	futureExpiry := time.Now().Add(24 * time.Hour)

	tests := []struct {
		name         string
		userID       uint
		sessionID    string
		oldToken     string
		newToken     string
		newExpiresAt time.Time
	}{
		{
			name:         "zero user ID",
			userID:       0,
			sessionID:    "session-test",
			oldToken:     "old-token",
			newToken:     "new-token",
			newExpiresAt: futureExpiry,
		},
		{
			name:         "empty session ID",
			userID:       userID,
			sessionID:    "",
			oldToken:     "old-token",
			newToken:     "new-token",
			newExpiresAt: futureExpiry,
		},
		{
			name:         "empty old refresh token",
			userID:       userID,
			sessionID:    "session-test",
			oldToken:     "",
			newToken:     "new-token",
			newExpiresAt: futureExpiry,
		},
		{
			name:         "empty new refresh token",
			userID:       userID,
			sessionID:    "session-test",
			oldToken:     "old-token",
			newToken:     "",
			newExpiresAt: futureExpiry,
		},
		{
			name:         "expired new expiration",
			userID:       userID,
			sessionID:    "session-test",
			oldToken:     "old-token",
			newToken:     "new-token",
			newExpiresAt: time.Now().Add(-time.Hour),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.RotateSession(
				tt.userID,
				tt.sessionID,
				tt.oldToken,
				tt.newToken,
				tt.newExpiresAt,
			)

			if err == nil {
				t.Fatal("expected an error for invalid parameters")
			}
		})
	}
}

func TestRotateSessionNotFound(t *testing.T) {
	repo, userID := setupRepositoryTest(t)

	err := repo.RotateSession(
		userID,
		fmt.Sprintf("missing-session-%d", time.Now().UnixNano()),
		"old-token",
		"new-token",
		time.Now().Add(24*time.Hour),
	)

	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got: %v", err)
	}
}

func TestSavePasswordResetToken(t *testing.T) {
	t.Run("save reset token successfully", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		hashedToken := "hashed-reset-token"
		expiresAt := time.Now().Add(time.Hour).UTC().Round(time.Millisecond)

		err := repo.SavePasswordResetToken(
			userID,
			hashedToken,
			expiresAt,
		)
		if err != nil {
			t.Fatalf("expected saving reset token to succeed, got: %v", err)
		}

		user, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to retrieve user: %v", err)
		}

		if user.ResetToken == nil {
			t.Fatal("expected reset token to be saved, got nil")
		}

		if *user.ResetToken != hashedToken {
			t.Errorf(
				"expected reset token %q, got %q",
				hashedToken,
				*user.ResetToken,
			)
		}

		if !user.ResetTokenExpiry.Equal(expiresAt) {
			t.Errorf(
				"expected expiry %v, got %v",
				expiresAt,
				user.ResetTokenExpiry,
			)
		}
	})

	t.Run("zero user ID", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		err := repo.SavePasswordResetToken(
			0,
			"hashed-reset-token",
			time.Now().Add(time.Hour),
		)

		if err == nil {
			t.Fatal("expected error for zero user ID")
		}
	})

	t.Run("empty hashed token", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		err := repo.SavePasswordResetToken(
			userID,
			"",
			time.Now().Add(time.Hour),
		)

		if err == nil {
			t.Fatal("expected error for empty hashed token")
		}
	})

	t.Run("non-existent user", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		err := repo.SavePasswordResetToken(
			999999999,
			"hashed-reset-token",
			time.Now().Add(time.Hour),
		)

		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf(
				"expected gorm.ErrRecordNotFound, got: %v",
				err,
			)
		}
	})
}
func TestCreateUser(t *testing.T) {
	t.Run("create user successfully", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		user := model.User{
			Name:     "New Repository User",
			Email:    fmt.Sprintf("new-user-%d@example.com", time.Now().UnixNano()),
			Phone:    fmt.Sprintf("09%09d", time.Now().UnixNano()%1_000_000_000),
			Password: "test-password-hash",
		}

		err := repo.CreateUser(&user)
		if err != nil {
			t.Fatalf("expected user creation to succeed, got: %v", err)
		}

		if user.ID == 0 {
			t.Fatal("expected created user to have a non-zero ID")
		}
	})

	t.Run("duplicate email", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		existingUser, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to retrieve existing user: %v", err)
		}

		user := model.User{
			Name:     "Duplicate Email User",
			Email:    existingUser.Email,
			Phone:    fmt.Sprintf("09%09d", time.Now().UnixNano()%1_000_000_000),
			Password: "test-password-hash",
		}

		err = repo.CreateUser(&user)
		if !errors.Is(err, ErrEmailAlreadyExists) {
			t.Fatalf("expected ErrEmailAlreadyExists, got: %v", err)
		}
	})

	t.Run("duplicate phone", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		existingUser, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to retrieve existing user: %v", err)
		}

		user := model.User{
			Name:     "Duplicate Phone User",
			Email:    fmt.Sprintf("duplicate-phone-%d@example.com", time.Now().UnixNano()),
			Phone:    existingUser.Phone,
			Password: "test-password-hash",
		}

		err = repo.CreateUser(&user)
		if !errors.Is(err, ErrPhoneAlreadyExists) {
			t.Fatalf("expected ErrPhoneAlreadyExists, got: %v", err)
		}
	})
}
func TestGetUserByEmail(t *testing.T) {
	t.Run("find user by email", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		expectedUser, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to retrieve test user: %v", err)
		}

		user, err := repo.GetUserByEmail(expectedUser.Email)
		if err != nil {
			t.Fatalf("expected user lookup to succeed, got: %v", err)
		}

		if user.ID != userID {
			t.Errorf("expected user ID %d, got %d", userID, user.ID)
		}

		if user.Email != expectedUser.Email {
			t.Errorf("expected email %q, got %q", expectedUser.Email, user.Email)
		}
	})

	t.Run("email not found", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		_, err := repo.GetUserByEmail(
			fmt.Sprintf("missing-%d@example.com", time.Now().UnixNano()),
		)

		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("expected gorm.ErrRecordNotFound, got: %v", err)
		}
	})
}
func TestGetUserByID(t *testing.T) {
	t.Run("find user by ID", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		user, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("expected user lookup to succeed, got: %v", err)
		}

		if user == nil {
			t.Fatal("expected user, got nil")
		}

		if user.ID != userID {
			t.Errorf("expected user ID %d, got %d", userID, user.ID)
		}
	})

	t.Run("user ID not found", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		nonExistentID := uint(999999999)

		_, err := repo.GetUserByID(nonExistentID)
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("expected gorm.ErrRecordNotFound, got: %v", err)
		}
	})
}

func TestUpdatePassword(t *testing.T) {
	t.Run("update password successfully, increment token version, and clear reset token", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		resetTokenHash := "hashed-reset-token-before-password-change"
		resetExpiry := time.Now().Add(time.Hour)

		if err := repo.SavePasswordResetToken(
			userID,
			resetTokenHash,
			resetExpiry,
		); err != nil {
			t.Fatalf("failed to save reset token: %v", err)
		}

		userBefore, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to get user before update: %v", err)
		}

		if userBefore.ResetToken == nil || userBefore.ResetTokenExpiry == nil {
			t.Fatal("expected reset token and expiry to be saved before password change")
		}

		newHashedPassword := "new-test-password-hash"

		err = repo.UpdatePassword(userID, newHashedPassword)
		if err != nil {
			t.Fatalf("expected password update to succeed, got: %v", err)
		}

		userAfter, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to get user after update: %v", err)
		}

		if userAfter.Password != newHashedPassword {
			t.Errorf("expected password %q, got %q", newHashedPassword, userAfter.Password)
		}

		if userAfter.TokenVersion != userBefore.TokenVersion+1 {
			t.Errorf(
				"expected token version %d, got %d",
				userBefore.TokenVersion+1,
				userAfter.TokenVersion,
			)
		}

		if userAfter.ResetToken != nil {
			t.Errorf("expected reset token to be nil, got %q", *userAfter.ResetToken)
		}

		if userAfter.ResetTokenExpiry != nil {
			t.Errorf("expected reset token expiry to be nil, got %v", *userAfter.ResetTokenExpiry)
		}

		// The previously issued reset token must no longer be usable.
		err = repo.CompletePasswordReset(
			userID,
			"another-password-hash",
			resetTokenHash,
			time.Now(),
		)
		if !errors.Is(err, ErrInvalidOrExpiredResetToken) {
			t.Errorf("expected ErrInvalidOrExpiredResetToken after password change, got: %v", err)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		err := repo.UpdatePassword(999999999, "new-test-password-hash")
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("expected gorm.ErrRecordNotFound, got: %v", err)
		}
	})
}

func TestCompletePasswordReset(t *testing.T) {
	t.Run("complete password reset successfully", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		resetTokenHash := "hashed-reset-token"
		now := time.Now()
		resetExpiry := now.Add(time.Hour)

		if err := repo.SavePasswordResetToken(
			userID,
			resetTokenHash,
			resetExpiry,
		); err != nil {
			t.Fatalf("failed to save reset token: %v", err)
		}

		userBefore, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to get user before reset: %v", err)
		}

		newHashedPassword := "new-reset-password-hash"

		err = repo.CompletePasswordReset(
			userID,
			newHashedPassword,
			resetTokenHash,
			now,
		)
		if err != nil {
			t.Fatalf("expected password reset to succeed, got: %v", err)
		}

		userAfter, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to get user after reset: %v", err)
		}

		if userAfter.Password != newHashedPassword {
			t.Errorf("expected password %q, got %q",
				newHashedPassword, userAfter.Password)
		}

		if userAfter.ResetToken != nil {
			t.Errorf("expected reset token to be nil, got %q",
				*userAfter.ResetToken)
		}

		if userAfter.ResetTokenExpiry != nil {
			t.Errorf("expected reset token expiry to be nil, got %v",
				*userAfter.ResetTokenExpiry)
		}

		if userAfter.TokenVersion != userBefore.TokenVersion+1 {
			t.Errorf("expected token version %d, got %d",
				userBefore.TokenVersion+1, userAfter.TokenVersion)
		}

		// The same reset token must not be reusable.
		err = repo.CompletePasswordReset(
			userID,
			"another-password-hash",
			resetTokenHash,
			now,
		)
		if !errors.Is(err, ErrInvalidOrExpiredResetToken) {
			t.Errorf("expected ErrInvalidOrExpiredResetToken on reuse, got: %v", err)
		}
	})

	t.Run("reject expired reset token", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		resetTokenHash := "expired-reset-token"
		now := time.Now()
		expiredAt := now.Add(-time.Minute)

		if err := repo.SavePasswordResetToken(
			userID,
			resetTokenHash,
			expiredAt,
		); err != nil {
			t.Fatalf("failed to save expired reset token: %v", err)
		}

		err := repo.CompletePasswordReset(
			userID,
			"new-password-hash",
			resetTokenHash,
			now,
		)

		if !errors.Is(err, ErrInvalidOrExpiredResetToken) {
			t.Errorf("expected ErrInvalidOrExpiredResetToken, got: %v", err)
		}
	})

	t.Run("reject user not found", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		err := repo.CompletePasswordReset(
			999999999,
			"new-reset-password-hash",
			"some-reset-token-hash",
			time.Now(),
		)

		if !errors.Is(err, ErrInvalidOrExpiredResetToken) {
			t.Errorf("expected ErrInvalidOrExpiredResetToken, got: %v", err)
		}
	})
}

func TestPromoteUserToAdmin(t *testing.T) {
	t.Run("promote user successfully and increment token version", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		userBefore, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to get user before promotion: %v", err)
		}

		if userBefore.Role != "user" {
			t.Fatalf("expected initial role user, got %q", userBefore.Role)
		}

		err = repo.PromoteUserToAdmin(userID)
		if err != nil {
			t.Fatalf("expected promotion to succeed, got: %v", err)
		}

		userAfter, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to get user after promotion: %v", err)
		}

		if userAfter.Role != "admin" {
			t.Errorf("expected role admin, got %q", userAfter.Role)
		}

		if userAfter.TokenVersion != userBefore.TokenVersion+1 {
			t.Errorf("expected token version %d, got %d",
				userBefore.TokenVersion+1, userAfter.TokenVersion)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		err := repo.PromoteUserToAdmin(999999999)
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("expected gorm.ErrRecordNotFound, got: %v", err)
		}
	})
}
func TestGetTokenVersion(t *testing.T) {
	t.Run("get token version successfully", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		user, err := repo.GetUserByID(userID)
		if err != nil {
			t.Fatalf("failed to get test user: %v", err)
		}

		version, err := repo.GetTokenVersion(userID)
		if err != nil {
			t.Fatalf("expected token version lookup to succeed, got: %v", err)
		}

		if version != user.TokenVersion {
			t.Errorf("expected token version %d, got %d",
				user.TokenVersion, version)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		_, err := repo.GetTokenVersion(999999999)
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("expected gorm.ErrRecordNotFound, got: %v", err)
		}
	})
}
func TestDeleteUser(t *testing.T) {
	t.Run("delete user successfully", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		sessionID := fmt.Sprintf("delete-session-%d", time.Now().UnixNano())

		err := repo.CreateSession(
			userID,
			sessionID,
			"test-refresh-token",
			time.Now().Add(24*time.Hour),
		)
		if err != nil {
			t.Fatalf("failed to create test session: %v", err)
		}

		err = repo.DeleteUser(userID)
		if err != nil {
			t.Fatalf("expected user deletion to succeed, got: %v", err)
		}

		_, err = repo.GetUserByID(userID)
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("expected user to be deleted, got error: %v", err)
		}

		var session model.UserSession
		err = repo.DB.Where("session_id = ?", sessionID).
			First(&session).Error

		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("expected session to be deleted, got error: %v", err)
		}
	})

	t.Run("zero user ID", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		err := repo.DeleteUser(0)
		if err == nil || err.Error() != "user ID is required" {
			t.Errorf("expected user ID is required error, got: %v", err)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		repo, _ := setupRepositoryTest(t)

		err := repo.DeleteUser(999999999)
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("expected gorm.ErrRecordNotFound, got: %v", err)
		}
	})
}

func TestIsSessionActive(t *testing.T) {
	t.Run("active session", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		sessionID := fmt.Sprintf("active-session-%d", time.Now().UnixNano())
		refreshToken := fmt.Sprintf("refresh-%d", time.Now().UnixNano())

		err := repo.CreateSession(
			userID,
			sessionID,
			refreshToken,
			time.Now().Add(time.Hour),
		)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		active, err := repo.IsSessionActive(userID, sessionID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !active {
			t.Fatal("expected session to be active")
		}
	})

	t.Run("revoked session", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		sessionID := fmt.Sprintf("revoked-session-%d", time.Now().UnixNano())

		err := repo.CreateSession(
			userID,
			sessionID,
			fmt.Sprintf("refresh-%d", time.Now().UnixNano()),
			time.Now().Add(time.Hour),
		)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		if err := repo.DB.Model(&model.UserSession{}).
			Where("session_id = ?", sessionID).
			Update("revoked_at", time.Now()).Error; err != nil {
			t.Fatalf("failed to revoke session: %v", err)
		}

		active, err := repo.IsSessionActive(userID, sessionID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if active {
			t.Fatal("expected revoked session to be inactive")
		}
	})

	t.Run("expired session", func(t *testing.T) {
		repo, userID := setupRepositoryTest(t)

		sessionID := fmt.Sprintf("expired-session-%d", time.Now().UnixNano())

		err := repo.CreateSession(
			userID,
			sessionID,
			fmt.Sprintf("refresh-%d", time.Now().UnixNano()),
			time.Now().Add(time.Hour),
		)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		if err := repo.DB.Model(&model.UserSession{}).
			Where("session_id = ?", sessionID).
			Update("expires_at", time.Now().Add(-time.Hour)).Error; err != nil {
			t.Fatalf("failed to expire session: %v", err)
		}

		active, err := repo.IsSessionActive(userID, sessionID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if active {
			t.Fatal("expected expired session to be inactive")
		}
	})
}
