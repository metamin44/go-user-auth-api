package model

import "time"

type UserSession struct {
	ID               uint       `json:"id" gorm:"primaryKey"`
	SessionID        string     `json:"-" gorm:"type:varchar(64);not null;uniqueIndex"`
	UserID           uint       `json:"user_id" gorm:"not null;index"`
	RefreshTokenHash string     `json:"-" gorm:"type:varchar(64);not null;uniqueIndex"`
	ExpiresAt        time.Time  `json:"expires_at" gorm:"not null;index"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt        time.Time  `json:"updated_at" gorm:"autoUpdateTime"`
}
