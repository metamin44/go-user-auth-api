package model

import "time"

type User struct {
	ID               uint       `json:"id" gorm:"primaryKey"`
	Name             string     `json:"name"`
	Email            string     `json:"email" gorm:"unique"`
	Phone            string     `json:"phone" gorm:"unique"`
	Password         string     `json:"password"`
	Role             string     `gorm:"default:'user'"`
	ResetToken       *string    `gorm:"reset_token,omitempty"`
	ResetTokenExpiry *time.Time `gorm:"reset_token_expiry,omitempty"`
	CreatedAT        time.Time  `gorm:"autoCreatetime"`
	UpdatedAt        time.Time  `gorm:"autoUpdatetime"`
}

type UserResponse struct {
	ID    uint   `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type RegisterRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Phone    string `json:"phone" validate:"required,e164"` // or custom validation
	Password string `json:"password" validate:"required,min=8"`
}

// RegisterPayload represents the Swagger schema for registration
type RegisterPayload struct {
	Name     string `json:"name" example:"John Doe"`
	Email    string `json:"email" example:"john@example.com"`
	Phone    string `json:"phone" example:"09123456789"`
	Password string `json:"password" example:"Secret123!"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// APIResponse is a generic API response wrapper
type APIResponse struct {
	Code    int         `json:"code"`           // e.g. 200, 400, 401
	Message string      `json:"message"`        // human-readable message
	Data    interface{} `json:"data,omitempty"` // optional payload for success
}

// RegisterRequest/Response (if you want to be explicit)
type RegisterResponse struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	// Add more fields you want to return after register
}

type LoginResponse struct {
	Token string `json:"token"`
	// Add more fields if needed
}

type ProfileResponse struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	// Add more profile fields
}

type UpdateUserRequest struct {
	Name  string `json:"name" example:"John Doe"`
	Phone string `json:"phone" example:"09123456789"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" example:"Secret123!"`
	NewPassword string `json:"new_password" example:"Secret123!"`
}
