package request

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type PromoteUserRequest struct {
	UserID uint `json:"user_id" example:"123"`
}
