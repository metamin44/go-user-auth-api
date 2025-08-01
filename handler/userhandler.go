package handler

import (
	"errors"
	"fmt"
	"net/http"
	"reg/config"
	middle "reg/middleware"
	"reg/model"
	"reg/model/request"
	"reg/repository"
	"reg/tokenutil"
	"reg/validationuser"
	"strings"

	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserHandler struct {
	Repo   *repository.UserRepo
	Cfg    *config.Config
	Logger *zap.Logger
}

func NewUserHandler(repo *repository.UserRepo, cfg *config.Config, logger *zap.Logger) *UserHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &UserHandler{Repo: repo, Cfg: cfg, Logger: logger}
}

// Register godoc
// @Summary Register a new user
// @Description Create a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param user body model.RegisterPayload true "User Registration Data"
// @Success 200 {object} model.APIResponse{data=model.RegisterResponse} "Success"
// @Failure 400 {object} model.APIResponse "Bad Request - validation errors"
// @Failure 500 {object} model.APIResponse "Internal Server Error"
// @Router /register [post]
func (h *UserHandler) Register(c echo.Context) error {
	user := new(model.User)
	if err := c.Bind(user); err != nil {
		h.Logger.Error("Failed to bind user input", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid input"})
	}

	// Validations
	if err := validationuser.ValidateName(user.Name); err != nil {
		h.Logger.Warn("Invalid name", zap.String("name", user.Name), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Name: " + err.Error()})
	}
	if err := validationuser.ValidateEmail(user.Email); err != nil {
		h.Logger.Warn("Invalid email", zap.String("email", user.Email), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Email: " + err.Error()})
	}
	if err := validationuser.ValidatePhone(user.Phone); err != nil {
		h.Logger.Warn("Invalid phone", zap.String("phone", user.Phone), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Phone: " + err.Error()})
	}
	if err := validationuser.ValidatePassword(user.Password); err != nil {
		h.Logger.Warn("Invalid password", zap.String("password", user.Password), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Password: " + err.Error()})
	}

	if user.Role == "" {
		user.Role = "user"
		h.Logger.Debug("Default role assigned", zap.String("role", user.Role))
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		h.Logger.Error("Failed to hash password", zap.Error(err), zap.String("email", user.Email))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "could not hash password"})
	}
	user.Password = string(hashedPassword)

	if err := h.Repo.CreateUser(user); err != nil {
		h.Logger.Error("Failed to create user", zap.Error(err), zap.String("email", user.Email))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	h.Logger.Info("user registered successfully", zap.String("email", user.Email))
	return c.JSON(http.StatusCreated, echo.Map{"message": "user registered successfully"})
}

// Login godoc
// @Summary User login
// @Description Authenticate user and get JWT token
// @Tags auth
// @Accept json
// @Produce json
// @Param input body model.LoginRequest true "Login payload"
// @Success 200 {object} model.APIResponse{data=model.LoginResponse} "Success"
// @Failure 400 {object} model.APIResponse "Bad Request - invalid input"
// @Failure 401 {object} model.APIResponse "Unauthorized - invalid credentials"
// @Router /login [post]
func (h *UserHandler) Login(c echo.Context) error {
	req := new(model.User)
	if err := c.Bind(req); err != nil {
		h.Logger.Error("Failed to bind login input", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid input"})
	}

	if err := validationuser.ValidateEmail(req.Email); err != nil {
		h.Logger.Warn("Invalid email", zap.String("email", req.Email), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}
	if err := validationuser.ValidatePassword(req.Password); err != nil {
		h.Logger.Warn("Invalid password", zap.String("password", req.Password), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	user, err := h.Repo.GetUserByEmail(req.Email)
	if err != nil {
		h.Logger.Warn("User not found during login", zap.String("email", req.Email), zap.Error(err))
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "email or password incorrect"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		h.Logger.Warn("Invalid password attempt", zap.String("email", req.Email), zap.Error(err))
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "email or password incorrect"})
	}

	accessToken, refreshToken, err := middle.GenerateTokens(user.ID, user.Role, h.Cfg)
	if err != nil {
		h.Logger.Error("Failed to generate tokens", zap.String("email", req.Email), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "could not generate tokens"})
	}

	h.Logger.Info("user logged in successfully", zap.String("email", req.Email), zap.Time("time", time.Now()))
	return c.JSON(http.StatusOK, echo.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// Profile godoc
// @Summary Get user profile
// @Description Get authenticated user profile info
// @Tags user
// @Security BearerAuth
// @Accept json
// @Produce json
// @Success 200 {object} model.APIResponse{data=model.ProfileResponse} "Success"
// @Failure 401 {object} model.APIResponse "Unauthorized - invalid or missing token"
// @Router /auth/profile [get]
func (h *UserHandler) Profile(c echo.Context) error {
	uid, ok := c.Get("user_id").(uint)
	if !ok {
		h.Logger.Warn("Unauthorized access to profile: missing user_id in context")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "unauthorized"})
	}

	user, err := h.Repo.GetUserByID(uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.Logger.Warn("User not found", zap.Uint("user_id", uid))
			return c.JSON(http.StatusNotFound, echo.Map{"error": "user not found"})
		}
		h.Logger.Error("Failed to fetch user from DB", zap.Uint("user_id", uid), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "could not fetch user"})
	}

	h.Logger.Info("Profile fetched", zap.Uint("user_id", user.ID), zap.String("email", user.Email))

	res := model.UserResponse{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
		Phone: user.Phone,
	}

	return c.JSON(http.StatusOK, res)
}

// RefreshToken godoc
// @Summary Refresh JWT access token
// @Description Generate a new access token using a valid refresh token
// @Tags Auth
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param refresh_token formData string true "Refresh Token"
// @Success 200 {object} map[string]string "access_token"
// @Failure 400 {object} map[string]string "invalid request"
// @Failure 401 {object} map[string]string "invalid refresh token"
// @Failure 500 {object} map[string]string "could not create new token"
// @Router /refresh [post]

func (h *UserHandler) RefreshToken(c echo.Context) error {
	refreshToken := c.FormValue("refresh_token")
	if refreshToken == "" {
		h.Logger.Warn("Missing refresh token in request")
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "missing refresh token"})
	}

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(h.Cfg.JWT.RefreshKey), nil
	})

	if err != nil || !token.Valid {
		h.Logger.Warn("Invalid refresh token", zap.Error(err))
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid refresh token"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		h.Logger.Error("Failed to extract claims from token")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid token claims"})
	}

	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		h.Logger.Error("Invalid user ID in refresh token")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid user ID in token"})
	}
	userID := uint(userIDFloat)

	role, ok := claims["role"].(string)
	if !ok {
		h.Logger.Error("Invalid role in refresh token", zap.Uint("user_id", userID))
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid role in token"})
	}

	accessToken, err := tokenutil.GenerateAccessToken(userID, role, h.Cfg.JWT.SignKey)
	if err != nil {
		h.Logger.Error("Failed to generate access token", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "failed to generate access token"})
	}

	newRefreshToken, err := tokenutil.GenerateRefreshToken(userID, role, h.Cfg.JWT.RefreshKey)
	if err != nil {
		h.Logger.Error("Failed to generate refresh token", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "failed to generate refresh token"})
	}

	h.Logger.Info("Tokens refreshed successfully", zap.Uint("user_id", userID), zap.String("role", role))

	return c.JSON(http.StatusOK, echo.Map{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}

// UpdateUser godoc
// @Summary Update user profile
// @Description Allows an authenticated user to update their name and phone
// @Tags User
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param update body model.UpdateUserRequest true "Update Payload"
// @Success 200 {object} map[string]string "user updated"
// @Failure 400 {object} map[string]string "validation or bad request"
// @Failure 500 {object} map[string]string "internal error"
// @Router /auth/update [put]
func (h *UserHandler) UpdateUser(c echo.Context) error {
	userID, ok := c.Get("user_id").(uint)
	if !ok {
		h.Logger.Warn("Unauthorized access: user_id missing or invalid in context")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "unauthorized"})
	}

	var req model.UpdateUserRequest
	if err := c.Bind(&req); err != nil {
		h.Logger.Warn("Failed to bind update user request", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request"})
	}

	if err := validationuser.ValidateUpdateUser(&req); err != nil {
		h.Logger.Warn("Validation failed for update user", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	updates := map[string]interface{}{
		"name":  req.Name,
		"phone": req.Phone,
	}

	if err := h.Repo.UpdateUser(userID, updates); err != nil {
		h.Logger.Error("Failed to update user in database", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "failed to update user"})
	}

	h.Logger.Info("User updated successfully", zap.Uint("user_id", userID), zap.String("name", req.Name), zap.String("phone", req.Phone))
	return c.JSON(http.StatusOK, echo.Map{"message": "user updated"})
}

// DeleteUser godoc
// @Summary Delete user account
// @Description Deletes the authenticated user’s account permanently
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string "user deleted"
// @Failure 500 {object} map[string]string "internal error"
// @Router /auth/delete [delete]
func (h *UserHandler) DeleteUser(c echo.Context) error {
	userID, ok := c.Get("user_id").(uint)
	if !ok {
		h.Logger.Warn("Unauthorized delete attempt: missing user_id in context")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "unauthorized"})
	}

	// Optional: first check if user exists
	_, err := h.Repo.GetUserByID(userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.Logger.Warn("Attempted to delete non-existent user", zap.Uint("user_id", userID))
			return c.JSON(http.StatusNotFound, echo.Map{"error": "user not found"})
		}
		h.Logger.Error("Failed to check user existence", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "failed to check user existence"})
	}

	if err := h.Repo.DeleteUser(userID); err != nil {
		h.Logger.Error("Failed to delete user", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "failed to delete user"})
	}

	h.Logger.Info("User deleted successfully", zap.Uint("user_id", userID))
	return c.JSON(http.StatusOK, echo.Map{"message": "user deleted"})
}

// ChangePassword godoc
// @Summary Change user password
// @Description Authenticated user can change their password by providing the old and new password
// @Tags User
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param change body model.ChangePasswordRequest true "Change Password Payload"
// @Success 200 {object} map[string]string "password updated"
// @Failure 400 {object} map[string]string "validation or bad request"
// @Failure 401 {object} map[string]string "unauthorized – wrong password"
// @Failure 500 {object} map[string]string "internal error"
// @Router /auth/change-password [post]
func (h *UserHandler) ChangePassword(c echo.Context) error {
	userID, ok := c.Get("user_id").(uint)
	if !ok {
		h.Logger.Warn("Unauthorized password change attempt: missing user_id in context")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "unauthorized"})
	}

	var req model.ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		h.Logger.Warn("Failed to bind ChangePassword request", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request"})
	}

	if err := validationuser.ValidateChangePassword(&req); err != nil {
		h.Logger.Warn("Validation failed for ChangePassword", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	user, err := h.Repo.GetUserByID(userID)
	if err != nil {
		h.Logger.Error("Failed to fetch user for password change", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "user not found"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword)); err != nil {
		h.Logger.Warn("Incorrect old password attempt", zap.Uint("user_id", userID))
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "old password is incorrect"})
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		h.Logger.Error("Failed to hash new password", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "failed to hash password"})
	}

	if err := h.Repo.UpdatePassword(userID, string(hashed)); err != nil {
		h.Logger.Error("Failed to update password in DB", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "failed to update password"})
	}

	h.Logger.Info("Password updated successfully", zap.Uint("user_id", userID))
	return c.JSON(http.StatusOK, echo.Map{"message": "password updated"})
}

// ForgotPassword godoc
// @Summary Request password reset
// @Description Generate a password reset token and print reset link to the console
// @Tags auth
// @Accept json
// @Produce json
// @Param request body request.ForgotPasswordRequest true "User email"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /forgot-password [post]
func (h *UserHandler) ForgotPassword(c echo.Context) error {
	var req request.ForgotPasswordRequest
	if err := c.Bind(&req); err != nil {
		h.Logger.Warn("Invalid ForgotPassword request", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request"})
	}

	// Look up user by email
	user, err := h.Repo.GetUserByEmail(req.Email)
	if err != nil {
		h.Logger.Warn("User not found during ForgotPassword", zap.String("email", req.Email), zap.Error(err))
		return c.JSON(http.StatusNotFound, echo.Map{"error": "User not found"})
	}

	// Generate reset JWT token
	claims := jwt.MapClaims{
		"sub":  user.Email,
		"role": user.Role,
		"exp":  time.Now().Add(15 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(h.Cfg.JWT.ResetKey))
	if err != nil {
		h.Logger.Error("Failed to sign reset token", zap.String("email", user.Email), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to generate token"})
	}

	updateFields := map[string]interface{}{
		"reset_token":        signedToken,
		"reset_token_expiry": time.Now().Add(15 * time.Minute),
	}

	if err := h.Repo.UpdateUser(user.ID, updateFields); err != nil {
		h.Logger.Error("Failed to update user with reset token", zap.Uint("user_id", user.ID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to save reset token"})
	}

	resetLink := fmt.Sprintf("http://localhost:8085/reset-password?token=%s", signedToken)

	if h.Cfg.Email.EnableLogs {
		h.Logger.Debug("Password reset link (logged)", zap.String("email", user.Email), zap.String("reset_link", resetLink))
	}

	if h.Cfg.Email.EnableEmail {
		if err := tokenutil.SendResetEmail(h.Cfg, user.Email, signedToken); err != nil {
			h.Logger.Error("Failed to send reset email", zap.String("email", user.Email), zap.Error(err))
			return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to send reset email"})
		}
	}

	h.Logger.Info("Password reset link sent", zap.String("email", user.Email))
	return c.JSON(http.StatusOK, echo.Map{"message": "Password reset link sent to your email"})
}

// ResetPassword godoc
// @Summary Reset user password
// @Description Reset password using a valid token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body request.ResetPasswordRequest true "Reset password payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /reset-password [post]
func (h *UserHandler) ResetPassword(c echo.Context) error {
	var req request.ResetPasswordRequest
	if err := c.Bind(&req); err != nil {
		h.Logger.Warn("Invalid ResetPassword request", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request"})
	}

	// Parse JWT token
	token, err := jwt.Parse(req.Token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(h.Cfg.JWT.ResetKey), nil
	})
	if err != nil || !token.Valid {
		h.Logger.Warn("Invalid or expired reset token", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid or expired token"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["sub"] == nil {
		h.Logger.Warn("Token payload missing subject")
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid token payload"})
	}

	email, ok := claims["sub"].(string)
	if !ok {
		h.Logger.Warn("Token subject is not a string", zap.Any("sub", claims["sub"]))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid token subject"})
	}

	// Find the user
	user, err := h.Repo.GetUserByEmail(email)
	if err != nil {
		h.Logger.Warn("User not found during password reset", zap.String("email", email), zap.Error(err))
		return c.JSON(http.StatusNotFound, echo.Map{"error": "User not found"})
	}

	// Validate token match and expiry
	if user.ResetToken == nil || *user.ResetToken != req.Token || time.Now().After(*user.ResetTokenExpiry) {
		h.Logger.Warn("Token mismatch or expired", zap.String("email", email))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Token is invalid or expired"})
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		h.Logger.Error("Failed to hash new password", zap.String("email", email), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to hash password"})
	}

	// Update password and clear reset token
	updates := map[string]interface{}{
		"password":           string(hashedPassword),
		"reset_token":        nil,
		"reset_token_expiry": nil,
	}

	if err := h.Repo.UpdateUser(user.ID, updates); err != nil {
		h.Logger.Error("Failed to update password in DB", zap.Uint("user_id", user.ID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to update password"})
	}

	h.Logger.Info("Password reset successful", zap.String("email", email))
	return c.JSON(http.StatusOK, echo.Map{"message": "Password successfully reset"})
}

// AdminDashboard godoc
// @Summary Admin dashboard
// @Description Access protected admin dashboard
// @Tags Admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string "welcome to the admin dashboard"
// @Failure 401 {object} map[string]string "unauthorized"
// @Failure 403 {object} map[string]string "access denied"
// @Router /admin/dashboard [get]
func (h *UserHandler) AdminDashboard(c echo.Context) error {
	user := c.Get("user")
	if user == nil {
		h.Logger.Warn("Unauthorized access attempt to AdminDashboard: missing user in context")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Unauthorized"})
	}

	token, ok := user.(*jwt.Token)
	if !ok {
		h.Logger.Warn("Unauthorized access attempt to AdminDashboard: invalid token type")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Unauthorized"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		h.Logger.Warn("Unauthorized access attempt to AdminDashboard: invalid claims")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Unauthorized"})
	}

	role, ok := claims["role"].(string)
	email, _ := claims["sub"].(string) // optional, for audit logging

	if !ok || role != "admin" {
		h.Logger.Warn("Forbidden access to AdminDashboard",
			zap.String("email", email),
			zap.String("role", role),
		)
		return c.JSON(http.StatusForbidden, echo.Map{"error": "Forbidden - Admins only"})
	}

	h.Logger.Info("Admin accessed dashboard", zap.String("email", email))
	return c.JSON(http.StatusOK, echo.Map{"message": "Welcome Admin!"})
}

// PromoteUser godoc
// @Summary Promote a user to admin
// @Description Admins can promote a user to admin role
// @Tags Admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body request.PromoteUserRequest true "User ID payload"
// @Success 200 {object} map[string]string "user promoted to admin successfully"
// @Failure 400 {object} map[string]string "invalid request"
// @Failure 403 {object} map[string]string "access denied"
// @Failure 500 {object} map[string]string "internal server error"
// @Router /admin/promote [put]
func (h *UserHandler) PromoteToAdmin(c echo.Context) error {
	type requestBody struct {
		UserID uint `json:"user_id"`
	}

	var req requestBody
	if err := c.Bind(&req); err != nil || req.UserID == 0 {
		h.Logger.Warn("Invalid promote-to-admin request", zap.Uint("user_id", req.UserID), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request"})
	}

	// Step 1: Check if user exists
	user, err := h.Repo.GetUserByID(req.UserID)
	if err != nil {
		h.Logger.Warn("Attempted to promote non-existent user", zap.Uint("user_id", req.UserID), zap.Error(err))
		return c.JSON(http.StatusNotFound, echo.Map{"error": "user not found"})
	}

	// Step 2: Promote user
	if err := h.Repo.PromoteUserToAdmin(req.UserID); err != nil {
		h.Logger.Error("Failed to promote user to admin", zap.Uint("user_id", req.UserID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "failed to promote user"})
	}

	h.Logger.Info("User promoted to admin successfully",
		zap.Uint("user_id", user.ID),
		zap.String("email", user.Email),
	)

	return c.JSON(http.StatusOK, echo.Map{"message": "user promoted to admin successfully"})
}

func (h *UserHandler) ShowResetPasswordPage(c echo.Context) error {
	token := c.QueryParam("token")
	h.Logger.Debug("Raw query param", zap.String("token", token))
	if token == "" {
		h.Logger.Warn("Missing token in reset-password link")
		return c.String(http.StatusBadRequest, "Missing token")
	}
	token = strings.ReplaceAll(token, " ", "+")

	h.Logger.Info("Received token for verification", zap.String("token", token))

	// Optional: Parse and validate token immediately
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(h.Cfg.JWT.ResetKey), nil
	})
	if err != nil || !parsedToken.Valid {
		h.Logger.Warn("Invalid or expired reset token", zap.Error(err))
		return c.String(http.StatusBadRequest, "Invalid or expired token")
	}

	h.Logger.Info("Reset password page requested", zap.String("token", token))

	return c.String(http.StatusOK, "Valid reset link. Token: "+token)
}
