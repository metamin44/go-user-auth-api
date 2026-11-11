package handler

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"reg/config"
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

//go:embed templates/reset_password.html
var resetPasswordTemplate embed.FS

var resetPasswordPage = template.Must(
	template.ParseFS(resetPasswordTemplate, "templates/reset_password.html"),
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

func hashResetToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func passwordResetResponse(c echo.Context) error {
	return c.JSON(http.StatusOK, echo.Map{
		"message": "If the email exists, a password reset link will be sent.",
	})
}

// Register godoc
// @Summary Register a new user
// @Description Create a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param user body model.RegisterPayload true "User Registration Data"
// @Success 201 {object} model.APIResponse{data=model.UserResponse} "Success"
// @Failure 400 {object} model.APIResponse "Bad Request"
// @Failure 500 {object} model.APIResponse "Internal Server Error"
// @Router /register [post]
func (h *UserHandler) Register(c echo.Context) error {
	// 1. Bind request to DTO
	req := new(model.RegisterRequest)

	if err := c.Bind(req); err != nil {
		h.Logger.Warn("Failed to bind registration input", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "invalid input",
		})
	}

	// 2. Normalize input
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Phone = strings.TrimSpace(req.Phone)

	// 3. Validate input
	if err := validationuser.ValidateName(req.Name); err != nil {
		h.Logger.Warn("Invalid name", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Name: " + err.Error(),
		})
	}

	if err := validationuser.ValidateEmail(req.Email); err != nil {
		h.Logger.Warn("Invalid email", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Email: " + err.Error(),
		})
	}

	if err := validationuser.ValidatePhone(req.Phone); err != nil {
		h.Logger.Warn("Invalid phone", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Phone: " + err.Error(),
		})
	}

	if err := validationuser.ValidatePassword(req.Password); err != nil {
		// Never log the password.
		h.Logger.Warn("Invalid password", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Password: " + err.Error(),
		})
	}

	// 4. Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(req.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		h.Logger.Error("Failed to hash password", zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "could not hash password",
		})
	}

	// 5. Create user model.
	// Role is always assigned by the server.
	user := &model.User{
		Name:     req.Name,
		Email:    req.Email,
		Phone:    req.Phone,
		Password: string(hashedPassword),
		Role:     "user",
	}

	// 6. Save user

	if err := h.Repo.CreateUser(user); err != nil {

		switch {
		case errors.Is(err, repository.ErrEmailAlreadyExists):
			return c.JSON(http.StatusConflict, echo.Map{
				"error": "email already exists",
			})

		case errors.Is(err, repository.ErrPhoneAlreadyExists):
			return c.JSON(http.StatusConflict, echo.Map{
				"error": "phone already exists",
			})

		case errors.Is(err, repository.ErrDuplicateEntry):
			return c.JSON(http.StatusConflict, echo.Map{
				"error": "duplicate entry",
			})

		default:
			h.Logger.Error(
				"Failed to register user",
				zap.Error(err),
			)

			return c.JSON(http.StatusInternalServerError, echo.Map{
				"error": "could not register user",
			})
		}
	}

	// 7. Build safe response
	response := model.UserResponse{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
		Phone: user.Phone,
	}

	h.Logger.Info(
		"User registered successfully",
		zap.Uint("user_id", user.ID),
	)

	return c.JSON(http.StatusCreated, echo.Map{
		"message": "user registered successfully",
		"data":    response,
	})
}

// Login godoc
// @Summary User login
// @Description Authenticate user and get JWT tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param input body model.LoginRequest true "Login payload"
// @Success 200 {object} model.APIResponse{data=model.LoginResponse} "Success"
// @Failure 400 {object} model.APIResponse "Bad Request - invalid input"
// @Failure 401 {object} model.APIResponse "Unauthorized - invalid credentials"
// @Failure 500 {object} model.APIResponse "Internal Server Error"
// @Router /login [post]
func (h *UserHandler) Login(c echo.Context) error {
	req := new(model.LoginRequest)

	if err := c.Bind(req); err != nil {
		h.Logger.Error("Failed to bind login input", zap.Error(err))
		return c.JSON(http.StatusBadRequest, model.APIResponse{
			Code:    http.StatusBadRequest,
			Message: "invalid input",
		})
	}

	if err := validationuser.ValidateEmail(req.Email); err != nil {
		h.Logger.Warn("Invalid email", zap.Error(err))
		return c.JSON(http.StatusBadRequest, model.APIResponse{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	if err := validationuser.ValidateLoginPassword(req.Password); err != nil {
		h.Logger.Warn("Invalid password", zap.Error(err))
		return c.JSON(http.StatusBadRequest, model.APIResponse{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	user, err := h.Repo.GetUserByEmail(req.Email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.Logger.Warn("User not found during login",
				zap.String("email", req.Email),
			)
			return c.JSON(http.StatusUnauthorized, model.APIResponse{
				Code:    http.StatusUnauthorized,
				Message: "email or password incorrect",
			})
		}

		h.Logger.Error("Database error during login",
			zap.String("email", req.Email),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, model.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
		})
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(req.Password),
	); err != nil {
		h.Logger.Warn("Invalid password attempt",
			zap.String("email", req.Email),
		)
		return c.JSON(http.StatusUnauthorized, model.APIResponse{
			Code:    http.StatusUnauthorized,
			Message: "email or password incorrect",
		})
	}

	// Generate a unique session ID.
	sessionID, err := tokenutil.GenerateSessionID()
	if err != nil {
		h.Logger.Error("Failed to generate session ID",
			zap.Uint("user_id", user.ID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, model.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: "could not create user session",
		})
	}

	// Generate access token linked to the session.
	accessToken, err := tokenutil.GenerateAccessTokenWithSession(
		user.ID,
		user.Role,
		user.TokenVersion,
		sessionID,
		h.Cfg,
	)
	if err != nil {
		h.Logger.Error("Failed to generate access token",
			zap.Uint("user_id", user.ID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, model.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: "could not generate tokens",
		})
	}

	// Generate refresh token linked to the session.
	refreshToken, err := tokenutil.GenerateRefreshToken(
		user.ID,
		user.Role,
		user.TokenVersion,
		sessionID,
		h.Cfg,
	)
	if err != nil {
		h.Logger.Error("Failed to generate refresh token",
			zap.Uint("user_id", user.ID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, model.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: "could not generate tokens",
		})
	}

	// Calculate refresh token expiration.
	expiresAt := time.Now().Add(h.Cfg.JWT.RefreshTTL)

	// Save the session and refresh token hash in database.
	if err := h.Repo.CreateSession(
		user.ID,
		sessionID,
		refreshToken,
		expiresAt,
	); err != nil {
		h.Logger.Error("Failed to create user session",
			zap.Uint("user_id", user.ID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, model.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: "could not create user session",
		})
	}

	h.Logger.Info("User logged in successfully",
		zap.String("email", req.Email),
	)

	return c.JSON(http.StatusOK, model.APIResponse{
		Code:    http.StatusOK,
		Message: "Login successful",
		Data: model.LoginResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	})
}

// Profile godoc
// @Summary Get user profile
// @Description Get authenticated user profile info
// @Tags user
// @Security BearerAuth
// @Accept json
// @Produce json
// @Success 200 {object} model.APIResponse{data=model.UserResponse} "Success"
// @Failure 401 {object} model.APIResponse "Unauthorized - invalid or missing token"
// @Failure 404 {object} model.APIResponse "User Not Found"
// @Failure 500 {object} model.APIResponse "Internal Server Error"
// @Router /auth/profile [get]
func (h *UserHandler) Profile(c echo.Context) error {
	uid, ok := c.Get("user_id").(uint)
	if !ok {
		h.Logger.Warn("Unauthorized access to profile: missing user_id in context")
		return c.JSON(http.StatusUnauthorized, model.APIResponse{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized: missing user_id in context",
		})
	}

	user, err := h.Repo.GetUserByID(uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.Logger.Warn("User not found", zap.Uint("user_id", uid))
			return c.JSON(http.StatusNotFound, model.APIResponse{
				Code:    http.StatusNotFound,
				Message: "User not found",
			})
		}
		h.Logger.Error("Failed to fetch user from DB", zap.Uint("user_id", uid), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, model.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: "Could not fetch user",
		})
	}

	h.Logger.Info("Profile fetched", zap.Uint("user_id", user.ID), zap.String("email", user.Email))

	res := model.UserResponse{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
		Phone: user.Phone,
	}

	return c.JSON(http.StatusOK, model.APIResponse{
		Code:    http.StatusOK,
		Message: "Profile fetched successfully",
		Data:    res,
	})
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
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "missing refresh token",
		})
	}

	// 1. Validate refresh token.
	claims, err := tokenutil.ParseToken(
		refreshToken,
		h.Cfg.JWT.RefreshKey,
		tokenutil.TokenTypeRefresh,
	)

	if err != nil {
		h.Logger.Warn("Invalid or expired refresh token", zap.Error(err))
		return c.JSON(http.StatusUnauthorized, echo.Map{
			"error": "invalid or expired refresh token",
		})
	}

	// 2. Extract user ID.
	userIDValue, ok := tokenutil.ParsePositiveIntegerClaim(claims, "user_id")
	if !ok {
		return c.JSON(http.StatusUnauthorized, echo.Map{
			"error": "invalid user ID in token",
		})
	}

	userID := uint(userIDValue)

	// 3. Extract token version.
	tokenVersionValue, ok := tokenutil.ParsePositiveIntegerClaim(claims, "token_version")
	if !ok {
		return c.JSON(http.StatusUnauthorized, echo.Map{
			"error": "invalid token version",
		})
	}

	// 4. Extract session ID.
	sessionID, ok := claims["session_id"].(string)
	if !ok || sessionID == "" {
		h.Logger.Warn("Missing session ID in refresh token",
			zap.Uint("user_id", userID),
		)

		return c.JSON(http.StatusUnauthorized, echo.Map{
			"error": "invalid refresh token session",
		})
	}

	// 5. Fetch current user data.
	user, err := h.Repo.GetUserByID(userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.Logger.Warn("User not found during token refresh",
				zap.Uint("user_id", userID),
			)

			return c.JSON(http.StatusUnauthorized, echo.Map{
				"error": "invalid or expired refresh token",
			})
		}

		h.Logger.Error("Database error during token refresh",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)

		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "internal server error",
		})
	}

	// 6. Check token version.
	if tokenVersionValue != user.TokenVersion {
		h.Logger.Warn("Stale refresh token detected",
			zap.Uint("user_id", userID),
		)

		return c.JSON(http.StatusUnauthorized, echo.Map{
			"error": "refresh token has been revoked",
		})
	}

	role := user.Role
	tokenVersion := user.TokenVersion

	// 7. Generate new access token.
	accessToken, err := tokenutil.GenerateAccessTokenWithSession(
		user.ID,
		role,
		tokenVersion,
		sessionID,
		h.Cfg,
	)
	if err != nil {
		h.Logger.Error("Failed to generate access token",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)

		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "failed to generate access token",
		})
	}

	// 8. Generate new refresh token using the same session ID.
	newRefreshToken, err := tokenutil.GenerateRefreshToken(
		user.ID,
		role,
		tokenVersion,
		sessionID,
		h.Cfg,
	)

	if err != nil {
		h.Logger.Error("Failed to generate refresh token",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)

		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "failed to generate refresh token",
		})
	}

	// 9. Rotate the stored refresh token hash.
	newExpiresAt := time.Now().Add(h.Cfg.JWT.RefreshTTL)

	err = h.Repo.RotateSession(
		user.ID,
		sessionID,
		refreshToken,
		newRefreshToken,
		newExpiresAt,
	)

	if err != nil {
		if errors.Is(err, repository.ErrSessionNotFound) ||
			errors.Is(err, repository.ErrSessionRevoked) ||
			errors.Is(err, repository.ErrSessionExpired) ||
			errors.Is(err, repository.ErrRefreshTokenReuse) {

			h.Logger.Warn("Refresh token rejected",
				zap.Uint("user_id", userID),
				zap.Error(err),
			)

			return c.JSON(http.StatusUnauthorized, echo.Map{
				"error": "refresh token is invalid, expired, or revoked",
			})
		}

		h.Logger.Error("Internal error while rotating refresh token",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)

		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "internal server error",
		})
	}

	h.Logger.Info("Tokens refreshed successfully",
		zap.Uint("user_id", userID),
		zap.String("role", role),
	)

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
// @Failure 401 {object} map[string]string "unauthorized"
// @Failure 404 {object} map[string]string "user not found"
// @Failure 409 {object} map[string]string "phone already exists or duplicate entry"
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
	// Normalize input
	req.Name = strings.TrimSpace(req.Name)
	req.Phone = strings.TrimSpace(req.Phone)

	if err := validationuser.ValidateUpdateUser(&req); err != nil {
		h.Logger.Warn("Validation failed for update user", zap.Uint("user_id", userID), zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	if err := h.Repo.UpdateUserProfile(userID, req.Name, req.Phone); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, echo.Map{
				"error": "user not found",
			})
		}

		if errors.Is(err, repository.ErrPhoneAlreadyExists) {
			return c.JSON(http.StatusConflict, echo.Map{
				"error": "phone already exists",
			})
		}

		if errors.Is(err, repository.ErrDuplicateEntry) {
			return c.JSON(http.StatusConflict, echo.Map{
				"error": "duplicate entry",
			})
		}

		h.Logger.Error(
			"Failed to update user profile",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)

		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "failed to update user",
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": "user updated",
	})
}

// DeleteUser godoc
// @Summary Delete user account
// @Description Deletes the authenticated user’s account permanently
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string "user deleted"
// @Failure 500 {object} map[string]string "internal error"
// @Failure 401 {object} map[string]string "unauthorized"
// @Router /auth/delete [delete]
func (h *UserHandler) DeleteUser(c echo.Context) error {
	userID, ok := c.Get("user_id").(uint)
	if !ok {
		h.Logger.Warn("Unauthorized delete attempt: missing user_id in context")
		return c.JSON(http.StatusUnauthorized, echo.Map{
			"error": "unauthorized",
		})
	}

	err := h.Repo.DeleteUser(userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.Logger.Warn("Attempted to delete non-existent user",
				zap.Uint("user_id", userID),
			)
			return c.JSON(http.StatusNotFound, echo.Map{
				"error": "user not found",
			})
		}

		h.Logger.Error("Failed to delete user",
			zap.Uint("user_id", userID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "failed to delete user",
		})
	}

	h.Logger.Info("User deleted successfully",
		zap.Uint("user_id", userID),
	)

	return c.JSON(http.StatusOK, echo.Map{
		"message": "user deleted",
	})
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
// @Description Request a password reset link. If the email exists, a reset link will be sent.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body request.ForgotPasswordRequest true "User email"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /forgot-password [post]
func (h *UserHandler) ForgotPassword(c echo.Context) error {
	var req request.ForgotPasswordRequest
	if err := c.Bind(&req); err != nil {
		h.Logger.Warn("Invalid ForgotPassword request", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request"})
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	if err := validationuser.ValidateEmail(req.Email); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Invalid email address",
		})
	}

	// Look up user by email

	user, err := h.Repo.GetUserByEmail(req.Email)

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.Logger.Info("Password reset request processed")

			return passwordResetResponse(c)
		}

		h.Logger.Error(
			"Database error during password reset request",
			zap.Error(err),
		)

		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Unable to process password reset request",
		})
	}

	// Generate reset JWT token

	signedToken, err := tokenutil.GenerateResetToken(user.Email, h.Cfg)
	if err != nil {
		h.Logger.Error(
			"Failed to generate reset token",
			zap.Uint("user_id", user.ID),
			zap.Error(err),
		)

		return passwordResetResponse(c)
	}
	hashedToken := hashResetToken(signedToken)
	expiresAt := time.Now().Add(15 * time.Minute)

	if err := h.Repo.SavePasswordResetToken(
		user.ID,
		hashedToken,
		expiresAt,
	); err != nil {
		h.Logger.Error("Failed to update user with reset token", zap.Uint("user_id", user.ID), zap.Error(err))
		return passwordResetResponse(c)
	}

	if h.Cfg.Email.EnableEmail {
		if err := tokenutil.SendResetEmail(h.Cfg, user.Email, signedToken); err != nil {
			h.Logger.Error("Failed to send reset email", zap.Uint("user_id", user.ID), zap.Error(err))
			return passwordResetResponse(c)
		}
	}

	h.Logger.Info("Password reset request processed")
	return passwordResetResponse(c)
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
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /reset-password [post]
func (h *UserHandler) ResetPassword(c echo.Context) error {
	var req request.ResetPasswordRequest

	if err := c.Bind(&req); err != nil {
		h.Logger.Warn("Invalid ResetPassword request", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Invalid request",
		})
	}

	// Parse and validate JWT reset token
	claims, err := tokenutil.ParseToken(
		req.Token,
		h.Cfg.JWT.ResetKey,
		tokenutil.TokenTypeReset,
	)

	if err != nil {
		h.Logger.Warn("Invalid or expired reset token", zap.Error(err))
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Invalid or expired reset token",
		})
	}

	// Extract email from token subject
	email, ok := claims["sub"].(string)
	if !ok || email == "" {
		h.Logger.Warn("Invalid reset token subject")
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Invalid reset token subject",
		})
	}

	// Find user

	user, err := h.Repo.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.Logger.Warn("User not found during password reset")
			return c.JSON(http.StatusNotFound, echo.Map{
				"error": "User not found",
			})
		}

		h.Logger.Error(
			"Failed to retrieve user during password reset",
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Internal server error",
		})
	}

	// Validate token match and database expiry
	resetTokenHash := hashResetToken(req.Token)
	now := time.Now()

	if user.ResetToken == nil ||
		user.ResetTokenExpiry == nil ||
		*user.ResetToken != resetTokenHash ||
		!user.ResetTokenExpiry.After(now) {

		h.Logger.Warn("Token mismatch or expired", zap.Uint("user_id", user.ID))
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Token is invalid or expired",
		})
	}

	// Validate new password
	if err := validationuser.ValidatePassword(req.NewPassword); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Invalid password",
		})
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(req.NewPassword),
		bcrypt.DefaultCost,
	)
	if err != nil {
		h.Logger.Error("Failed to hash new password", zap.Uint("user_id", user.ID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Failed to hash password",
		})
	}

	// Atomically validate and consume the reset token.
	if err := h.Repo.CompletePasswordReset(
		user.ID,
		string(hashedPassword),
		resetTokenHash,
		now,
	); err != nil {
		if errors.Is(err, repository.ErrInvalidOrExpiredResetToken) {
			return c.JSON(http.StatusBadRequest, echo.Map{
				"error": "Token is invalid or expired",
			})
		}

		h.Logger.Error("Failed to update password in DB", zap.Uint("user_id", user.ID), zap.Error(err))
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "Failed to update password",
		})
	}

	h.Logger.Info("Password reset successful", zap.Uint("user_id", user.ID))

	return c.JSON(http.StatusOK, echo.Map{
		"message": "Password successfully reset",
	})
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.Logger.Warn(
				"Attempted to promote non-existent user",
				zap.Uint("user_id", req.UserID),
			)
			return c.JSON(http.StatusNotFound, echo.Map{"error": "user not found"})
		}

		h.Logger.Error(
			"Failed to retrieve user for promotion",
			zap.Uint("user_id", req.UserID),
			zap.Error(err),
		)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "internal server error"})
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

	if token == "" {
		h.Logger.Warn("Missing token in reset-password link")
		return c.String(http.StatusBadRequest, "Missing token")
	}

	token = strings.ReplaceAll(token, " ", "+")

	claims, err := tokenutil.ParseToken(
		token,
		h.Cfg.JWT.ResetKey,
		tokenutil.TokenTypeReset,
	)

	if err != nil {
		h.Logger.Warn(
			"Reset token validation failed",
			zap.Error(err),
		)
		return c.String(http.StatusBadRequest, "Invalid or expired token")
	}

	email, ok := claims["sub"].(string)
	if !ok || email == "" {
		return c.String(http.StatusBadRequest, "Invalid reset token subject")
	}

	user, err := h.Repo.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.String(http.StatusBadRequest, "Invalid or expired token")
		}

		h.Logger.Error(
			"Failed to retrieve user during reset page request",
			zap.Error(err),
		)
		return c.String(http.StatusInternalServerError, "Internal server error")
	}
	if user.ResetToken == nil || user.ResetTokenExpiry == nil {
		h.Logger.Warn("Reset token data is missing in database")
		return c.String(http.StatusBadRequest, "Invalid or expired token")
	}

	if *user.ResetToken != hashResetToken(token) {
		h.Logger.Warn("Reset token hash does not match database")
		return c.String(http.StatusBadRequest, "Invalid or expired token")
	}

	if time.Now().After(*user.ResetTokenExpiry) {
		h.Logger.Warn(
			"Reset token database expiration has passed",
			zap.Time("expires_at", *user.ResetTokenExpiry),
			zap.Time("current_time", time.Now()),
		)
		return c.String(http.StatusBadRequest, "Invalid or expired token")
	}

	h.Logger.Info("Valid password reset page requested")

	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	c.Response().Header().Set("X-Content-Type-Options", "nosniff")

	return resetPasswordPage.Execute(c.Response().Writer, struct {
		Token string
	}{
		Token: token,
	})
}
