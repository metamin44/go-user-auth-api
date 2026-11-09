package validationuser

import (
	"reg/model"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid name", "Ali Reza", false},
		{"empty name", "", true},
		{"short name", "Al", true},
		{"whitespace only", "   ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateName(%q) error = %v, wantErr %v",
					tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid email", "user@example.com", false},
		{"empty email", "", true},
		{"invalid email", "invalid-email", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail(%q) error = %v, wantErr %v",
					tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePhone(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid phone", "09123456789", false},
		{"empty phone", "", true},
		{"short phone", "0912345678", true},
		{"wrong prefix", "08123456789", true},
		{"contains letters", "0912345678a", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePhone(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePhone(%q) error = %v, wantErr %v",
					tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid password", "Secret123!", false},
		{"empty password", "", true},
		{"short password", "Abc123!", true},
		{"underscore is allowed", "Secret_123", false},
		{"dollar sign is allowed", "Secret$123", false},
		{"password with spaces", "Secret 123", true},
		{"maximum bcrypt password length (72 bytes)", strings.Repeat("A", 72), false},
		{"password exceeds bcrypt limit (73 bytes)", strings.Repeat("A", 73), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword error = %v, wantErr %v",
					err, tt.wantErr)
			}
		})
	}
}

func TestValidateLoginPassword(t *testing.T) {
	if err := ValidateLoginPassword("anything"); err != nil {
		t.Errorf("expected non-empty password to be valid, got %v", err)
	}

	if err := ValidateLoginPassword(""); err == nil {
		t.Error("expected empty password to be invalid")
	}
	if err := ValidateLoginPassword(strings.Repeat("A", 72)); err != nil {
		t.Errorf("expected 72-byte password to be valid, got %v", err)
	}

	if err := ValidateLoginPassword(strings.Repeat("A", 73)); err == nil {
		t.Error("expected password longer than 72 bytes to be invalid")
	}
}

func TestValidateUpdateUser(t *testing.T) {
	if err := ValidateUpdateUser(nil); err == nil {
		t.Error("expected nil request to be invalid")
	}

	valid := &model.UpdateUserRequest{
		Name:  "Ali Reza",
		Phone: "09123456789",
	}

	if err := ValidateUpdateUser(valid); err != nil {
		t.Errorf("expected valid request, got %v", err)
	}

	invalid := &model.UpdateUserRequest{
		Name:  "",
		Phone: "09123456789",
	}

	if err := ValidateUpdateUser(invalid); err == nil {
		t.Error("expected empty name to be invalid")
	}
}

func TestValidateChangePassword(t *testing.T) {
	if err := ValidateChangePassword(nil); err == nil {
		t.Error("expected nil request to be invalid")
	}

	valid := &model.ChangePasswordRequest{
		OldPassword: "OldSecret123!",
		NewPassword: "NewSecret123!",
	}

	if err := ValidateChangePassword(valid); err != nil {
		t.Errorf("expected valid request, got %v", err)
	}

	invalid := &model.ChangePasswordRequest{
		OldPassword: "",
		NewPassword: "NewSecret123!",
	}

	if err := ValidateChangePassword(invalid); err == nil {
		t.Error("expected empty old password to be invalid")
	}
	tooLong := &model.ChangePasswordRequest{
		OldPassword: "OldSecret123!",
		NewPassword: strings.Repeat("A", 73),
	}

	if err := ValidateChangePassword(tooLong); err == nil {
		t.Error("expected new password longer than 72 bytes to be invalid")
	}
}
