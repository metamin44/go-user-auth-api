package validationuser

import (
	"fmt"
	"reg/model"
	"regexp"
	"strings"

	ozzo "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

var (
	phoneRegex    = regexp.MustCompile(`^09[0-9]{9}$`)
	passwordRegex = regexp.MustCompile(`^[\x21-\x7E]{8,}$`)
)

func ValidateName(name string) error {
	return ozzo.Validate(
		strings.TrimSpace(name),
		ozzo.Required,
		ozzo.Length(3, 0),
	)
}

func ValidateEmail(email string) error {
	return ozzo.Validate(email,
		ozzo.Required,
		is.Email,
	)
}

func ValidatePhone(phone string) error {
	return ozzo.Validate(phone,
		ozzo.Required,
		ozzo.Match(phoneRegex).Error(
			"Phone must start with 09 and be 11 digits.",
		),
	)
}

func ValidatePassword(password string) error {
	return ozzo.Validate(password,
		ozzo.Required,
		ozzo.Match(passwordRegex).Error(
			"Password must contain at least 8 characters without spaces.",
		),
	)
}

func ValidateUpdateUser(req *model.UpdateUserRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	return ozzo.ValidateStruct(req,
		ozzo.Field(&req.Name,
			ozzo.Required,
			ozzo.By(func(value interface{}) error {
				name, ok := value.(string)
				if !ok {
					return fmt.Errorf("name must be a string")
				}
				if len([]rune(strings.TrimSpace(name))) < 3 {
					return fmt.Errorf("name must be at least 3 characters")
				}
				return nil
			}),
		),
		ozzo.Field(&req.Phone,
			ozzo.Required,
			ozzo.Match(phoneRegex),
		),
	)
}

func ValidateChangePassword(req *model.ChangePasswordRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	return ozzo.ValidateStruct(req,
		ozzo.Field(&req.OldPassword, ozzo.Required),
		ozzo.Field(&req.NewPassword,
			ozzo.Required,
			ozzo.Match(passwordRegex).Error(
				"New password must contain at least 8 characters without spaces",
			),
		),
	)
}

func ValidateLoginPassword(password string) error {
	return ozzo.Validate(password, ozzo.Required)
}
