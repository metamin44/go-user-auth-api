package validationuser

import (
	"reg/model"
	"regexp"

	ozzo "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

func ValidateName(name string) error {
	return ozzo.Validate(name,
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
		ozzo.Match(regexp.MustCompile(`^09[0-9]{9}$`)).Error("Phone must start with 09 and be 11 digits."),
	)
}

func ValidatePassword(password string) error {
	return ozzo.Validate(password,
		ozzo.Required,
		ozzo.Match(regexp.MustCompile(`^[A-Za-z0-9!@#%^&*]{8,}$`)).
			Error("Password must be min 8 chars."),
	)
}

func ValidateUpdateUser(req *model.UpdateUserRequest) error {
	return ozzo.ValidateStruct(req,
		ozzo.Field(&req.Name, ozzo.Required, ozzo.Length(3, 0)),
		ozzo.Field(&req.Phone, ozzo.Required, ozzo.Match(regexp.MustCompile(`^09[0-9]{9}$`))),
	)
}

func ValidateChangePassword(req *model.ChangePasswordRequest) error {
	return ozzo.ValidateStruct(req,
		ozzo.Field(&req.OldPassword, ozzo.Required),
		ozzo.Field(&req.NewPassword, ozzo.Required, ozzo.Match(
			regexp.MustCompile(`^[A-Za-z0-9!@#%^&*]{8,}$`),
		).Error("New password must be min 8 chars")),
	)
}
