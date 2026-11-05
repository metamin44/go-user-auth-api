package tokenutil

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/mail"
	"net/smtp"
	"net/url"
	"reg/config"
	"time"

	"go.uber.org/zap"
)

//go:embed templates/reset_email.html
var emailTemplates embed.FS

type ResetEmailData struct {
	Email     string
	ResetLink string
	Year      int
}

func SendResetEmail(cfg *config.Config, to string, token string) error {
	if cfg == nil {
		return fmt.Errorf("email configuration is nil")
	}

	if to == "" {
		return fmt.Errorf("recipient email cannot be empty")
	}

	if token == "" {
		return fmt.Errorf("reset token cannot be empty")
	}

	recipientAddress, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("invalid recipient email address")
	}

	fromAddress, err := mail.ParseAddress(cfg.Email.From)
	if err != nil {
		return fmt.Errorf("invalid sender email address")
	}

	if !cfg.Email.EnableEmail {
		return fmt.Errorf("email sending is disabled")
	}

	from := cfg.Email.From
	password := cfg.Email.Password

	if cfg.Email.Host == "" ||
		cfg.Email.Username == "" ||
		password == "" ||
		from == "" ||
		cfg.Email.ResetURL == "" {
		return fmt.Errorf("email configuration is incomplete")
	}

	// Build the full reset link with token.

	resetURL, err := url.Parse(cfg.Email.ResetURL)
	if err != nil {
		return fmt.Errorf("invalid reset URL: %w", err)
	}

	if resetURL.Scheme != "https" && resetURL.Scheme != "http" {
		return fmt.Errorf("reset URL must use HTTP or HTTPS")
	}

	if resetURL.Host == "" {
		return fmt.Errorf("reset URL must include a host")
	}

	query := resetURL.Query()
	query.Set("token", token)
	resetURL.RawQuery = query.Encode()

	resetLink := resetURL.String()

	tmpl, err := template.ParseFS(
		emailTemplates,
		"templates/reset_email.html",
	)
	if err != nil {
		zap.L().Error(
			"Failed to parse email template",
			zap.Error(err),
		)
		return err
	}

	var body bytes.Buffer

	data := ResetEmailData{
		Email:     to,
		ResetLink: resetLink,
		Year:      time.Now().Year(),
	}

	if err := tmpl.Execute(&body, data); err != nil {
		zap.L().Error(
			"Failed to execute email template",
			zap.Error(err),
		)
		return err
	}

	msg := "MIME-version: 1.0;\r\n"
	msg += "Content-Type: text/html; charset=\"UTF-8\";\r\n"
	msg += fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: Password Reset Request\r\n\r\n",
		fromAddress.String(),
		recipientAddress.String(),
	)
	msg += body.String()

	auth := smtp.PlainAuth(
		"",
		cfg.Email.Username,
		password,
		cfg.Email.Host,
	)

	err = smtp.SendMail(
		fmt.Sprintf("%s:%d", cfg.Email.Host, cfg.Email.Port),
		auth,
		fromAddress.Address,
		[]string{recipientAddress.Address},
		[]byte(msg),
	)

	if err != nil {
		zap.L().Error(
			"Failed to send reset email",
			zap.Error(err),
		)
		return err
	}

	zap.L().Info("Reset email sent successfully")

	return nil
}
