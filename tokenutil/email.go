package tokenutil

import (
	"bytes"
	"fmt"
	"net/smtp"
	"path/filepath"
	"reg/config"
	"text/template"
	"time"

	"go.uber.org/zap"
)

type ResetEmailData struct {
	Email     string
	ResetLink string
	Year      int
}

func SendResetEmail(cfg *config.Config, to string, token string) error {
	from := cfg.Email.From
	password := cfg.Email.Password

	// Build the full reset link with token
	resetLink := fmt.Sprintf("http://localhost:8085/reset-password?token=%s", token)

	tmplPath := filepath.Join("templates", "reset_email.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		zap.L().Error("Failed to parse email template",
			zap.String("templatePath", tmplPath),
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
		zap.L().Error("Failed to execute email template",
			zap.String("to", to),
			zap.Error(err),
		)
		return err
	}

	msg := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n"
	msg += fmt.Sprintf("From: %s\nTo: %s\nSubject: Password Reset Request\n\n", from, to)
	msg += body.String()

	auth := smtp.PlainAuth("", cfg.Email.Username, password, cfg.Email.Host)
	err = smtp.SendMail(
		fmt.Sprintf("%s:%d", cfg.Email.Host, cfg.Email.Port),
		auth,
		from,
		[]string{to},
		[]byte(msg),
	)
	if err != nil {
		zap.L().Error("Failed to send reset email",
			zap.String("to", to),
			zap.String("link", resetLink),
			zap.Error(err),
		)
		return err
	}

	zap.L().Info("Reset email sent successfully",
		zap.String("to", to),
		zap.String("link", resetLink),
	)
	return nil
}
