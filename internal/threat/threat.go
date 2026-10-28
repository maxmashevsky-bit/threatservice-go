package threat

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var (
	ErrNotFound      = errors.New("threat not found")
	ErrAlreadyExists = errors.New("threat already exists")
)

type ValidationError struct{ Field, Message string }

func (e *ValidationError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Message) }

type Threat struct {
	MD5         string
	Name        string
	Description string
	Severity    Severity
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Input struct {
	Name        string
	Description string
	Severity    Severity
}

type Repository interface {
	Create(context.Context, string, Input) (Threat, error)
	GetByMD5(context.Context, string) (Threat, error)
	Replace(context.Context, string, Input) (Threat, error)
}

func NormalizeMD5(value string) (string, error) {
	if len(value) != 32 {
		return "", &ValidationError{"md5", "must contain exactly 32 hexadecimal characters"}
	}
	for _, c := range []byte(value) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", &ValidationError{"md5", "must contain exactly 32 hexadecimal characters"}
		}
	}
	return strings.ToLower(value), nil
}

func ValidateInput(input Input) error {
	if !utf8.ValidString(input.Name) || strings.ContainsRune(input.Name, 0) || strings.TrimSpace(input.Name) == "" || utf8.RuneCountInString(input.Name) > 255 {
		return &ValidationError{"name", "must contain 1 to 255 characters, must not be blank or contain NUL"}
	}
	if !utf8.ValidString(input.Description) || strings.ContainsRune(input.Description, 0) || utf8.RuneCountInString(input.Description) > 4000 {
		return &ValidationError{"description", "must contain at most 4000 characters and must not contain NUL"}
	}
	switch input.Severity {
	case SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return nil
	default:
		return &ValidationError{"severity", "must be unknown, low, medium, high or critical"}
	}
}

type Service struct{ repo Repository }

func NewService(repo Repository) *Service { return &Service{repo: repo} }
func (s *Service) Create(ctx context.Context, md5 string, input Input) (Threat, error) {
	normalized, err := NormalizeMD5(md5)
	if err != nil {
		return Threat{}, err
	}
	if err := ValidateInput(input); err != nil {
		return Threat{}, err
	}
	return s.repo.Create(ctx, normalized, input)
}
func (s *Service) GetByMD5(ctx context.Context, md5 string) (Threat, error) {
	normalized, err := NormalizeMD5(md5)
	if err != nil {
		return Threat{}, err
	}
	return s.repo.GetByMD5(ctx, normalized)
}
func (s *Service) Replace(ctx context.Context, md5 string, input Input) (Threat, error) {
	normalized, err := NormalizeMD5(md5)
	if err != nil {
		return Threat{}, err
	}
	if err := ValidateInput(input); err != nil {
		return Threat{}, err
	}
	return s.repo.Replace(ctx, normalized, input)
}
