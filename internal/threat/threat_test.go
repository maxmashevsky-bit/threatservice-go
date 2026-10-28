package threat

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNormalizeMD5(t *testing.T) {
	for _, tt := range []struct {
		name, input, want string
		valid             bool
	}{
		{"lower", "0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef", true},
		{"mixed", "0123456789ABCDEF0123456789abcDEF", "0123456789abcdef0123456789abcdef", true},
		{"empty", "", "", false}, {"short", strings.Repeat("a", 31), "", false},
		{"long", strings.Repeat("a", 33), "", false}, {"nonhex", strings.Repeat("g", 32), "", false},
		{"trailing newline", strings.Repeat("a", 31) + "\n", "", false},
		{"unicode", strings.Repeat("а", 16), "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeMD5(tt.input)
			if (err == nil) != tt.valid || got != tt.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestValidateInput(t *testing.T) {
	valid := Input{Name: "Trojan", Description: "", Severity: SeverityUnknown}
	for _, tt := range []struct {
		name   string
		change func(*Input)
		field  string
	}{
		{"blank", func(i *Input) { i.Name = " \t\n\u2003" }, "name"},
		{"long name", func(i *Input) { i.Name = strings.Repeat("я", 256) }, "name"},
		{"nul name", func(i *Input) { i.Name = "x\x00" }, "name"},
		{"bad UTF8", func(i *Input) { i.Name = string([]byte{0xff}) }, "name"},
		{"long description", func(i *Input) { i.Description = strings.Repeat("я", 4001) }, "description"},
		{"nul description", func(i *Input) { i.Description = "\x00" }, "description"},
		{"empty severity", func(i *Input) { i.Severity = "" }, "severity"},
		{"unknown severity", func(i *Input) { i.Severity = "HIGH" }, "severity"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := valid
			tt.change(&v)
			err := ValidateInput(v)
			var validation *ValidationError
			if !errors.As(err, &validation) || validation.Field != tt.field {
				t.Fatalf("got %v", err)
			}
		})
	}
	for _, severity := range []Severity{SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if err := ValidateInput(Input{Name: strings.Repeat("😀", 255), Description: strings.Repeat("ж", 4000), Severity: severity}); err != nil {
			t.Fatal(err)
		}
	}
}

type recordingRepo struct {
	calls int
	md5   string
	input Input
	err   error
}

func (r *recordingRepo) Create(_ context.Context, md5 string, input Input) (Threat, error) {
	r.calls++
	r.md5 = md5
	r.input = input
	return Threat{MD5: md5, Name: input.Name}, r.err
}
func (r *recordingRepo) GetByMD5(_ context.Context, md5 string) (Threat, error) {
	r.calls++
	r.md5 = md5
	return Threat{}, r.err
}
func (r *recordingRepo) Replace(ctx context.Context, md5 string, input Input) (Threat, error) {
	return r.Create(ctx, md5, input)
}

func TestServiceValidatesBeforeStorageAndPreservesInput(t *testing.T) {
	r := &recordingRepo{}
	s := NewService(r)
	input := Input{Name: "  Троян  ", Description: "е\u0301", Severity: SeverityHigh}
	if _, err := s.Create(context.Background(), strings.Repeat("A", 32), input); err != nil {
		t.Fatal(err)
	}
	if r.md5 != strings.Repeat("a", 32) || r.input != input {
		t.Fatalf("input changed: %+v", r)
	}
	if _, err := s.Replace(context.Background(), strings.Repeat("a", 32), Input{}); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if _, err := s.GetByMD5(context.Background(), "invalid"); err == nil {
		t.Fatal("invalid hash accepted")
	}
	if r.calls != 1 {
		t.Fatalf("invalid requests reached storage: %d calls", r.calls)
	}
	r.err = ErrAlreadyExists
	if _, err := s.Create(context.Background(), strings.Repeat("a", 32), input); !errors.Is(err, ErrAlreadyExists) {
		t.Fatal(err)
	}
	r.err = ErrNotFound
	if _, err := s.GetByMD5(context.Background(), strings.Repeat("a", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
