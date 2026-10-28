package threat

import (
	"regexp"
	"strings"
	"testing"
)

func FuzzNormalizeMD5(f *testing.F) {
	for _, seed := range []string{"", strings.Repeat("a", 32), strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("я", 16), strings.Repeat("a", 31) + "\n"} {
		f.Add(seed)
	}
	contract := regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	f.Fuzz(func(t *testing.T, value string) {
		got, err := NormalizeMD5(value)
		if (err == nil) != contract.MatchString(value) {
			t.Fatal("MD5 validation differs from the API contract")
		}
		if err == nil && (got != strings.ToLower(value) || len(got) != 32) {
			t.Fatal("incorrect canonical MD5")
		}
	})
}
