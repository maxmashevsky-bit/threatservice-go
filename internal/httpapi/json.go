package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

func decodeObject(body []byte, allowed, required []string, dst any) error {
	if !utf8.Valid(body) || !validSurrogates(body) {
		return errors.New("JSON strings must contain valid Unicode")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("body must be one JSON object")
	}
	known := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		known[key] = true
	}
	seen := make(map[string]bool, len(allowed))
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return errors.New("invalid JSON")
		}
		key, ok := token.(string)
		if !ok || !known[key] {
			return errors.New("unknown JSON field")
		}
		if seen[key] {
			return errors.New("duplicate JSON field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return errors.New("invalid JSON")
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("%s must not be null", key)
		}
		var str string
		if err := json.Unmarshal(value, &str); err != nil {
			return fmt.Errorf("%s must be a string", key)
		}
	}
	if closing, err := dec.Token(); err != nil || closing != json.Delim('}') {
		return errors.New("invalid JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("body must contain exactly one JSON object")
	}
	for _, key := range required {
		if !seen[key] {
			return fmt.Errorf("%s is required", key)
		}
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return errors.New("invalid JSON")
	}
	return nil
}

func validSurrogates(body []byte) bool {
	inside := false
	for i := 0; i < len(body); i++ {
		if body[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || body[i] != '\\' {
			continue
		}
		i++
		if i >= len(body) {
			return false
		}
		if body[i] != 'u' {
			continue
		}
		code, ok := hex4(body, i+1)
		if !ok {
			return false
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if i+6 >= len(body) || body[i+1] != '\\' || body[i+2] != 'u' {
			return false
		}
		low, ok := hex4(body, i+3)
		if !ok || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}

func hex4(body []byte, start int) (uint16, bool) {
	if start+4 > len(body) {
		return 0, false
	}
	var value uint16
	for _, ch := range body[start : start+4] {
		value <<= 4
		switch {
		case ch >= '0' && ch <= '9':
			value |= uint16(ch - '0')
		case ch >= 'a' && ch <= 'f':
			value |= uint16(ch - 'a' + 10)
		case ch >= 'A' && ch <= 'F':
			value |= uint16(ch - 'A' + 10)
		default:
			return 0, false
		}
	}
	return value, true
}
