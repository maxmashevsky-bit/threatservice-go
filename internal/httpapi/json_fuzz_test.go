package httpapi

import (
	"encoding/json"
	"testing"
	"unicode/utf8"

	"threatservice/api"
)

func FuzzDecodeObject(f *testing.F) {
	for _, seed := range []string{`{"md5":"0123456789abcdef0123456789abcdef","name":"a"}`, `{"md5":"a","name":"\uD83D\uDE00"}`, `{"md5":"a","name":"\uD800"}`, `{"name":"a","\u006eame":"b"}`, `{"name":null}`, `[]`, `null`, `{}`, `{"name":{"deep":[[]]}}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		var request api.ThreatCreateRequest
		err := decodeObject(data, []string{"md5", "name", "description", "severity"}, []string{"md5", "name"}, &request)
		if err != nil {
			return
		}
		// Independent standard-library decoding checks structural invariants of
		// every accepted input. The ordinary tests cover duplicate-key rejection.
		if !utf8.Valid(data) || !json.Valid(data) {
			t.Fatal("accepted invalid UTF-8 or JSON")
		}
		var values map[string]json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil || values == nil {
			t.Fatal("accepted non-object")
		}
		for _, key := range []string{"md5", "name"} {
			if _, ok := values[key]; !ok {
				t.Fatal("accepted a missing required field")
			}
		}
		for key, value := range values {
			if key != "md5" && key != "name" && key != "description" && key != "severity" {
				t.Fatal("accepted an unknown field")
			}
			var text string
			if string(value) == "null" || json.Unmarshal(value, &text) != nil {
				t.Fatal("accepted a non-string value")
			}
		}
		canonical, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip api.ThreatCreateRequest
		if err := decodeObject(canonical, []string{"md5", "name", "description", "severity"}, []string{"md5", "name"}, &roundtrip); err != nil {
			t.Fatal("accepted value does not round-trip")
		}
	})
}
