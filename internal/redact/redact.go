// Package redact strips secrets from JSON payloads before they are logged.
package redact

import (
	"encoding/json"
	"regexp"
)

const Placeholder = "«redacted»"

var (
	secretKey = regexp.MustCompile(`(?i)(token|key|secret|password|passwd|auth|credential)`)
	// sk_/sk- style prefixes, bearer tokens, JWTs, and long hex/base64 runs,
	// matched anywhere inside a string
	secretValue = regexp.MustCompile(`\bsk[-_][A-Za-z0-9_-]{8,}|(?i:bearer)\s+[A-Za-z0-9._~+/=-]+|\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}|\b[A-Fa-f0-9]{32,}\b|[A-Za-z0-9+/=_-]{40,}`)
)

// Key reports whether a JSON key or env name looks like it holds a secret.
func Key(k string) bool { return secretKey.MatchString(k) }

// JSON redacts raw and truncates the encoded result to max bytes (0 = no
// limit). It returns the redacted JSON and the size before truncation.
// Input that is not valid JSON is treated as an opaque string.
func JSON(raw []byte, max int) (out []byte, size int) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		v = string(raw)
	}
	v = walk(v)
	enc, err := json.Marshal(v)
	if err != nil {
		enc = []byte(`"` + Placeholder + `"`)
	}
	size = len(enc)
	if max > 0 && len(enc) > max {
		enc = append(enc[:max], []byte("…")...)
	}
	return enc, size
}

func walk(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if Key(k) {
				t[k] = Placeholder
				continue
			}
			t[k] = walk(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = walk(val)
		}
		return t
	case string:
		return redactString(t)
	}
	return v
}

// redactString handles JSON that arrives encoded inside a string, which is
// how most tool results carry structured data, then scrubs inline secrets.
func redactString(s string) string {
	if len(s) > 1 && (s[0] == '{' || s[0] == '[') {
		var inner any
		if err := json.Unmarshal([]byte(s), &inner); err == nil {
			if enc, err := json.Marshal(walk(inner)); err == nil {
				return string(enc)
			}
		}
	}
	return secretValue.ReplaceAllString(s, Placeholder)
}
