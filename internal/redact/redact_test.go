package redact

import (
	"strings"
	"testing"
)

func TestJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"key match", `{"api_token":"abc","symbol":"AAPL"}`, `{"api_token":"«redacted»","symbol":"AAPL"}`},
		{"key match is case insensitive", `{"Authorization":"x","PassWord":"y"}`, `{"Authorization":"«redacted»","PassWord":"«redacted»"}`},
		{"nested and arrays", `{"a":[{"secret":1},{"b":"sk_live_abcdefghijk"}]}`, `{"a":[{"secret":"«redacted»"},{"b":"«redacted»"}]}`},
		{"jwt value", `{"x":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}`, `{"x":"«redacted»"}`},
		{"hex run", `{"h":"0123456789abcdef0123456789abcdef"}`, `{"h":"«redacted»"}`},
		{"short hex kept", `{"h":"deadbeef"}`, `{"h":"deadbeef"}`},
		{"normal prose kept", `{"q":"what is the price of apple stock today please"}`, `{"q":"what is the price of apple stock today please"}`},
		{"numbers and bools untouched", `{"n":42,"b":true,"z":null}`, `{"b":true,"n":42,"z":null}`},
		{"non json becomes string", `not json`, `"not json"`},
		{"top level array", `["sk-abcdefghijklmnop","x"]`, `["«redacted»","x"]`},
		{"key hit inside description word", `{"monkey":"banana"}`, `{"monkey":"«redacted»"}`},
		{"json inside string", `{"text":"{\"api_key\":\"x\",\"price\":1}"}`, `{"text":"{\"api_key\":\"«redacted»\",\"price\":1}"}`},
		{"inline secret in prose", `{"t":"use sk_live_abcdefghijk for calls"}`, `{"t":"use «redacted» for calls"}`},
		{"inline bearer", `{"t":"Authorization: Bearer abc.def-ghi rest"}`, `{"t":"Authorization: «redacted» rest"}`},
		{"string starting with brace but not json", `{"t":"{not json sk_live_abcdefghijk"}`, `{"t":"{not json «redacted»"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := JSON([]byte(tc.in), 0)
			if string(got) != tc.want {
				t.Errorf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestJSONTruncates(t *testing.T) {
	in := `{"text":"` + strings.Repeat("word ", 20) + `"}`
	got, size := JSON([]byte(in), 20)
	if size != len(in) {
		t.Errorf("size %d want %d", size, len(in))
	}
	if len(got) != 20+len("…") || !strings.HasSuffix(string(got), "…") {
		t.Errorf("got %q", got)
	}
	got, size = JSON([]byte(in), 1000)
	if size != len(in) || string(got) != in {
		t.Errorf("should not truncate under limit: %q", got)
	}
}
