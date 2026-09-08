package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// The Datastar SSE protocol (v1) is small enough to write directly rather
// than pull in the SDK and its compression dependencies.

type sse struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func newSSE(w http.ResponseWriter, r *http.Request) (*sse, error) {
	f, ok := w.(http.Flusher)
	if !ok {
		return nil, errors.New("response writer cannot stream")
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	f.Flush()
	return &sse{w: w, flusher: f}, nil
}

// patchElements morphs the elements into the DOM by id.
func (s *sse) patchElements(html string) error {
	var b strings.Builder
	b.WriteString("event: datastar-patch-elements\n")
	for _, line := range strings.Split(strings.TrimRight(html, "\n"), "\n") {
		b.WriteString("data: elements ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	if _, err := io.WriteString(s.w, b.String()); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}

// readSignals decodes the signals Datastar sends: a `datastar` query
// parameter on GET, the JSON body otherwise.
func readSignals(r *http.Request, v any) error {
	if r.Method == http.MethodGet {
		raw := r.URL.Query().Get("datastar")
		if raw == "" {
			return nil
		}
		return json.Unmarshal([]byte(raw), v)
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return fmt.Errorf("decode signals: %w", err)
	}
	return nil
}
