package audit

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// Handler serves GET /audit?namespace=&server=&tool=&status=&since=&after_id=&limit=
// where since is RFC 3339 or a Go duration like 24h.
func Handler(store *Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := Filter{Namespace: q.Get("namespace"), Server: q.Get("server"), Tool: q.Get("tool"), Status: q.Get("status")}
		if s := q.Get("since"); s != "" {
			t, err := ParseSince(s)
			if err != nil {
				http.Error(w, "since: "+err.Error(), http.StatusBadRequest)
				return
			}
			f.Since = t
		}
		if s := q.Get("limit"); s != "" {
			f.Limit, _ = strconv.Atoi(s)
		}
		if s := q.Get("after_id"); s != "" {
			f.AfterID, _ = strconv.ParseInt(s, 10, 64)
		}
		rows, err := store.Query(r.Context(), f)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if rows == nil {
			rows = []Row{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rows)
	})
}

func ParseSince(s string) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	return time.Parse(time.RFC3339, s)
}
