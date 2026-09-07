package main

import (
	"fmt"
	"net/http"
	"time"
)

// runHealthcheck exits non-zero unless url answers 200, so the image needs
// no curl for Docker HEALTHCHECK.
func runHealthcheck(url string) error {
	c := &http.Client{Timeout: 4 * time.Second}
	res, err := c.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", res.StatusCode)
	}
	return nil
}
