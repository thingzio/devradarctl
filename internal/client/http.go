package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Retry policy for idempotent (GET) requests. Writes are never retried here —
// submit is idempotent server-side, but a blind client retry on an ambiguous
// write (e.g. a timeout after the server committed) is still avoided by design.
const (
	maxGetAttempts = 4
	baseBackoff    = 250 * time.Millisecond
	maxBackoff     = 5 * time.Second
)

// do issues an authenticated request to {baseURL}{path} (with optional query),
// sending body when non-nil. A non-2xx status is returned as an error including
// the response body. When out is non-nil and the response has a body, the body
// is JSON-decoded into out; a 204 (or empty body) leaves out untouched.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body io.Reader, out any) error {
	_, err := c.doOnce(ctx, method, path, q, body, out)
	return err
}

// doOnce performs a single request attempt. It returns the *APIError (if the
// status was non-2xx) alongside the error so a retry loop can inspect the
// status without re-parsing, and returns other errors (transport, read) as-is.
func (c *Client) doOnce(ctx context.Context, method, path string, q url.Values, body io.Reader, out any) (*APIError, error) {
	u := c.baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s %s: %w", method, u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bound the response read: a hostile or buggy server must not be able to
	// exhaust memory. maxResponseBytes is generous for any DevRadar JSON page.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("%s %s: response exceeds %d bytes", method, path, maxResponseBytes)
	}
	if resp.StatusCode >= 300 {
		apiErr := newAPIError(resp.StatusCode, raw)
		apiErr.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
		return apiErr, apiErr
	}

	if out == nil || len(raw) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("decode response (HTTP %d): %w", resp.StatusCode, err)
	}
	return nil, nil
}

// get is an authenticated GET decoding JSON into out, with bounded retries on
// transient failures (transport errors, 5xx, and 429) using exponential
// backoff with jitter, honoring a Retry-After header when present.
func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	var lastErr error
	for attempt := range maxGetAttempts {
		if attempt > 0 {
			delay := backoffDelay(attempt, lastErr)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		apiErr, err := c.doOnce(ctx, http.MethodGet, path, q, nil, out)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryable(apiErr, err) {
			return err
		}
	}
	return lastErr
}

// isRetryable reports whether a failed GET should be retried: a transient
// transport error, or a 5xx / 429 status. A context cancellation is not
// retryable.
func isRetryable(apiErr *APIError, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if apiErr != nil {
		return apiErr.StatusCode >= 500 || apiErr.StatusCode == http.StatusTooManyRequests
	}
	// No APIError → transport/read error → transient.
	return true
}

// backoffDelay returns the wait before the given attempt (1-based for the first
// retry). It honors a server Retry-After when present, otherwise uses capped
// exponential backoff with full jitter.
func backoffDelay(attempt int, lastErr error) time.Duration {
	var apiErr *APIError
	if errors.As(lastErr, &apiErr) && apiErr.retryAfter > 0 {
		return min(apiErr.retryAfter, maxBackoff)
	}
	// Exponential: base * 2^(attempt-1), capped, with full jitter in [0, d].
	d := min(baseBackoff<<(attempt-1), maxBackoff)
	return time.Duration(rand.Int64N(int64(d) + 1))
}

// parseRetryAfter parses a Retry-After header value, supporting the
// delta-seconds form (the HTTP-date form is uncommon here and treated as 0).
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
