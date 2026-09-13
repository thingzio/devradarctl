// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
	return c.doOnce(ctx, method, path, q, body, out)
}

// doOnce performs a single request attempt. A non-2xx status is returned as an
// *APIError, so a retry loop can recover the status with errors.As rather than
// re-parsing the response; transport and read failures are returned as-is.
func (c *Client) doOnce(ctx context.Context, method, path string, q url.Values, body io.Reader, out any) error {
	u := c.baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bound the response read: a hostile or buggy server must not be able to
	// exhaust memory. maxResponseBytes is generous for any DevRadar JSON page.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if int64(len(raw)) > maxResponseBytes {
		return fmt.Errorf("%s %s: response exceeds %d bytes", method, path, maxResponseBytes)
	}
	if resp.StatusCode >= 300 {
		apiErr := newAPIError(resp.StatusCode, raw)
		apiErr.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
		return apiErr
	}

	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode response (HTTP %d): %w", resp.StatusCode, err)
	}
	return nil
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
		err := c.doOnce(ctx, http.MethodGet, path, q, nil, out)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryable(err) {
			return err
		}
	}
	return lastErr
}

// isRetryable reports whether a failed GET should be retried: a transient
// transport error, or a 5xx / 429 status. A context cancellation is not
// retryable.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
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
	// Jitter spreads retries across clients; it is not a security boundary, so
	// a PRNG is the right tool and crypto/rand would only add cost.
	return time.Duration(rand.Int64N(int64(d) + 1)) //nolint:gosec // G404: jitter, not a secret
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
