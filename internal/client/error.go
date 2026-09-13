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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// APIError is a non-2xx response from the DevRadar API. It carries the HTTP
// status and the server's message (parsed from the standard {"error":"..."}
// envelope, falling back to the raw body), so callers can branch on the status
// (e.g. 429) instead of matching on strings.
type APIError struct {
	StatusCode int
	// Message is the server's human-readable error, or the trimmed raw body when
	// the response was not the {"error":"..."} envelope.
	Message string
	// retryAfter is the parsed Retry-After header (0 if absent), used by the GET
	// retry loop to pace a backoff.
	retryAfter time.Duration
}

// newAPIError builds an APIError from a status code and raw response body.
func newAPIError(status int, body []byte) *APIError {
	msg := strings.TrimSpace(string(body))
	var env struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error != "" {
		msg = env.Error
	}
	return &APIError{StatusCode: status, Message: msg}
}

// Error implements error. The message is already the server's text; the status
// is included so logs and unexpected cases stay diagnosable.
func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// TooManyRequests reports whether the response was a 429 — either a rate limit
// or a tenant SBOM/image cap.
func (e *APIError) TooManyRequests() bool {
	return e.StatusCode == http.StatusTooManyRequests
}
