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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// runCapture runs the CLI with args, capturing stdout and stderr via the
// command's Writer/ErrWriter (proving output is routed through them, not process
// globals). Returns stdout, stderr, and the run error.
func runCapture(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := New("test", "abc123", "today")
	cmd.Writer = &out
	cmd.ErrWriter = &errOut
	err := cmd.Run(context.Background(), append([]string{name}, args...))
	return out.String(), errOut.String(), err
}

func TestRender_JSONGoesToWriter(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sbom_id":"sb-1","format":"cyclonedx","counts":{"total":1}}`))
	}))
	defer srv.Close()

	out, _, err := runCapture(t, "sbom", "get", "sb-1", "--base-url", srv.URL, "-o", "json")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out)
	}
	if got["sbom_id"] != "sb-1" {
		t.Errorf("json = %v", got)
	}
}

func TestRender_TableGoesToWriter(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sbom_id":"sb-1","format":"cyclonedx","status":"active","counts":{"total":1}}`))
	}))
	defer srv.Close()

	out, _, err := runCapture(t, "sbom", "get", "sb-1", "--base-url", srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "sb-1") || !strings.Contains(out, "SBOM") {
		t.Errorf("table stdout missing expected content:\n%s", out)
	}
}

// TestMoreHint_GoesToStderr asserts the paging nudge lands on stderr (so it
// never contaminates piped JSON/table stdout consumed by tools).
func TestMoreHint_GoesToStderr(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A next_cursor with a table (default) output triggers the hint.
		_, _ = w.Write([]byte(`{"next_cursor":"c2","images":[{"repository":"r","counts":{"total":1}}]}`))
	}))
	defer srv.Close()

	out, errOut, err := runCapture(t, "images", "list", "--base-url", srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "more results available") {
		t.Errorf("hint leaked to stdout:\n%s", out)
	}
	if !strings.Contains(errOut, "more results available") {
		t.Errorf("hint missing from stderr:\n%s", errOut)
	}
}

// TestInvalidOutputFormat_FailsClosed confirms an unknown --output is rejected
// before any network call.
func TestInvalidOutputFormat_FailsClosed(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	_, _, err := runCapture(t, "sbom", "get", "sb-1", "-o", "yaml")
	if err == nil || !strings.Contains(err.Error(), "invalid --output") {
		t.Fatalf("want invalid --output error, got %v", err)
	}
}

func TestInvalidMinSeverity_FailsClosed(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	_, _, err := runCapture(t, "sbom", "findings", "sb-1", "--min-severity", "spicy")
	if err == nil || !strings.Contains(err.Error(), "invalid --min-severity") {
		t.Fatalf("want invalid --min-severity error, got %v", err)
	}
}

func TestInvalidLimit_FailsClosed(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	_, _, err := runCapture(t, "images", "list", "--limit", "0")
	if err == nil || !strings.Contains(err.Error(), "invalid --limit") {
		t.Fatalf("want invalid --limit error, got %v", err)
	}
}
