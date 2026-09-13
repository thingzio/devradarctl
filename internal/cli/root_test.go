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
	"context"
	"strings"
	"testing"
)

// runArgs runs the CLI with the given args and returns the resulting error.
func runArgs(t *testing.T, args ...string) error {
	t.Helper()
	cmd := New("test", "abc123", "today")
	return cmd.Run(context.Background(), append([]string{name}, args...))
}

func TestSubmit_RequiresFileOrImage(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	err := runArgs(t, "submit")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("want 'required' error, got %v", err)
	}
}

func TestSubmit_FileAndImageMutuallyExclusive(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	err := runArgs(t, "submit", "--file", "x.json", "--image", "alpine")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want 'mutually exclusive' error, got %v", err)
	}
}

func TestSubmit_MissingFile(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	err := runArgs(t, "submit", "--file", "/no/such/sbom.json")
	if err == nil || !strings.Contains(err.Error(), "read SBOM file") {
		t.Fatalf("want read error, got %v", err)
	}
}
