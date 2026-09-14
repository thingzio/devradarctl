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

package main

import (
	"bytes"
	"errors"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestResolveBuildInfo_BackfillsFromModuleVersion(t *testing.T) {
	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.1.2"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "77eeb7391a1c0d2e5f6a7b8c9d0e1f2a3b4c5d6e"},
			{Key: "vcs.time", Value: "2026-09-13T14:40:23Z"},
		},
	}
	v, c, d := resolveBuildInfo(devVersion, devCommit, devDate, bi)
	if v != "v0.1.2" {
		t.Errorf("version = %q, want v0.1.2", v)
	}
	if c != "77eeb73" {
		t.Errorf("commit = %q, want short revision 77eeb73", c)
	}
	if d != "2026-09-13T14:40:23Z" {
		t.Errorf("date = %q, want vcs.time", d)
	}
}

func TestResolveBuildInfo_KeepsLdflagValues(t *testing.T) {
	bi := &debug.BuildInfo{
		Main:     debug.Module{Version: "v0.1.2"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "deadbeefdeadbeef"}},
	}
	v, c, d := resolveBuildInfo("v0.4.0", "77eeb73", "2026-09-13T14:40:23Z", bi)
	if v != "v0.4.0" || c != "77eeb73" || d != "2026-09-13T14:40:23Z" {
		t.Errorf("ldflag values overwritten: %q %q %q", v, c, d)
	}
}

func TestResolveBuildInfo_MarksDirtyTree(t *testing.T) {
	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "77eeb7391a1c0d2e"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	v, c, _ := resolveBuildInfo(devVersion, devCommit, devDate, bi)
	if v != devVersion {
		t.Errorf("version = %q, want %q for a (devel) module", v, devVersion)
	}
	if c != "77eeb73-dirty" {
		t.Errorf("commit = %q, want 77eeb73-dirty", c)
	}
}

func TestResolveBuildInfo_NoBuildInfo(t *testing.T) {
	v, c, d := resolveBuildInfo(devVersion, devCommit, devDate, nil)
	if v != devVersion || c != devCommit || d != devDate {
		t.Errorf("defaults changed without build info: %q %q %q", v, c, d)
	}
}

func TestExitCode_Nil(t *testing.T) {
	var buf bytes.Buffer
	if got := exitCode(&buf, nil); got != 0 {
		t.Errorf("exitCode(nil) = %d, want 0", got)
	}
	if buf.Len() != 0 {
		t.Errorf("nil error should print nothing, got %q", buf.String())
	}
}

func TestExitCode_GenericError(t *testing.T) {
	var buf bytes.Buffer
	if got := exitCode(&buf, errors.New("boom")); got != 1 {
		t.Errorf("exitCode(err) = %d, want 1", got)
	}
	if !strings.Contains(buf.String(), "error: boom") {
		t.Errorf("stderr = %q", buf.String())
	}
}

func TestExitCode_HonorsExitCoder(t *testing.T) {
	var buf bytes.Buffer
	// cli.Exit with a non-zero code and no message (the findings/attestation gate).
	if got := exitCode(&buf, cli.Exit("", 2)); got != 2 {
		t.Errorf("exitCode(ExitCoder 2) = %d, want 2", got)
	}
	// Empty message must not print a bare "error:" line.
	if buf.Len() != 0 {
		t.Errorf("empty-message ExitCoder should print nothing, got %q", buf.String())
	}
}

func TestExitCode_ExitCoderWithMessage(t *testing.T) {
	var buf bytes.Buffer
	if got := exitCode(&buf, cli.Exit("nope", 3)); got != 3 {
		t.Errorf("exitCode = %d, want 3", got)
	}
	if !strings.Contains(buf.String(), "nope") {
		t.Errorf("stderr = %q", buf.String())
	}
}
