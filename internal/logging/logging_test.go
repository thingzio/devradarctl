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

package logging

import (
	"context"
	"log/slog"
	"testing"
)

func TestSetup_DefaultWarn(t *testing.T) {
	l := Setup(Options{})
	if l == nil {
		t.Fatal("Setup returned nil")
	}
	// Warn is the default; Info must be below threshold, Warn at/above.
	if l.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info should be disabled at default warn level")
	}
	if !l.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("Warn should be enabled at default level")
	}
}

func TestSetup_DebugLiftsLevel(t *testing.T) {
	l := Setup(Options{Debug: true})
	if !l.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Debug should be enabled with Debug: true")
	}
}

func TestSetup_JSONAndVersion(t *testing.T) {
	// Exercise the JSON handler + version attachment paths.
	if l := Setup(Options{JSON: true, Version: "v1.2.3"}); l == nil {
		t.Fatal("Setup(JSON) returned nil")
	}
	// Setup installs the default logger; confirm it is usable.
	slog.Debug("noop")
}
