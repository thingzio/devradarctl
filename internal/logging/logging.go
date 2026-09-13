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

// Package logging configures the process-wide structured logger for the CLI.
//
// Default level is Warn (quiet by default, per CLI convention); --debug lifts
// it to Debug. Output is a human-readable text handler on stderr unless JSON is
// requested (--log-json), in which case a JSON handler is used.
package logging

import (
	"log/slog"
	"os"
)

// Options controls logger construction.
type Options struct {
	// Debug lowers the level from Warn to Debug.
	Debug bool
	// JSON selects the JSON handler instead of the text handler.
	JSON bool
	// Version, when non-empty, is attached to every log entry.
	Version string
}

// Setup installs the default slog logger from opts and returns it. Level is
// Warn by default, Debug when opts.Debug is set.
func Setup(opts Options) *slog.Logger {
	level := slog.LevelWarn
	if opts.Debug {
		level = slog.LevelDebug
	}

	handlerOpts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if opts.JSON {
		handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, handlerOpts)
	}

	logger := slog.New(handler)
	if opts.Version != "" {
		logger = logger.With("version", opts.Version)
	}
	slog.SetDefault(logger)
	return logger
}
