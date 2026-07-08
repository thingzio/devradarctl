// Package logging configures the process-wide structured logger for the CLI.
//
// Default level is Warn (quiet by default, per CLI convention); --debug lifts
// it to Debug. Output is a human-readable text handler on stderr unless JSON is
// requested, in which case it matches the devradar server's JSON convention.
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
