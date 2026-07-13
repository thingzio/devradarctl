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
