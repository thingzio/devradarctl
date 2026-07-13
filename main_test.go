package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

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
