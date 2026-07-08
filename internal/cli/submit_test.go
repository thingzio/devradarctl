package cli

import (
	"strings"
	"testing"
)

func TestResolveToken_Env(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "  env-tok  ")
	got, err := resolveToken(strings.NewReader(""))
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "env-tok" {
		t.Errorf("token = %q, want env-tok (trimmed)", got)
	}
}

func TestResolveToken_Stdin(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "")
	got, err := resolveToken(strings.NewReader("piped-tok\n"))
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "piped-tok" {
		t.Errorf("token = %q, want piped-tok", got)
	}
}

func TestResolveToken_EnvBeatsStdin(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "env-tok")
	got, err := resolveToken(strings.NewReader("piped-tok"))
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "env-tok" {
		t.Errorf("token = %q, want env to win", got)
	}
}

func TestResolveToken_Missing(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "")
	// A nil reader stands in for a TTY (no piped data).
	if _, err := resolveToken(nil); err == nil {
		t.Fatal("expected error when no token and no stdin, got nil")
	}
}

func TestResolveToken_EmptyStdin(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "")
	if _, err := resolveToken(strings.NewReader("   \n")); err == nil {
		t.Fatal("expected error on whitespace-only stdin, got nil")
	}
}
