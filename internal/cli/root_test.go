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
