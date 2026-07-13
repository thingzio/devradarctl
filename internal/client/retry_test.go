package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestGet_RetriesOn5xxThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(w, `{"error":"transient"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sbom_id":"sb-1"}`))
	}))
	defer srv.Close()

	got, err := New(srv.URL, "tok").GetSBOM(context.Background(), "sb-1", "")
	if err != nil {
		t.Fatalf("GetSBOM after retries: %v", err)
	}
	if got.SBOMID != "sb-1" {
		t.Errorf("decoded = %+v", got)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("server calls = %d, want 3 (2 failures + 1 success)", n)
	}
}

func TestGet_DoesNotRetry4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "tok").GetSBOM(context.Background(), "missing", ""); err == nil {
		t.Fatal("expected error on 404")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("server calls = %d, want 1 (404 is not retried)", n)
	}
}

func TestGet_RetriesOn429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 2 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, `{"error":"slow down"}`, http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sbom_id":"sb-1"}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "tok").GetSBOM(context.Background(), "sb-1", ""); err != nil {
		t.Fatalf("GetSBOM after 429 retry: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("server calls = %d, want 2", n)
	}
}

func TestGet_RetryGivesUpAndReturnsLastError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0") // keep the test fast
		http.Error(w, `{"error":"always down"}`, http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "tok").GetSBOM(context.Background(), "sb-1", "")
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if n := calls.Load(); n != maxGetAttempts {
		t.Errorf("server calls = %d, want %d", n, maxGetAttempts)
	}
}

func TestGet_ContextCancelStopsRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"down"}`, http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	if _, err := New(srv.URL, "tok").GetSBOM(ctx, "sb-1", ""); err == nil {
		t.Fatal("expected error with cancelled context")
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("2"); got != 2*time.Second {
		t.Errorf("delta-seconds = %v, want 2s", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("empty = %v, want 0", got)
	}
	if got := parseRetryAfter("garbage"); got != 0 {
		t.Errorf("garbage = %v, want 0", got)
	}
}
