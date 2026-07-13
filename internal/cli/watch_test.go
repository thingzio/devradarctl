package cli

import (
	"context"
	"fmt"
	"testing"
)

// mkRows builds newest-first watchRows from RFC3339 timestamps.
func mkRows(ts ...string) []watchRow {
	rows := make([]watchRow, 0, len(ts))
	for _, t := range ts {
		rows = append(rows, watchRow{key: t, line: t, at: parseAt(t)})
	}
	return rows
}

func TestWatcher_PrimeThenOnlyNew(t *testing.T) {
	w := newWatcher()
	page := mkRows("2024-01-03T00:00:00Z", "2024-01-02T00:00:00Z", "2024-01-01T00:00:00Z")
	fetch := func(_ context.Context, cursor string) ([]watchRow, string, error) {
		return page, "", nil
	}

	// Prime: returns current rows, marks them seen.
	primed, err := w.poll(context.Background(), fetch)
	if err != nil {
		t.Fatalf("prime: %v", err)
	}
	if len(primed) != 3 {
		t.Fatalf("prime returned %d rows, want 3", len(primed))
	}

	// A second identical poll yields nothing new.
	again, err := w.poll(context.Background(), fetch)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("re-poll returned %d rows, want 0", len(again))
	}
}

func TestWatcher_EmitsChronological(t *testing.T) {
	w := newWatcher()
	fetch := func(_ context.Context, _ string) ([]watchRow, string, error) {
		return mkRows("2024-01-05T00:00:00Z", "2024-01-04T00:00:00Z"), "", nil
	}
	got, err := w.poll(context.Background(), fetch)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	// Newest-first input must be emitted oldest-first.
	if got[0].at.After(got[1].at) {
		t.Errorf("not chronological: %s then %s", got[0].line, got[1].line)
	}
}

// TestWatcher_BurstAcrossPages ensures events spanning more than one page are
// all captured in a single poll (the burst-loss bug).
func TestWatcher_BurstAcrossPages(t *testing.T) {
	w := newWatcher()
	// Prime with an empty state so the watermark is zero and paging runs to end.
	pages := map[string]struct {
		rows []watchRow
		next string
	}{
		"":   {mkRows("2024-02-02T00:00:00Z", "2024-02-01T12:00:00Z"), "c1"},
		"c1": {mkRows("2024-02-01T06:00:00Z", "2024-02-01T00:00:00Z"), ""},
	}
	fetch := func(_ context.Context, cursor string) ([]watchRow, string, error) {
		p := pages[cursor]
		return p.rows, p.next, nil
	}
	got, err := w.poll(context.Background(), fetch)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("burst across 2 pages returned %d rows, want 4", len(got))
	}
}

func TestWatcher_BoundedSeen(t *testing.T) {
	w := newWatcher()
	// Push more distinct keys than the cap; the set must not exceed it.
	for i := range maxSeenKeys + 100 {
		w.markSeen(fmt.Sprintf("k%d", i))
	}
	if len(w.seen) > maxSeenKeys {
		t.Errorf("seen set = %d, want <= %d", len(w.seen), maxSeenKeys)
	}
	if len(w.order) > maxSeenKeys {
		t.Errorf("order slice = %d, want <= %d", len(w.order), maxSeenKeys)
	}
}

func TestWatch_RejectsShortInterval(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	err := runArgs(t, "watch", "sb-1", "--interval", "0s")
	if err == nil {
		t.Fatal("expected error on zero interval")
	}
}
