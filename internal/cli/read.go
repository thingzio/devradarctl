package cli

import (
	"fmt"
	"io"
	"os"
)

// readFileLimit reads path but fails if it exceeds max bytes, so an
// accidentally-huge (or hostile) file can't be slurped whole into memory before
// the size is ever checked. what names the input for the error message.
func readFileLimit(path, what string, max int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path is a user-supplied CLI arg by design
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	defer func() { _ = f.Close() }()

	// Stat is advisory (a pipe/proc file may report 0); the LimitReader below is
	// the real enforcement, so we don't trust size alone.
	if fi, err := f.Stat(); err == nil && fi.Size() > max {
		return nil, fmt.Errorf("%s is %d bytes, exceeds the %d-byte limit", what, fi.Size(), max)
	}

	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", what, max)
	}
	return b, nil
}
