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
	if fi, statErr := f.Stat(); statErr == nil && fi.Size() > max {
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
