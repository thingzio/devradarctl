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

package sbom

import (
	"context"
	"strings"
	"testing"
)

func TestCapBuffer_UnderLimit(t *testing.T) {
	b := &capBuffer{max: 100}
	n, err := b.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if b.overflow {
		t.Error("overflow set under limit")
	}
	if b.String() != "hello" {
		t.Errorf("String = %q", b.String())
	}
}

func TestCapBuffer_TruncatesAtLimit(t *testing.T) {
	b := &capBuffer{max: 4}
	// Report full length consumed so os/exec's copy never blocks, but retain
	// only max bytes and flag overflow.
	n, err := b.Write([]byte("abcdef"))
	if err != nil || n != 6 {
		t.Fatalf("Write = %d, %v (want 6, nil)", n, err)
	}
	if !b.overflow {
		t.Error("overflow not set past limit")
	}
	if b.Len() != 4 || b.String() != "abcd" {
		t.Errorf("buffer = %q (len %d), want abcd", b.String(), b.Len())
	}

	// A subsequent write past a full buffer still reports consumed and stays capped.
	if n, _ := b.Write([]byte("ghi")); n != 3 {
		t.Errorf("second Write = %d, want 3", n)
	}
	if b.Len() != 4 {
		t.Errorf("buffer grew past cap: len %d", b.Len())
	}
}

func TestCapBuffer_ExactLimit(t *testing.T) {
	b := &capBuffer{max: 3}
	_, _ = b.Write([]byte("abc"))
	if b.overflow {
		t.Error("overflow set at exact limit")
	}
	if b.Bytes() == nil || b.String() != "abc" {
		t.Errorf("buffer = %q", b.String())
	}
}

func TestEnsureSyft_Missing(t *testing.T) {
	if err := EnsureSyft("/nonexistent/syft-binary"); err == nil {
		t.Fatal("expected error for missing syft")
	}
}

// TestGenerate_MissingSyft exercises Generate's fail-fast path without a real
// syft binary on PATH.
func TestGenerate_MissingSyft(t *testing.T) {
	_, err := Generate(context.Background(), "alpine@sha256:0", Options{SyftPath: "/nonexistent/syft"})
	if err == nil || !strings.Contains(err.Error(), "syft not found") {
		t.Fatalf("want 'syft not found', got %v", err)
	}
}
