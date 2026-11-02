// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package pairing

import "testing"

func TestMemStoreEmpty(t *testing.T) {
	s := NewMemStore()
	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got == nil {
		t.Fatal("List returned nil, want an empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("List returned %d pairings, want 0", len(got))
	}
}

func TestMemStorePutReplacesSameHash(t *testing.T) {
	var s Store = NewMemStore()
	if err := s.Put(Pairing{ID: "first", IDKey: "k1", IDSecret: "s1", DBHash: "hash-a", Created: "2026-11-02T10:00:00Z"}); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	if err := s.Put(Pairing{ID: "second", IDKey: "k2", IDSecret: "s2", DBHash: "hash-a", Created: "2026-11-02T11:00:00Z"}); err != nil {
		t.Fatalf("Put second: %v", err)
	}
	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List returned %d pairings, want 1: %+v", len(got), got)
	}
	if got[0].ID != "second" {
		t.Fatalf("List()[0].ID = %q, want %q", got[0].ID, "second")
	}
}

func TestMemStoreKeepsDifferentHashes(t *testing.T) {
	s := NewMemStore()
	for _, h := range []string{"hash-a", "hash-b"} {
		if err := s.Put(Pairing{ID: "id-" + h, DBHash: h}); err != nil {
			t.Fatalf("Put %s: %v", h, err)
		}
	}
	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d pairings, want 2: %+v", len(got), got)
	}
}
