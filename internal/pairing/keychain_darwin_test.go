// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && cgo && keychain

package pairing

import "testing"

// TestKeychainRoundTrip talks to the real login keychain, under a separate
// service name so that real pairings are never touched. Run it with
// `just test-keychain`; macOS may ask once to allow access.
func TestKeychainRoundTrip(t *testing.T) {
	old := service
	service = "secure-kp-test"
	t.Cleanup(func() { service = old })

	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := deleteItem(hash); err != nil {
		t.Fatalf("deleteItem before test: %v", err)
	}
	t.Cleanup(func() {
		if err := deleteItem(hash); err != nil {
			t.Errorf("deleteItem cleanup: %v", err)
		}
	})

	s := NewKeychainStore()
	first := Pairing{ID: "first", IDKey: "key-1", IDSecret: "secret-1", DBHash: hash, Created: "2026-11-02T10:00:00Z"}
	if err := s.Put(first); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	got, err := s.List()
	if err != nil {
		t.Fatalf("List after first Put: %v", err)
	}
	if len(got) != 1 || got[0] != first {
		t.Fatalf("List after first Put = %+v, want [%+v]", got, first)
	}

	second := Pairing{ID: "second", IDKey: "key-2", IDSecret: "secret = with spaces\nand ünïcode", DBHash: hash, Created: "2026-11-02T11:00:00Z"}
	if err := s.Put(second); err != nil {
		t.Fatalf("Put second: %v", err)
	}
	got, err = s.List()
	if err != nil {
		t.Fatalf("List after second Put: %v", err)
	}
	if len(got) != 1 || got[0] != second {
		t.Fatalf("List after second Put = %+v, want [%+v]", got, second)
	}

	if err := deleteItem(hash); err != nil {
		t.Fatalf("deleteItem: %v", err)
	}
	got, err = s.List()
	if err != nil {
		t.Fatalf("List after delete: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("List after delete = %#v, want an empty slice", got)
	}
}
