// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package pairing

import "sync"

// MemStore is an in-memory Store for tests.
type MemStore struct {
	mu    sync.Mutex
	items []Pairing
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{}
}

// List returns a copy of the stored pairings in the order they were first put.
func (m *MemStore) List() ([]Pairing, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Pairing, len(m.items))
	copy(out, m.items)
	return out, nil
}

// Put stores p, replacing any pairing with the same DBHash.
func (m *MemStore) Put(p Pairing) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.items {
		if m.items[i].DBHash == p.DBHash {
			m.items[i] = p
			return nil
		}
	}
	m.items = append(m.items, p)
	return nil
}
