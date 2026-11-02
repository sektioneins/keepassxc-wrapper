// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

// Package pairing stores the KeePassXC identification keypairs ("pairings")
// that secure-kp creates with associate, one per database.
package pairing

// Pairing is one association with a KeePassXC database. IDSecret is the
// secret half of the identification keypair and must never be logged.
type Pairing struct {
	ID       string `json:"id"`
	IDKey    string `json:"idKey"`
	IDSecret string `json:"idSecret"`
	DBHash   string `json:"dbHash"`
	Created  string `json:"created"`
}

// Store keeps pairings, at most one per database hash.
type Store interface {
	// List returns every stored pairing. It returns an empty slice, not an
	// error, when there is none.
	List() ([]Pairing, error)
	// Put stores p, replacing any pairing with the same DBHash.
	Put(p Pairing) error
}
