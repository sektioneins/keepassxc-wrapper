// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

// Package kpx implements the primitives of the KeePassXC browser protocol.
package kpx

import "fmt"

// Error codes returned by KeePassXC.
const (
	ErrDatabaseNotOpened = "1"
	ErrAssociationFailed = "8"
	ErrNoLogins          = "15"
)

// ProtocolError is an error reply from KeePassXC.
type ProtocolError struct {
	Action, Code, Message string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("keepassxc: %s failed with error %s: %s", e.Action, e.Code, e.Message)
}

// IncrementNonce returns a copy of n incremented as a little-endian number
// with carry, like libsodium's sodium_increment.
func IncrementNonce(n []byte) []byte {
	out := append([]byte(nil), n...)
	for i := range out {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}
