// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package kpx

import (
	"bytes"
	"encoding/json"
	"testing"
)

func assertEq(t *testing.T, got, want any) {
	t.Helper()
	if b, ok := got.([]byte); ok {
		if !bytes.Equal(b, want.([]byte)) {
			t.Fatalf("got %v, want %v", got, want)
		}
		return
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Fatalf("got %s, want %s", g, w)
	}
}

func TestIncrementNonce(t *testing.T) {
	// verified against KeePassXC 2.8.0: "JP57ya…" → "Jf57ya…" (first byte 0x24 → 0x25)
	assertEq(t, IncrementNonce([]byte{0x24, 0, 0}), []byte{0x25, 0, 0})
	assertEq(t, IncrementNonce([]byte{0xff, 0xff, 0x01}), []byte{0, 0, 0x02})
	assertEq(t, IncrementNonce([]byte{0xff, 0xff}), []byte{0, 0})
	in := []byte{1}
	IncrementNonce(in)
	assertEq(t, in, []byte{1}) // input untouched
}

func TestProtocolErrorCodeStringOrNumber(t *testing.T) {
	for _, js := range []string{`{"errorCode":"8"}`, `{"errorCode":8}`} {
		var e ProtocolError
		if err := json.Unmarshal([]byte(js), &e); err != nil {
			t.Fatal(err)
		}
		assertEq(t, e.Code, "8")
	}
	e := &ProtocolError{Action: "get-logins", Code: ErrNoLogins, Message: "No logins found"}
	if e.Error() == "" {
		t.Fatal("empty message")
	}
}
