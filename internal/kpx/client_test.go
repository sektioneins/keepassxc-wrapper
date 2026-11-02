// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package kpx_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/sektioneins/keepassxc-wrapper/internal/kpx"
	"github.com/sektioneins/keepassxc-wrapper/internal/kpx/kpxtest"
)

func newFake() *kpxtest.Server {
	return &kpxtest.Server{DBHash: "hash1", AssociateName: "test"}
}

func connect(t *testing.T, f *kpxtest.Server, opts kpx.Options) *kpx.Client {
	t.Helper()
	c, err := kpx.NewClient(f.Conn(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestHandshakeAndCall(t *testing.T) {
	c := connect(t, newFake(), kpx.Options{})
	if c.Version() != "2.8.0" {
		t.Fatalf("version %q", c.Version())
	}
	r, err := kpx.CallForTest(c, "get-databasehash", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if r["hash"] != "hash1" {
		t.Fatalf("reply %v", r)
	}
}

func TestCallSkipsUnsolicitedMessages(t *testing.T) {
	f := newFake()
	f.PushBefore = "database-locked"
	c := connect(t, f, kpx.Options{})
	r, err := kpx.CallForTest(c, "get-databasehash", map[string]any{})
	if err != nil || r["hash"] != "hash1" {
		t.Fatalf("reply %v, err %v", r, err)
	}
}

func TestCallReturnsProtocolError(t *testing.T) {
	f := newFake()
	f.Locked = true
	c := connect(t, f, kpx.Options{})
	_, err := kpx.CallForTest(c, "get-databasehash", map[string]any{})
	var pe *kpx.ProtocolError
	if !errors.As(err, &pe) || pe.Code != kpx.ErrDatabaseNotOpened {
		t.Fatalf("err %v", err)
	}
}

// A hand-rolled server answers one request with the unmodified request nonce.
func TestCallRejectsBadReplyNonce(t *testing.T) {
	cl, srv := net.Pipe()
	t.Cleanup(func() { cl.Close(); srv.Close() })
	go func() {
		dec := json.NewDecoder(srv)
		var m map[string]string
		if dec.Decode(&m) != nil {
			return
		}
		b64 := base64.StdEncoding
		pub, _, _ := box.GenerateKey(rand.Reader)
		nonce, _ := b64.DecodeString(m["nonce"])
		out, _ := json.Marshal(map[string]any{"action": "change-public-keys", "version": "2.8.0",
			"publicKey": b64.EncodeToString(pub[:]), "success": "true",
			"nonce": b64.EncodeToString(kpx.IncrementNonce(nonce))})
		srv.Write(out)
		if dec.Decode(&m) != nil {
			return
		}
		out, _ = json.Marshal(map[string]any{"action": m["action"], "message": "AAAA", "nonce": m["nonce"]})
		srv.Write(out)
	}()
	c, err := kpx.NewClient(cl, kpx.Options{ReplyTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kpx.CallForTest(c, "get-databasehash", map[string]any{}); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("err %v", err)
	}
}

func TestDebugOutputRedacted(t *testing.T) {
	f := newFake()
	f.Pairings = map[string]string{"id1": "idkey1"}
	f.Entries = []kpxtest.Entry{{
		Entry: kpx.Entry{UUID: "u1", Name: "n", Password: "s3cret-pw", Fields: map[string]string{"KPH: T": "s3cret-field"}},
		URLs:  []string{"secure-kp://p"},
	}}
	var dbg bytes.Buffer
	c := connect(t, f, kpx.Options{Debug: &dbg})
	if _, err := kpx.CallForTest(c, "test-associate", map[string]any{"id": "id1", "key": "idkey1"}); err != nil {
		t.Fatal(err)
	}
	r, err := kpx.CallForTest(c, "get-logins", map[string]any{"url": "secure-kp://p"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r["entries"])
	var es []kpx.Entry
	if err := json.Unmarshal(b, &es); err != nil || len(es) != 1 || es[0].Password != "s3cret-pw" || es[0].Fields["KPH: T"] != "s3cret-field" {
		t.Fatalf("entries %v, err %v", es, err)
	}
	out := dbg.String()
	for _, s := range []string{"s3cret-pw", "s3cret-field", "idkey1"} {
		if strings.Contains(out, s) {
			t.Fatalf("%q leaked in debug output:\n%s", s, out)
		}
	}
	if !strings.Contains(out, ">>>") || !strings.Contains(out, "<<<") {
		t.Fatalf("no wire lines:\n%s", out)
	}
}

func TestTriggerUnlockSentInnerAndOuter(t *testing.T) {
	f := newFake()
	c := connect(t, f, kpx.Options{})
	if _, err := kpx.CallForTest(c, "get-databasehash", map[string]any{}, kpx.TriggerUnlockForTest); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	last := calls[len(calls)-1]
	if last.Inner["triggerUnlock"] != "true" || last.Outer["triggerUnlock"] != "true" {
		t.Fatalf("inner %v outer %v", last.Inner, last.Outer)
	}
}

func TestUnlockPushAfterTrigger(t *testing.T) {
	f := newFake()
	f.Locked = true
	f.UnlockAfter = 10 * time.Millisecond
	c := connect(t, f, kpx.Options{})
	_, err := kpx.CallForTest(c, "get-databasehash", map[string]any{}, kpx.TriggerUnlockForTest)
	var pe *kpx.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("err %v", err)
	}
	if _, err := kpx.WaitForForTest(c, "database-unlocked", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := kpx.CallForTest(c, "get-databasehash", map[string]any{}); err != nil {
		t.Fatal(err)
	}
}

func TestCloseOnAndTimeoutDoNotHang(t *testing.T) {
	f := newFake()
	f.CloseOn = "get-databasehash"
	c := connect(t, f, kpx.Options{})
	if _, err := kpx.CallForTest(c, "get-databasehash", map[string]any{}); err == nil {
		t.Fatal("expected error on closed connection")
	}
	cl, srv := net.Pipe()
	t.Cleanup(func() { cl.Close(); srv.Close() })
	_, err := kpx.NewClient(cl, kpx.Options{ReplyTimeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("expected timeout")
	}
}
