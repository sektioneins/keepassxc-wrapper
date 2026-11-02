// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package kpx_test

import (
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sektioneins/keepassxc-wrapper/internal/kpx"
	"github.com/sektioneins/keepassxc-wrapper/internal/kpx/kpxtest"
)

func within(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("did not finish within %s", d)
	}
}

func protoCode(t *testing.T, err error) string {
	t.Helper()
	var pe *kpx.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("want ProtocolError, got %v", err)
	}
	return pe.Code
}

func TestAssociateThenTestAssociate(t *testing.T) {
	f := newFake()
	f.AssociateName = "secure-kp-test"
	c := connect(t, f, kpx.Options{})
	id, hash, err := c.Associate("idkey-1")
	if err != nil {
		t.Fatal(err)
	}
	if id != "secure-kp-test" || hash != f.DBHash {
		t.Fatalf("id %q hash %q", id, hash)
	}
	if err := c.TestAssociate(id, "idkey-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.TestAssociate(id, "wrong"); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func fakeWithEntry(urls ...string) *kpxtest.Server {
	f := newFake()
	f.Pairings = map[string]string{"id1": "idk"}
	f.Entries = []kpxtest.Entry{{
		Entry: kpx.Entry{UUID: "u1", Name: "n", Login: "l", Password: "pw", Fields: map[string]string{"KPH: T": "tok"}},
		URLs:  urls,
	}}
	f.TOTP = map[string]string{"u1": "123456"}
	return f
}

func TestGetLoginsRequiresTestAssociate(t *testing.T) {
	c := connect(t, fakeWithEntry("secure-kp://p"), kpx.Options{})
	_, err := c.GetLogins("secure-kp://p", []kpx.Key{{ID: "id1", Key: "idk"}})
	if code := protoCode(t, err); code != "8" {
		t.Fatalf("code %q", code)
	}
}

func TestGetLoginsMatchesAdditionalURL(t *testing.T) {
	f := fakeWithEntry("https://example.org", "secure-kp://p")
	c := connect(t, f, kpx.Options{})
	if err := c.TestAssociate("id1", "idk"); err != nil {
		t.Fatal(err)
	}
	es, err := c.GetLogins("secure-kp://p", []kpx.Key{{ID: "id1", Key: "idk"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 || es[0].UUID != "u1" || es[0].Password != "pw" || es[0].Fields["KPH: T"] != "tok" {
		t.Fatalf("entries %+v", es)
	}
	calls := f.Calls()
	in := calls[len(calls)-1].Inner
	keys, _ := in["keys"].([]any)
	if in["url"] != "secure-kp://p" || len(keys) != 1 {
		t.Fatalf("inner %v", in)
	}
	k, _ := keys[0].(map[string]any)
	if k["id"] != "id1" || k["key"] != "idk" {
		t.Fatalf("keys %v", keys)
	}
}

func TestGetLoginsNoMatch(t *testing.T) {
	c := connect(t, fakeWithEntry("https://example.org"), kpx.Options{})
	if err := c.TestAssociate("id1", "idk"); err != nil {
		t.Fatal(err)
	}
	_, err := c.GetLogins("secure-kp://none", nil)
	if code := protoCode(t, err); code != "15" {
		t.Fatalf("code %q", code)
	}
}

func TestDatabaseHashUnlockFlow(t *testing.T) {
	f := newFake()
	f.Locked = true
	f.UnlockAfter = 50 * time.Millisecond
	c := connect(t, f, kpx.Options{})
	_, err := c.DatabaseHash(true)
	if code := protoCode(t, err); code != "1" {
		t.Fatalf("code %q", code)
	}
	if err := c.WaitUnlocked(time.Second); err != nil {
		t.Fatal(err)
	}
	h, err := c.DatabaseHash(false)
	if err != nil || h != f.DBHash {
		t.Fatalf("hash %q err %v", h, err)
	}
}

// With a tiny UnlockAfter the push must not overtake the error reply.
func TestUnlockPushNeverOvertakesErrorReply(t *testing.T) {
	for i := 0; i < 50; i++ {
		f := newFake()
		f.Locked = true
		f.UnlockAfter = time.Nanosecond
		c := connect(t, f, kpx.Options{})
		within(t, 2*time.Second, func() {
			if _, err := c.DatabaseHash(true); err == nil {
				t.Error("expected locked error")
				return
			}
			if err := c.WaitUnlocked(time.Second); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestWaitUnlockedTimeout(t *testing.T) {
	f := newFake()
	f.Locked = true
	c := connect(t, f, kpx.Options{})
	within(t, time.Second, func() {
		if err := c.WaitUnlocked(100 * time.Millisecond); err == nil {
			t.Error("expected error")
		}
	})
}

func TestConnectionClosedMidRequest(t *testing.T) {
	f := fakeWithEntry("secure-kp://p")
	f.CloseOn = "get-logins"
	c := connect(t, f, kpx.Options{})
	if err := c.TestAssociate("id1", "idk"); err != nil {
		t.Fatal(err)
	}
	within(t, time.Second, func() {
		if _, err := c.GetLogins("secure-kp://p", nil); err == nil {
			t.Error("expected error")
		}
	})
}

// The peer completes the handshake, reads the request and stays silent, so the
// read deadline (not the write deadline) fires.
func TestNoReplyTimesOut(t *testing.T) {
	cl, srv := net.Pipe()
	t.Cleanup(func() { cl.Close(); srv.Close() })
	f := newFake()
	// Serve the handshake through the fake, then go silent by proxying.
	fc := f.Conn()
	t.Cleanup(func() { fc.Close() })
	go proxyHandshake(srv, fc)
	c, err := kpx.NewClient(cl, kpx.Options{DialogTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	within(t, time.Second, func() {
		if _, _, err := c.Associate("k"); err == nil {
			t.Error("expected timeout")
		}
	})
}

// proxyHandshake forwards the first request/reply pair between a and the fake
// b, then reads (and discards) everything else from a without replying.
func proxyHandshake(a, b net.Conn) {
	da, db := json.NewDecoder(a), json.NewDecoder(b)
	var m json.RawMessage
	if da.Decode(&m) != nil {
		return
	}
	b.Write(m)
	if db.Decode(&m) != nil {
		return
	}
	a.Write(m)
	for da.Decode(&m) == nil {
	}
}

func TestGetTOTP(t *testing.T) {
	c := connect(t, fakeWithEntry("secure-kp://p"), kpx.Options{})
	if err := c.TestAssociate("id1", "idk"); err != nil {
		t.Fatal(err)
	}
	code, err := c.GetTOTP("u1")
	if err != nil || code != "123456" {
		t.Fatalf("code %q err %v", code, err)
	}
	if _, err := c.GetTOTP("nope"); err == nil {
		t.Fatal("expected error")
	}
}
