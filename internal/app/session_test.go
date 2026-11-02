// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"strings"
	"testing"
	"time"

	"github.com/sektioneins/keepassxc-wrapper/internal/pairing"
)

func TestSessionNoPairing(t *testing.T) {
	te := newTestEnv(t, newFake())
	_, _, _, err := openSession(te.Env, globals{socket: "/s"})
	if err == nil || !strings.Contains(err.Error(), "secure-kp associate") {
		t.Fatalf("err = %v", err)
	}
}

func TestSessionWrongDatabase(t *testing.T) {
	te := newTestEnv(t, newFake())
	te.store.Put(pairing.Pairing{ID: "x", IDKey: "k", IDSecret: "s", DBHash: "other"})
	_, _, _, err := openSession(te.Env, globals{socket: "/s"})
	if err == nil || !strings.Contains(err.Error(), "not associated") {
		t.Fatalf("err = %v", err)
	}
}

func TestSessionSuccess(t *testing.T) {
	fake := newFake()
	te := newTestEnv(t, fake)
	if code := Main([]string{"associate"}, te.Env); code != 0 {
		t.Fatalf("associate: %s", te.errb.String())
	}
	te.errb.Reset()
	c, all, p, err := openSession(te.Env, globals{socket: "/s"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if len(all) != 1 || p.DBHash != fake.DBHash {
		t.Errorf("all=%v p=%v", all, p)
	}
}

func lockedSetup(t *testing.T, unlockAfter time.Duration) *testEnv {
	fake := newFake()
	te := newTestEnv(t, fake)
	if code := Main([]string{"associate"}, te.Env); code != 0 {
		t.Fatalf("associate: %s", te.errb.String())
	}
	te.errb.Reset()
	fake.Locked = true
	fake.UnlockAfter = unlockAfter
	return te
}

func TestSessionUnlocksThenAuthenticates(t *testing.T) {
	te := lockedSetup(t, 50*time.Millisecond)
	te.UnlockTimeout = 5 * time.Second
	c, _, _, err := openSession(te.Env, globals{socket: "/s"})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if !strings.Contains(te.errb.String(), "waiting for unlock") {
		t.Errorf("stderr %q", te.errb.String())
	}
}

func TestSessionUnlockTimeout(t *testing.T) {
	te := lockedSetup(t, 0)
	te.UnlockTimeout = 100 * time.Millisecond
	_, _, _, err := openSession(te.Env, globals{socket: "/s"})
	if err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("err = %v", err)
	}
}
