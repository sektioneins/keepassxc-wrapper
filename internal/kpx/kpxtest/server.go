// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

// Package kpxtest is an in-process fake KeePassXC browser-integration server.
package kpxtest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/sektioneins/keepassxc-wrapper/internal/kpx"
)

var b64 = base64.StdEncoding

// Entry is a database entry together with the URLs it matches.
type Entry struct {
	kpx.Entry
	URLs []string
}

// Call is one request the server received.
type Call struct {
	Action string
	Inner  map[string]any
	Outer  map[string]any
}

// Server is a fake KeePassXC. Set the exported fields before the first Conn.
type Server struct {
	DBHash, AssociateName string
	Pairings              map[string]string // id -> idKey
	Entries               []Entry
	Locked                bool
	UnlockAfter           time.Duration // unlock this long after a triggerUnlock request
	DenyLogins            bool
	PushBefore            string // action pushed before every reply
	CloseOn               string // action on which the connection is dropped unanswered
	TOTP                  map[string]string

	mu    sync.Mutex
	calls []Call
}

// Calls returns the requests received so far.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// Conn returns the client end of a new connection served by the fake.
func (s *Server) Conn() net.Conn {
	cl, srv := net.Pipe()
	go s.serve(srv)
	return cl
}

type session struct {
	s          *Server
	conn       net.Conn
	wmu        sync.Mutex
	pub, sec   *[32]byte
	client     *[32]byte
	authed     bool
	unlockOnce sync.Once
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()
	pub, sec, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	ss := &session{s: s, conn: conn, pub: pub, sec: sec}
	dec := json.NewDecoder(conn)
	for {
		var outer map[string]any
		if err := dec.Decode(&outer); err != nil {
			return
		}
		if !ss.handle(outer) {
			return
		}
	}
}

func str(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

func (ss *session) write(msg map[string]any) bool {
	raw, _ := json.Marshal(msg)
	ss.wmu.Lock()
	defer ss.wmu.Unlock()
	_, err := ss.conn.Write(raw)
	return err == nil
}

func (ss *session) fail(action, code, text string) bool {
	return ss.write(map[string]any{"action": action, "error": text, "errorCode": code})
}

var errText = map[string]string{
	kpx.ErrDatabaseNotOpened: "Database not opened",
	kpx.ErrAssociationFailed: "KeePassXC association failed, try again",
	kpx.ErrNoLogins:          "No logins found",
}

func (ss *session) handle(outer map[string]any) bool {
	s := ss.s
	action := str(outer, "action")
	call := Call{Action: action, Outer: outer}
	nonce, err := b64.DecodeString(str(outer, "nonce"))
	if err != nil || len(nonce) != 24 {
		return ss.fail(action, "5", "bad nonce")
	}
	var inner map[string]any
	if action != "change-public-keys" {
		ct, _ := b64.DecodeString(str(outer, "message"))
		var n [24]byte
		copy(n[:], nonce)
		pt, ok := box.Open(nil, ct, &n, ss.client, ss.sec)
		if !ok || json.Unmarshal(pt, &inner) != nil {
			return ss.fail(action, "5", "cannot decrypt message")
		}
		call.Inner = inner
	}
	s.mu.Lock()
	s.calls = append(s.calls, call)
	closeNow := s.CloseOn != "" && s.CloseOn == action
	push := s.PushBefore
	s.mu.Unlock()
	if closeNow {
		return false
	}
	if push != "" && !ss.write(map[string]any{"action": push}) {
		return false
	}
	if action == "change-public-keys" {
		k, err := b64.DecodeString(str(outer, "publicKey"))
		if err != nil || len(k) != 32 {
			return ss.fail(action, "5", "bad public key")
		}
		ss.client = new([32]byte)
		copy(ss.client[:], k)
		return ss.write(map[string]any{"action": action, "version": "2.8.0",
			"publicKey": b64.EncodeToString(ss.pub[:]), "success": "true",
			"nonce": b64.EncodeToString(kpx.IncrementNonce(nonce))})
	}

	s.mu.Lock()
	reply, code := ss.dispatch(action, outer, inner)
	s.mu.Unlock()
	if code == kpx.ErrDatabaseNotOpened && (str(inner, "triggerUnlock") == "true" || str(outer, "triggerUnlock") == "true") {
		ss.scheduleUnlock()
	}
	if code != "" {
		return ss.fail(action, code, errText[code])
	}
	reply["action"] = action
	reply["version"] = "2.8.0"
	reply["success"] = "true"
	pt, _ := json.Marshal(reply)
	rn := kpx.IncrementNonce(nonce)
	var n [24]byte
	copy(n[:], rn)
	return ss.write(map[string]any{"action": action, "version": "2.8.0",
		"message": b64.EncodeToString(box.Seal(nil, pt, &n, ss.client, ss.sec)),
		"nonce":   b64.EncodeToString(rn)})
}

// scheduleUnlock unlocks the database after UnlockAfter and pushes
// database-unlocked, once per connection.
func (ss *session) scheduleUnlock() {
	s := ss.s
	s.mu.Lock()
	d := s.UnlockAfter
	s.mu.Unlock()
	if d <= 0 {
		return
	}
	ss.unlockOnce.Do(func() {
		time.AfterFunc(d, func() {
			s.mu.Lock()
			s.Locked = false
			s.mu.Unlock()
			ss.write(map[string]any{"action": "database-unlocked"})
		})
	})
}

// dispatch computes the reply body or an error code. s.mu is held.
func (ss *session) dispatch(action string, outer, inner map[string]any) (map[string]any, string) {
	s := ss.s
	if s.Locked {
		return nil, kpx.ErrDatabaseNotOpened
	}
	switch action {
	case "associate":
		if str(inner, "key") != b64.EncodeToString(ss.client[:]) {
			return nil, kpx.ErrAssociationFailed
		}
		if s.Pairings == nil {
			s.Pairings = map[string]string{}
		}
		s.Pairings[s.AssociateName] = str(inner, "idKey")
		return map[string]any{"id": s.AssociateName, "hash": s.DBHash}, ""
	case "test-associate":
		if k, ok := s.Pairings[str(inner, "id")]; !ok || k != str(inner, "key") {
			return nil, kpx.ErrAssociationFailed
		}
		ss.authed = true
		return map[string]any{"id": str(inner, "id"), "hash": s.DBHash}, ""
	case "get-databasehash":
		return map[string]any{"hash": s.DBHash}, ""
	case "get-logins":
		if !ss.authed {
			return nil, kpx.ErrAssociationFailed
		}
		var out []any
		url := str(inner, "url")
		for _, e := range s.Entries {
			if slices.Contains(e.URLs, url) {
				out = append(out, entryJSON(e.Entry))
			}
		}
		if s.DenyLogins || len(out) == 0 {
			return nil, kpx.ErrNoLogins
		}
		return map[string]any{"count": len(out), "entries": out, "hash": s.DBHash}, ""
	case "get-totp":
		if !ss.authed {
			return nil, kpx.ErrAssociationFailed
		}
		code, ok := s.TOTP[str(inner, "uuid")]
		if !ok {
			return nil, kpx.ErrNoLogins
		}
		return map[string]any{"totp": code}, ""
	}
	return nil, "4"
}

func entryJSON(e kpx.Entry) map[string]any {
	m := map[string]any{"uuid": e.UUID, "name": e.Name, "login": e.Login,
		"password": e.Password, "group": e.Group}
	if e.TOTP != "" {
		m["totp"] = e.TOTP
	}
	if e.Expired {
		m["expired"] = "true"
	}
	var sf []map[string]string
	for k, v := range e.Fields {
		sf = append(sf, map[string]string{k: v})
	}
	slices.SortFunc(sf, func(a, b map[string]string) int {
		for ka := range a {
			for kb := range b {
				return strings.Compare(ka, kb)
			}
		}
		return 0
	})
	if sf != nil {
		m["stringFields"] = sf
	}
	return m
}
