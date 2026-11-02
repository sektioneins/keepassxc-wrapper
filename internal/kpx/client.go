// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package kpx

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const (
	defaultReplyTimeout  = 30 * time.Second
	defaultDialogTimeout = 5 * time.Minute
)

var b64 = base64.StdEncoding

// Options configures a Client.
type Options struct {
	// Debug receives every wire message, secrets redacted. Nil disables it.
	Debug io.Writer
	// ReplyTimeout bounds an ordinary reply (default 30 s). DialogTimeout
	// bounds a reply that waits for a user dialog (default 5 min).
	ReplyTimeout, DialogTimeout time.Duration
}

// Client is one encrypted connection to KeePassXC.
type Client struct {
	conn     net.Conn
	dec      *json.Decoder
	pub, sec *[32]byte
	server   *[32]byte
	clientID string
	version  string
	opts     Options
}

// callOpt modifies a single call.
type callOpt func(*callCfg)

type callCfg struct{ triggerUnlock bool }

// triggerUnlock asks KeePassXC to show its unlock window. It is sent in both
// the inner message and the outer envelope.
func triggerUnlock(c *callCfg) { c.triggerUnlock = true }

// Dial connects to the KeePassXC socket and performs the key exchange.
func Dial(socketPath string, opts Options) (*Client, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to %s: %w (is KeePassXC running with browser integration enabled?)", socketPath, err)
	}
	return NewClient(conn, opts)
}

// NewClient runs the key exchange on conn. On error it closes conn.
func NewClient(conn net.Conn, opts Options) (*Client, error) {
	if opts.ReplyTimeout <= 0 {
		opts.ReplyTimeout = defaultReplyTimeout
	}
	if opts.DialogTimeout <= 0 {
		opts.DialogTimeout = defaultDialogTimeout
	}
	pub, sec, err := box.GenerateKey(rand.Reader)
	if err != nil {
		conn.Close()
		return nil, err
	}
	idBytes, err := randomBytes(24)
	if err != nil {
		conn.Close()
		return nil, err
	}
	c := &Client{conn: conn, dec: json.NewDecoder(conn), pub: pub, sec: sec,
		clientID: b64.EncodeToString(idBytes), opts: opts}
	if err := c.changePublicKeys(); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Version returns the KeePassXC version reported during the key exchange.
func (c *Client) Version() string { return c.version }

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (c *Client) debug(dir string, raw []byte) {
	if c.opts.Debug != nil {
		fmt.Fprintf(c.opts.Debug, "%s %s\n", dir, Redact(raw))
	}
}

func (c *Client) send(msg map[string]any, timeout time.Duration) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	c.debug(">>>", raw)
	c.conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := c.conn.Write(raw); err != nil {
		return fmt.Errorf("keepassxc: write: %w", err)
	}
	return nil
}

// recv reads messages until one has the given action and returns its raw JSON.
// Unsolicited messages with another action are skipped.
func (c *Client) recv(action string, timeout time.Duration) (json.RawMessage, error) {
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		var raw json.RawMessage
		if err := c.dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("keepassxc: waiting for %s: %w", action, err)
		}
		c.debug("<<<", raw)
		var head struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			return nil, fmt.Errorf("keepassxc: bad message: %w", err)
		}
		if head.Action == action {
			return raw, nil
		}
	}
}

func (c *Client) changePublicKeys() error {
	nonce, err := randomBytes(24)
	if err != nil {
		return err
	}
	const action = "change-public-keys"
	err = c.send(map[string]any{"action": action, "publicKey": b64.EncodeToString(c.pub[:]),
		"nonce": b64.EncodeToString(nonce), "clientID": c.clientID}, c.opts.ReplyTimeout)
	if err != nil {
		return err
	}
	raw, err := c.recv(action, c.opts.ReplyTimeout)
	if err != nil {
		return err
	}
	if perr := protocolError(raw); perr != nil {
		return perr
	}
	var r struct {
		PublicKey, Nonce, Version, Success string
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("keepassxc: bad %s reply: %w", action, err)
	}
	if r.Success != "true" {
		return fmt.Errorf("keepassxc: %s was not successful", action)
	}
	if err := checkNonce(r.Nonce, nonce); err != nil {
		return err
	}
	k, err := b64.DecodeString(r.PublicKey)
	if err != nil || len(k) != 32 {
		return errors.New("keepassxc: bad server public key")
	}
	c.server = new([32]byte)
	copy(c.server[:], k)
	c.version = r.Version
	return nil
}

// protocolError returns the error carried by an error reply, or nil.
func protocolError(raw []byte) *ProtocolError {
	var probe struct {
		Error     string          `json:"error"`
		ErrorCode json.RawMessage `json:"errorCode"`
	}
	if json.Unmarshal(raw, &probe) != nil || (probe.Error == "" && len(probe.ErrorCode) == 0) {
		return nil
	}
	var pe ProtocolError
	if err := json.Unmarshal(raw, &pe); err != nil {
		return &ProtocolError{Message: probe.Error}
	}
	return &pe
}

func checkNonce(got string, request []byte) error {
	rn, err := b64.DecodeString(got)
	if err != nil || !bytes.Equal(rn, IncrementNonce(request)) {
		return errors.New("keepassxc: reply nonce is not the incremented request nonce")
	}
	return nil
}

// call sends an encrypted request and returns the decrypted reply.
func (c *Client) call(action string, inner map[string]any, timeout time.Duration, opts ...callOpt) (map[string]any, error) {
	var cfg callCfg
	for _, o := range opts {
		o(&cfg)
	}
	msg := make(map[string]any, len(inner)+2)
	maps.Copy(msg, inner)
	msg["action"] = action
	if cfg.triggerUnlock {
		msg["triggerUnlock"] = "true"
	}
	plain, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	c.debug(">>> (inner)", plain)
	nb, err := randomBytes(24)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	copy(nonce[:], nb)
	outer := map[string]any{"action": action, "message": b64.EncodeToString(box.Seal(nil, plain, &nonce, c.server, c.sec)),
		"nonce": b64.EncodeToString(nonce[:]), "clientID": c.clientID}
	if cfg.triggerUnlock {
		outer["triggerUnlock"] = "true"
	}
	if err := c.send(outer, timeout); err != nil {
		return nil, err
	}
	raw, err := c.recv(action, timeout)
	if err != nil {
		return nil, err
	}
	if perr := protocolError(raw); perr != nil {
		if perr.Action == "" {
			perr.Action = action
		}
		return nil, perr
	}
	var r struct{ Message, Nonce string }
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("keepassxc: bad %s reply: %w", action, err)
	}
	if err := checkNonce(r.Nonce, nonce[:]); err != nil {
		return nil, err
	}
	ct, err := b64.DecodeString(r.Message)
	if err != nil {
		return nil, fmt.Errorf("keepassxc: bad %s reply: %w", action, err)
	}
	var rn [24]byte
	copy(rn[:], IncrementNonce(nonce[:]))
	pt, ok := box.Open(nil, ct, &rn, c.server, c.sec)
	if !ok {
		return nil, fmt.Errorf("keepassxc: cannot decrypt %s reply", action)
	}
	c.debug("<<< (inner)", pt)
	var out map[string]any
	if err := json.Unmarshal(pt, &out); err != nil {
		return nil, fmt.Errorf("keepassxc: bad %s reply: %w", action, err)
	}
	return out, nil
}

// waitFor blocks until an unsolicited message with the given action arrives.
func (c *Client) waitFor(action string, timeout time.Duration) (map[string]any, error) {
	raw, err := c.recv(action, timeout)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
