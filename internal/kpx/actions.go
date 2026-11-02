// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package kpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Key is an association (id and identification public key) sent with get-logins.
type Key struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// okReply fails unless the decrypted reply says success "true".
func okReply(action string, r map[string]any) error {
	if s, _ := r["success"].(string); s != "true" {
		return fmt.Errorf("keepassxc: %s was not successful", action)
	}
	return nil
}

func (c *Client) do(action string, inner map[string]any, timeout time.Duration, opts ...callOpt) (map[string]any, error) {
	r, err := c.call(action, inner, timeout, opts...)
	if err != nil {
		return nil, err
	}
	if err := okReply(action, r); err != nil {
		return nil, err
	}
	return r, nil
}

func replyString(action string, r map[string]any, field string) (string, error) {
	s, ok := r[field].(string)
	if !ok {
		return "", fmt.Errorf("keepassxc: %s reply has no %s", action, field)
	}
	return s, nil
}

// DatabaseHash returns the hash of the open database. With triggerUnlock a
// locked database makes KeePassXC show its unlock window; the call itself then
// fails with ErrDatabaseNotOpened.
func (c *Client) DatabaseHash(unlock bool) (string, error) {
	var opts []callOpt
	if unlock {
		opts = append(opts, triggerUnlock)
	}
	r, err := c.do("get-databasehash", nil, c.opts.ReplyTimeout, opts...)
	if err != nil {
		return "", err
	}
	return replyString("get-databasehash", r, "hash")
}

// WaitUnlocked waits for KeePassXC to announce that the database was unlocked.
func (c *Client) WaitUnlocked(timeout time.Duration) error {
	_, err := c.waitFor("database-unlocked", timeout)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("keepassxc: database stayed locked for %s", timeout)
	}
	return err
}

// Associate pairs with the open database. KeePassXC shows a dialog asking for
// a name. idKey is the base64 identification public key to register.
func (c *Client) Associate(idKey string) (id, hash string, err error) {
	r, err := c.do("associate", map[string]any{
		"key": b64.EncodeToString(c.pub[:]), "idKey": idKey}, c.opts.DialogTimeout)
	if err != nil {
		return "", "", err
	}
	if id, err = replyString("associate", r, "id"); err != nil {
		return "", "", err
	}
	if hash, err = replyString("associate", r, "hash"); err != nil {
		return "", "", err
	}
	return id, hash, nil
}

// TestAssociate proves to KeePassXC that this connection holds the pairing.
// get-logins and get-totp fail with error 8 on a connection that skipped it.
func (c *Client) TestAssociate(id, idKey string) error {
	_, err := c.do("test-associate", map[string]any{"id": id, "key": idKey}, c.opts.ReplyTimeout)
	return err
}

// GetLogins returns the entries matching url. KeePassXC may show a dialog.
func (c *Client) GetLogins(url string, keys []Key) ([]Entry, error) {
	if keys == nil {
		keys = []Key{}
	}
	r, err := c.do("get-logins", map[string]any{"url": url, "keys": keys}, c.opts.DialogTimeout)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r["entries"])
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err := json.Unmarshal(raw, &es); err != nil {
		return nil, fmt.Errorf("keepassxc: bad get-logins entries: %w", err)
	}
	return es, nil
}

// GetTOTP returns the current TOTP code of the entry with the given UUID.
func (c *Client) GetTOTP(uuid string) (string, error) {
	r, err := c.do("get-totp", map[string]any{"uuid": uuid}, c.opts.ReplyTimeout)
	if err != nil {
		return "", err
	}
	return replyString("get-totp", r, "totp")
}
