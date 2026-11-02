// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"fmt"
	"time"

	"github.com/sektioneins/keepassxc-wrapper/internal/kpx"
	"github.com/sektioneins/keepassxc-wrapper/internal/pairing"
)

const defaultUnlockTimeout = 2 * time.Minute

// databaseHash asks for the open database's hash. A locked database makes
// KeePassXC show its unlock window; this waits for the unlock.
func databaseHash(e *Env, c *kpx.Client) (string, error) {
	hash, err := c.DatabaseHash(true)
	var pe *kpx.ProtocolError
	if !errors.As(err, &pe) || pe.Code != kpx.ErrDatabaseNotOpened {
		return hash, err
	}
	fmt.Fprintln(e.Stderr, "secure-kp: database locked, waiting for unlock…")
	timeout := e.UnlockTimeout
	if timeout == 0 {
		timeout = defaultUnlockTimeout
	}
	if err := c.WaitUnlocked(timeout); err != nil {
		return "", err
	}
	return c.DatabaseHash(false)
}

// openSession connects, waits for an unlocked database, picks the matching
// pairing and authenticates with it. On success the caller closes the client.
// The slice holds all stored pairings.
func openSession(e *Env, g globals) (*kpx.Client, []pairing.Pairing, pairing.Pairing, error) {
	var none pairing.Pairing
	all, err := e.Store.List()
	if err != nil {
		return nil, nil, none, err
	}
	if len(all) == 0 {
		return nil, nil, none, errors.New("no pairing; run secure-kp associate")
	}
	c, err := dial(e, g)
	if err != nil {
		return nil, nil, none, err
	}
	hash, err := databaseHash(e, c)
	if err != nil {
		c.Close()
		return nil, nil, none, err
	}
	for _, p := range all {
		if p.DBHash != hash {
			continue
		}
		if err := c.TestAssociate(p.ID, p.IDKey); err != nil {
			c.Close()
			var pe *kpx.ProtocolError
			if errors.As(err, &pe) && pe.Code == kpx.ErrAssociationFailed {
				err = fmt.Errorf("KeePassXC no longer knows the pairing %q; run secure-kp associate", p.ID)
			}
			return nil, nil, none, err
		}
		return c, all, p, nil
	}
	c.Close()
	return nil, nil, none, errors.New("the open database is not associated; run secure-kp associate")
}
