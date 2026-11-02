// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/sektioneins/keepassxc-wrapper/internal/pairing"
)

// associate pairs secure-kp with the open KeePassXC database and stores the
// new identification keypair.
func associate(e *Env, g globals) error {
	c, err := dial(e, g)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := databaseHash(e, c); err != nil {
		return err
	}
	pub, sec, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	enc := base64.StdEncoding
	idKey := enc.EncodeToString(pub[:])
	id, hash, err := c.Associate(idKey)
	if err != nil {
		return err
	}
	err = e.Store.Put(pairing.Pairing{
		ID: id, IDKey: idKey, IDSecret: enc.EncodeToString(sec[:]),
		DBHash: hash, Created: e.Now().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	short := hash
	if len(short) > 12 {
		short = short[:12]
	}
	fmt.Fprintf(e.Stderr, "associated with database %s… as %q\n", short, id)
	return nil
}
