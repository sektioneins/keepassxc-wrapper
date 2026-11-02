// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && cgo

package kpx

import (
	"path/filepath"
	"testing"
)

func TestDefaultSocketPath(t *testing.T) {
	p, err := DefaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(p) || filepath.Base(p) != "org.keepassxc.KeePassXC.BrowserServer" {
		t.Errorf("unexpected path %q", p)
	}
}
