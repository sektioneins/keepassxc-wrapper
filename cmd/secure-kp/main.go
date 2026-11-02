// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

// Command secure-kp runs a command with secrets fetched from KeePassXC.
package main

import (
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/sektioneins/keepassxc-wrapper/internal/app"
	"github.com/sektioneins/keepassxc-wrapper/internal/kpx"
	"github.com/sektioneins/keepassxc-wrapper/internal/pairing"
)

func main() {
	home, _ := os.UserHomeDir() // on failure Home stays empty and app refuses to guess a config dir
	env := &app.Env{
		Stdout:        os.Stdout,
		Stderr:        os.Stderr,
		Getenv:        os.Getenv,
		Environ:       os.Environ(),
		Home:          home,
		Store:         pairing.NewKeychainStore(),
		Dial:          kpx.Dial,
		DefaultSocket: kpx.DefaultSocketPath,
		LookPath:      exec.LookPath,
		Exec:          syscall.Exec,
		Now:           time.Now,
		UnlockTimeout: 2 * time.Minute,
	}
	os.Exit(app.Main(os.Args[1:], env))
}
