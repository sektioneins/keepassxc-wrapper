// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

// Package app implements the secure-kp command line.
package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/sektioneins/keepassxc-wrapper/internal/kpx"
	"github.com/sektioneins/keepassxc-wrapper/internal/pairing"
	"github.com/sektioneins/keepassxc-wrapper/internal/profile"
)

// Env carries everything the commands need from the outside world, so tests
// can replace it.
type Env struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Environ        []string
	Home           string
	Store          pairing.Store
	Dial           func(socketPath string, opts kpx.Options) (*kpx.Client, error)
	DefaultSocket  func() (string, error)
	LookPath       func(string) (string, error)
	Exec           func(path string, argv, env []string) error
	Now            func() time.Time
	// UnlockTimeout bounds the wait for a locked database. Zero means 2 minutes.
	UnlockTimeout time.Duration
}

// globals are the parsed global flags.
type globals struct {
	socket  string
	verbose bool
}

const usageText = `secure-kp: run commands with secrets from KeePassXC
Copyright 2026 SektionEins GmbH, https://github.com/sektioneins/keepassxc-wrapper

usage:
  secure-kp [-v] [-socket PATH] <profile> [args...]   run a profile
  secure-kp associate                                 pair with the open KeePassXC database
  secure-kp lookup <url>                              list matching entries (names, UUIDs, fields; never values)
  secure-kp new <profile> [--command CMD] [--url URL] [--force]
                                                      create a profile from a lookup
  secure-kp list                                      list profiles without contacting KeePassXC
`

// usageError marks an error that makes Main print the usage and exit 2.
type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

// Main runs secure-kp with the arguments after the program name and returns
// the exit code.
func Main(args []string, e *Env) int {
	fs := flag.NewFlagSet("secure-kp", flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	fs.Usage = func() {}
	var g globals
	fs.BoolVar(&g.verbose, "v", false, "write messages exchanged with KeePassXC to stderr, secrets masked")
	fs.StringVar(&g.socket, "socket", "", "KeePassXC socket path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(e.Stdout, usageText)
			return 0
		}
		fmt.Fprint(e.Stderr, usageText)
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(e.Stderr, "secure-kp: missing profile or command")
		fmt.Fprint(e.Stderr, usageText)
		return 2
	}

	var err error
	switch name, sub := rest[0], rest[1:]; {
	case !slices.Contains(profile.Reserved, name):
		err = runProfile(e, g, name, sub)
	case name == "lookup":
		err = lookup(e, g, sub)
	case name == "new":
		err = newProfile(e, g, sub)
	default:
		if len(sub) > 0 {
			err = usageError{fmt.Sprintf("%s takes no arguments", name)}
		} else if name == "associate" {
			err = associate(e, g)
		} else {
			err = list(e)
		}
	}

	var ue usageError
	var xe exitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		fmt.Fprintf(e.Stderr, "secure-kp: %s\n", ue.msg)
		fmt.Fprint(e.Stderr, usageText)
		return 2
	case errors.As(err, &xe):
		fmt.Fprintf(e.Stderr, "secure-kp: %s\n", xe.msg)
		return xe.code
	default:
		fmt.Fprintf(e.Stderr, "secure-kp: %s\n", err)
		return 1
	}
}

// dial connects to KeePassXC. The socket comes from -socket, then
// SECURE_KP_SOCKET, then the default location.
func dial(e *Env, g globals) (*kpx.Client, error) {
	sock := g.socket
	if sock == "" {
		sock = e.Getenv("SECURE_KP_SOCKET")
	}
	if sock == "" {
		var err error
		if sock, err = e.DefaultSocket(); err != nil {
			return nil, err
		}
	}
	var opts kpx.Options
	if g.verbose {
		opts.Debug = e.Stderr
	}
	return e.Dial(sock, opts)
}
