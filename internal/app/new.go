// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"flag"
	"fmt"
	"strings"

	"github.com/sektioneins/keepassxc-wrapper/internal/profile"
)

// newProfile creates a profile file from a lookup. Flags may come before or
// after the profile name.
func newProfile(e *Env, g globals, args []string) error {
	fs := flag.NewFlagSet("new", flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	fs.Usage = func() {}
	command := fs.String("command", "", "command to run (split on whitespace)")
	url := fs.String("url", "", "URL to look up (default secure-kp://<profile>)")
	force := fs.Bool("force", false, "overwrite an existing profile")
	if err := fs.Parse(args); err != nil {
		return usageError{"bad arguments for new"}
	}
	if fs.NArg() == 0 {
		return usageError{"new needs a profile name"}
	}
	name := fs.Arg(0)
	if err := fs.Parse(fs.Args()[1:]); err != nil {
		return usageError{"bad arguments for new"}
	}
	if fs.NArg() > 0 {
		return usageError{"new takes exactly one profile name"}
	}
	if err := profile.ValidName(name); err != nil {
		return usageError{err.Error()}
	}
	u := *url
	if u == "" {
		u = "secure-kp://" + name
	}

	f, err := fetchFound(e, g, u)
	if err != nil {
		return err
	}
	data, err := profile.Generate(profile.GenInput{
		Name: name, URL: u, Command: strings.Fields(*command), Found: f,
		Cmdline: "secure-kp new " + strings.Join(args, " "), Now: e.Now(),
	})
	if err != nil {
		return err
	}
	dir := profile.Dir(e.Getenv, e.Home)
	if err := profile.Write(dir, name, data, *force); err != nil {
		return err
	}
	path, err := profile.Path(dir, name)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.Stderr, "secure-kp: wrote %s; edit it, then run: secure-kp %s\n", path, name)
	return nil
}
