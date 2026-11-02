// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"text/tabwriter"

	"github.com/sektioneins/keepassxc-wrapper/internal/profile"
)

// list prints the profiles without contacting KeePassXC.
func list(e *Env) error {
	dir, err := configDir(e)
	if err != nil {
		return err
	}
	sums, err := profile.List(dir)
	if err != nil {
		return err
	}
	if len(sums) == 0 {
		fmt.Fprintf(e.Stderr, "secure-kp: no profiles in %s\nsecure-kp: create one with: secure-kp new <profile>\n", dir)
		return nil
	}
	tw := tabwriter.NewWriter(e.Stdout, 0, 8, 2, ' ', 0)
	for _, s := range sums {
		n := "secrets"
		if s.Secrets == 1 {
			n = "secret"
		}
		line := fmt.Sprintf("%s\t%s\t%s\t%d %s", s.Name, s.Command, s.URL, s.Secrets, n)
		if s.Problem != "" {
			line += "\t(" + s.Problem + ")"
		}
		fmt.Fprintln(tw, line)
	}
	return tw.Flush()
}
