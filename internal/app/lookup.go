// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sektioneins/keepassxc-wrapper/internal/kpx"
	"github.com/sektioneins/keepassxc-wrapper/internal/profile"
)

// found lists the usable fields of each entry, sorted by name, then uuid. It
// never copies a value.
func found(entries []kpx.Entry) []profile.Found {
	out := make([]profile.Found, 0, len(entries))
	for _, en := range entries {
		f := profile.Found{Name: en.Name, Group: en.Group, UUID: en.UUID, Expired: en.Expired, Fields: []string{"password"}}
		if en.Login != "" {
			f.Fields = append(f.Fields, "username")
		}
		if en.TOTP != "" {
			f.Fields = append(f.Fields, "totp")
		}
		var kph []string
		for k := range en.Fields {
			if strings.HasPrefix(k, "KPH: ") {
				kph = append(kph, k)
			}
		}
		slices.Sort(kph)
		f.Fields = append(f.Fields, kph...)
		out = append(out, f)
	}
	slices.SortStableFunc(out, func(a, b profile.Found) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.UUID, b.UUID))
	})
	return out
}

// formatLookup renders the lookup output, one line per entry plus a summary.
func formatLookup(url string, f []profile.Found) string {
	return strings.Join(profile.FormatLookup(url, f), "\n") + "\n"
}

// fetchFound opens a session, makes exactly one get-logins and closes the
// client again. It fails if nothing is found.
func fetchFound(e *Env, g globals, url string) ([]profile.Found, error) {
	c, all, _, err := openSession(e, g)
	if err != nil {
		return nil, err
	}
	entries, err := c.GetLogins(url, keysOf(all))
	c.Close()
	var pe *kpx.ProtocolError
	if errors.As(err, &pe) && pe.Code == kpx.ErrNoLogins {
		return nil, fmt.Errorf("no entries found for %s (or access was denied)", url)
	}
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries found for %s (or access was denied)", url)
	}
	return found(entries), nil
}

// lookup prints the entries matching a URL: names, UUIDs and field names,
// never values.
func lookup(e *Env, g globals, args []string) error {
	if len(args) != 1 {
		return usageError{"lookup takes exactly one URL"}
	}
	f, err := fetchFound(e, g, args[0])
	if err != nil {
		return err
	}
	fmt.Fprint(e.Stdout, formatLookup(args[0], f))
	return nil
}
