// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sektioneins/keepassxc-wrapper/internal/kpx"
	"github.com/sektioneins/keepassxc-wrapper/internal/profile"
)

// exitError makes Main exit with a specific code after printing msg.
type exitError struct {
	code int
	msg  string
}

func (x exitError) Error() string { return x.msg }

// normUUID makes UUIDs from profiles and from KeePassXC comparable.
func normUUID(s string) string { return strings.ToLower(strings.ReplaceAll(s, "-", "")) }

// ResolveSecrets maps each variable to its value. Entries that get-logins did
// not return, and fields they lack, leave the variable unresolved. totp is
// asked for a code only when the entry was returned without one. The error
// lists every unresolved variable with its uuid and field, never a value.
func ResolveSecrets(secrets map[string]profile.Secret, entries []kpx.Entry, totp func(uuid string) (string, error)) (map[string]string, error) {
	byUUID := make(map[string]kpx.Entry, len(entries))
	for _, en := range entries {
		byUUID[normUUID(en.UUID)] = en
	}
	out := make(map[string]string, len(secrets))
	var missing []string
	for _, name := range sortedKeys(secrets) {
		s := secrets[name]
		field := s.Field
		if field == "" {
			field = "password"
		}
		val, ok := "", false
		if en, found := byUUID[normUUID(s.UUID)]; found {
			switch {
			case field == "password":
				val, ok = en.Password, true
			case field == "username":
				val, ok = en.Login, true
			case field == "totp":
				val, ok = en.TOTP, en.TOTP != ""
				if !ok && totp != nil {
					if code, err := totp(en.UUID); err == nil && code != "" {
						val, ok = code, true
					}
				}
			case strings.HasPrefix(field, "KPH: "):
				val, ok = en.Fields[field]
			}
		}
		if ok {
			out[name] = val
		} else {
			missing = append(missing, fmt.Sprintf("%s (uuid %s, field %s)", name, s.UUID, field))
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("cannot resolve %d variable(s):\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
	return out, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// BuildEnv returns base with env and secrets applied, each name exactly once.
// Secrets beat env, env beats base. Base order is kept (an overridden name keeps
// its first position); new names follow, sorted. base is not modified.
func BuildEnv(base []string, env, secrets map[string]string) []string {
	final := make(map[string]string, len(env)+len(secrets))
	for k, v := range env {
		final[k] = v
	}
	for k, v := range secrets {
		final[k] = v
	}
	out := make([]string, 0, len(base)+len(final))
	seen := make(map[string]bool, len(base))
	for _, kv := range base {
		k, _, hasEq := strings.Cut(kv, "=")
		if !hasEq {
			out = append(out, kv)
			continue
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		if v, ok := final[k]; ok {
			out = append(out, k+"="+v)
		} else {
			out = append(out, kv)
		}
	}
	for _, k := range sortedKeys(final) {
		if !seen[k] {
			out = append(out, k+"="+final[k])
		}
	}
	return out
}

// fetchSecrets makes one get-logins and resolves the profile's secrets.
func fetchSecrets(e *Env, g globals, p *profile.Profile) (map[string]string, error) {
	c, _, _, err := openSession(e, g)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	entries, err := c.GetLogins(p.URL, nil)
	denied := false
	var pe *kpx.ProtocolError
	if errors.As(err, &pe) && pe.Code == kpx.ErrNoLogins {
		denied, entries, err = true, nil, nil
	}
	if err != nil {
		return nil, err
	}
	vals, err := ResolveSecrets(p.Secrets, entries, c.GetTOTP)
	if err != nil {
		if denied {
			err = fmt.Errorf("%w\nKeePassXC returned no entries: they may lack the URL %s, or access was denied", err, p.URL)
		}
		return nil, err
	}
	warnExpired(e, p, entries)
	return vals, nil
}

// warnExpired warns once per expired entry that a secret uses, sorted by name.
func warnExpired(e *Env, p *profile.Profile, entries []kpx.Entry) {
	used := map[string]bool{}
	for _, s := range p.Secrets {
		used[normUUID(s.UUID)] = true
	}
	var names []string
	for _, en := range entries {
		if en.Expired && used[normUUID(en.UUID)] {
			names = append(names, en.Name)
		}
	}
	slices.Sort(names)
	for _, n := range slices.Compact(names) {
		fmt.Fprintf(e.Stderr, "secure-kp: warning: entry %q is expired\n", n)
	}
}

// runProfile loads a profile, fetches its secrets and execs its command.
func runProfile(e *Env, g globals, name string, args []string) error {
	if err := profile.ValidName(name); err != nil {
		return usageError{err.Error()}
	}
	p, err := profile.Load(profile.Dir(e.Getenv, e.Home), name)
	if err != nil {
		return err
	}
	if err := p.Runnable(); err != nil {
		return err
	}
	var vals map[string]string
	if len(p.Secrets) > 0 {
		if vals, err = fetchSecrets(e, g, p); err != nil {
			return err
		}
	}
	path, err := e.LookPath(p.Command[0])
	if err != nil {
		return exitError{127, fmt.Sprintf("command %q not found in PATH", p.Command[0])}
	}
	argv := append(slices.Clone(p.Command), args...)
	if err := e.Exec(path, argv, BuildEnv(e.Environ, p.Env, vals)); err != nil {
		return fmt.Errorf("exec %s: %w", path, err)
	}
	return nil
}
