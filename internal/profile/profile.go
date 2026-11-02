// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

// Package profile locates, loads, validates and lists secure-kp profiles.
package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Placeholder is the command written by `new` when none is given.
const Placeholder = "CHANGE-ME"

// Reserved lists names that are subcommands and so cannot be profile names.
var Reserved = []string{"associate", "lookup", "new", "list"}

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	varRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	hexRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Secret maps an environment variable to a KeePassXC entry field.
type Secret struct {
	UUID  string `toml:"uuid"`
	Field string `toml:"field"`
}

// Profile is a parsed profile file.
type Profile struct {
	Name    string            `toml:"-"`
	URL     string            `toml:"url"`
	Command []string          `toml:"command"`
	Env     map[string]string `toml:"env"`
	Secrets map[string]Secret `toml:"secrets"`
}

// ValidName reports whether name is usable as a profile name.
func ValidName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid profile name %q (use letters, digits, '.', '_' and '-', starting with a letter or digit)", name)
	}
	if slices.Contains(Reserved, name) {
		return fmt.Errorf("profile name %q is reserved", name)
	}
	return nil
}

// Path returns the file for a profile, after validating the name.
func Path(dir, name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".toml"), nil
}

// NormalizeUUID strips dashes, lower-cases and requires 32 hex characters.
func NormalizeUUID(s string) (string, error) {
	n := strings.ToLower(strings.ReplaceAll(s, "-", ""))
	if !hexRe.MatchString(n) {
		return "", fmt.Errorf("invalid uuid %q (want 32 hex characters, dashes optional)", s)
	}
	return n, nil
}

// Load reads and validates the named profile.
func Load(dir, name string) (*Profile, error) {
	path, err := Path(dir, name)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("profile %q not found in %s (see `secure-kp list`)", name, dir)
	}
	p := &Profile{Name: name}
	md, err := toml.DecodeFile(path, p)
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, len(un))
		for i, k := range un {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("profile %q: unknown key(s): %s", name, strings.Join(keys, ", "))
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	return p, nil
}

func (p *Profile) validate() error {
	if p.URL == "" {
		return errors.New("missing required key \"url\"")
	}
	if len(p.Command) == 0 || p.Command[0] == "" {
		return errors.New("\"command\" must be a non-empty array")
	}
	for k := range p.Env {
		if !varRe.MatchString(k) {
			return fmt.Errorf("invalid variable name %q in [env]", k)
		}
	}
	for k, s := range p.Secrets {
		if !varRe.MatchString(k) {
			return fmt.Errorf("invalid variable name %q in [secrets]", k)
		}
		u, err := NormalizeUUID(s.UUID)
		if err != nil {
			return fmt.Errorf("[secrets] %s: %w", k, err)
		}
		s.UUID = u
		if s.Field == "" {
			s.Field = "password"
		}
		switch {
		case s.Field == "password", s.Field == "username", s.Field == "totp":
		case strings.HasPrefix(s.Field, "KPH: ") && len(s.Field) > len("KPH: "):
		default:
			return fmt.Errorf("[secrets] %s: invalid field %q (use password, username, totp or \"KPH: <name>\")", k, s.Field)
		}
		p.Secrets[k] = s
	}
	return nil
}

// Runnable reports an error when the command is still the placeholder.
func (p *Profile) Runnable() error {
	if len(p.Command) > 0 && p.Command[0] == Placeholder {
		return fmt.Errorf("profile %q is not runnable: edit command (it is still %s)", p.Name, Placeholder)
	}
	return nil
}

// Summary describes one profile for `list`.
type Summary struct {
	Name, Command, URL string
	Secrets            int
	Problem            string
}

// List summarises every <valid-name>.toml regular file in dir (symlinks to
// regular files count, as for Load), sorted by name.
// A missing directory gives an empty list.
func List(dir string) ([]Summary, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Summary
	for _, e := range entries {
		fn := e.Name()
		name, ok := strings.CutSuffix(fn, ".toml")
		if !ok || ValidName(name) != nil {
			continue
		}
		if fi, err := os.Stat(filepath.Join(dir, fn)); err != nil || !fi.Mode().IsRegular() {
			continue // not a regular file, or a dangling symlink
		}
		s := Summary{Name: name}
		p, err := Load(dir, name)
		if err != nil {
			s.Problem = err.Error()
		} else {
			s.Command = strings.Join(p.Command, " ")
			s.URL = p.URL
			s.Secrets = len(p.Secrets)
			if err := p.Runnable(); err != nil {
				s.Problem = "not runnable: edit command"
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
