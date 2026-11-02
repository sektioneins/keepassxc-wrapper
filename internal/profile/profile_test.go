// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadBody(t *testing.T, body string) (*Profile, error) {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, "p.toml", body)
	return Load(dir, "p")
}

func TestLoadValid(t *testing.T) {
	p, err := loadBody(t, `
url     = "secure-kp://hcloud-s1"
command = ["hcloud"]

[env]
HCLOUD_CONTEXT = "s1"

[secrets]
HCLOUD_TOKEN = { uuid = "1f7160154af146b39991dd240877e4f3", field = "KPH: HCLOUD_TOKEN" }
SSH_PASS     = { uuid = "C0F0D430-92F1-4CA4-9938-7B759EDB541C" }    # field defaults to "password"
`)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "p" || p.URL != "secure-kp://hcloud-s1" || len(p.Command) != 1 || p.Command[0] != "hcloud" {
		t.Errorf("bad profile: %+v", p)
	}
	if p.Env["HCLOUD_CONTEXT"] != "s1" {
		t.Errorf("env: %v", p.Env)
	}
	s := p.Secrets["SSH_PASS"]
	if s.Field != "password" || s.UUID != "c0f0d43092f14ca499387b759edb541c" {
		t.Errorf("SSH_PASS: %+v", s)
	}
	if h := p.Secrets["HCLOUD_TOKEN"]; h.Field != "KPH: HCLOUD_TOKEN" || h.UUID != "1f7160154af146b39991dd240877e4f3" {
		t.Errorf("HCLOUD_TOKEN: %+v", h)
	}
}

func TestLoadRejects(t *testing.T) {
	good := `url = "u"` + "\n"
	cases := []struct {
		name, body, want string
	}{
		{"unknown top key", good + `comand = ["x"]` + "\ncommand = [\"x\"]\n", "comand"},
		{"unknown secret key", good + "command = [\"x\"]\n[secrets]\nA = { uuid = \"" + strings.Repeat("a", 32) + "\", feild = \"x\" }\n", "feild"},
		{"command string", good + `command = "hcloud"`, "command"},
		{"missing url", `command = ["x"]`, "url"},
		{"missing command", good, "command"},
		{"empty command", good + `command = []`, "command"},
		{"field KPH:X", good + "command = [\"x\"]\n[secrets]\nA = { uuid = \"" + strings.Repeat("a", 32) + "\", field = \"KPH:X\" }\n", "field"},
		{"field notes", good + "command = [\"x\"]\n[secrets]\nA = { uuid = \"" + strings.Repeat("a", 32) + "\", field = \"notes\" }\n", "field"},
		{"bad uuid", good + "command = [\"x\"]\n[secrets]\nA = { uuid = \"xyz\" }\n", "uuid"},
		{"bad env name", good + "command = [\"x\"]\n[env]\n\"1X\" = \"v\"\n", "1X"},
		{"bad secret name", good + "command = [\"x\"]\n[secrets]\n\"A-B\" = { uuid = \"" + strings.Repeat("a", 32) + "\" }\n", "A-B"},
		{"broken toml", "url = ", ""},
	}
	for _, c := range cases {
		_, err := loadBody(t, c.body)
		if err == nil {
			t.Errorf("%s: expected error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q lacks %q", c.name, err, c.want)
		}
	}
}

func TestLoadAllowsSameNameInEnvAndSecrets(t *testing.T) {
	_, err := loadBody(t, "url = \"u\"\ncommand = [\"x\"]\n[env]\nA = \"1\"\n[secrets]\nA = { uuid = \""+strings.Repeat("a", 32)+"\" }\n")
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(t.TempDir(), "nope")
	if err == nil || !strings.Contains(err.Error(), "secure-kp list") {
		t.Fatalf("got %v", err)
	}
}

func TestNormalizeUUID(t *testing.T) {
	got, err := NormalizeUUID("1F716015-4AF1-46B3-9991-DD240877E4F3")
	if err != nil || got != "1f7160154af146b39991dd240877e4f3" {
		t.Fatalf("%q %v", got, err)
	}
	for _, s := range []string{"", "abc", strings.Repeat("g", 32), strings.Repeat("a", 33)} {
		if _, err := NormalizeUUID(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestRunnablePlaceholder(t *testing.T) {
	if err := (&Profile{Command: []string{Placeholder}}).Runnable(); err == nil {
		t.Error("placeholder is runnable")
	}
	if err := (&Profile{Command: []string{"hcloud"}}).Runnable(); err != nil {
		t.Error(err)
	}
}

func TestValidNameRejects(t *testing.T) {
	for _, n := range []string{"../x", "a/b", ".hidden", "", "list", "new", "lookup", "associate", "-v"} {
		if ValidName(n) == nil {
			t.Errorf("%q accepted", n)
		}
	}
	for _, n := range []string{"a", "hcloud-s1", "a.b_c", "0x"} {
		if err := ValidName(n); err != nil {
			t.Errorf("%q rejected: %v", n, err)
		}
	}
}

func TestPathRejectsBeforeFileAccess(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "cfg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, parent, "x.toml", "url = \"u\"\ncommand = [\"x\"]\n")
	if _, err := Path(dir, "../x"); err == nil {
		t.Error("Path accepted ../x")
	}
	if _, err := Load(dir, "../x"); err == nil {
		t.Error("Load accepted ../x")
	}
	p, err := Path(dir, "ok")
	if err != nil || p != filepath.Join(dir, "ok.toml") {
		t.Errorf("%q %v", p, err)
	}
}

func TestListSummaries(t *testing.T) {
	dir := t.TempDir()
	u := strings.Repeat("a", 32)
	write(t, dir, "b-valid.toml", "url = \"secure-kp://b\"\ncommand = [\"hcloud\", \"server\"]\n[secrets]\nA = { uuid = \""+u+"\" }\n")
	write(t, dir, "a-place.toml", "url = \"secure-kp://a\"\ncommand = [\"CHANGE-ME\"]\n")
	write(t, dir, "c-broken.toml", "url = ")
	write(t, dir, "notes.txt", "x")
	write(t, dir, ".hidden.toml", "x")
	write(t, dir, "list.toml", "x")
	if err := os.Mkdir(filepath.Join(dir, "d.toml"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Name != "a-place" || !strings.Contains(got[0].Problem, "not runnable") {
		t.Errorf("0: %+v", got[0])
	}
	if got[1].Name != "b-valid" || got[1].Problem != "" || got[1].Command != "hcloud server" || got[1].URL != "secure-kp://b" || got[1].Secrets != 1 {
		t.Errorf("1: %+v", got[1])
	}
	if got[2].Name != "c-broken" || got[2].Problem == "" {
		t.Errorf("2: %+v", got[2])
	}
	empty, err := List(filepath.Join(dir, "missing"))
	if err != nil || len(empty) != 0 {
		t.Errorf("missing dir: %v %v", empty, err)
	}
}
