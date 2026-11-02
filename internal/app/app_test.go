// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sektioneins/keepassxc-wrapper/internal/kpx"
	"github.com/sektioneins/keepassxc-wrapper/internal/kpx/kpxtest"
	"github.com/sektioneins/keepassxc-wrapper/internal/pairing"
)

const repoURL = "https://github.com/sektioneins/keepassxc-wrapper"

// testEnv bundles an Env with its fakes. Tasks extending package app reuse it.
type testEnv struct {
	*Env
	out, errb        *bytes.Buffer
	store            *pairing.MemStore
	cfgDir           string
	vars             map[string]string
	sockets          []string // socket paths given to Dial
	debugs           []bool   // whether Dial got a Debug writer
	defaultSockCalls int
	lookPaths        []string
	execs            []execCall
	// LookPathResult and ExecErr control the fakes.
	lookPathResult string
	lookPathErr    error
	execErr        error
}

type execCall struct {
	Path      string
	Argv, Env []string
}

func newTestEnv(t *testing.T, fake *kpxtest.Server) *testEnv {
	t.Helper()
	te := &testEnv{out: &bytes.Buffer{}, errb: &bytes.Buffer{}, store: pairing.NewMemStore(), cfgDir: t.TempDir(), vars: map[string]string{}}
	te.vars["SECURE_KP_CONFIG_DIR"] = te.cfgDir
	te.Env = &Env{
		Stdout: te.out,
		Stderr: te.errb,
		Getenv: func(k string) string { return te.vars[k] },
		Home:   t.TempDir(),
		Store:  te.store,
		Now:    func() time.Time { return time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC) },
		Dial: func(sock string, opts kpx.Options) (*kpx.Client, error) {
			te.sockets = append(te.sockets, sock)
			te.debugs = append(te.debugs, opts.Debug != nil)
			return kpx.NewClient(fake.Conn(), opts)
		},
		DefaultSocket: func() (string, error) {
			te.defaultSockCalls++
			return "/default.sock", nil
		},
		LookPath: func(name string) (string, error) {
			te.lookPaths = append(te.lookPaths, name)
			if te.lookPathErr != nil {
				return "", te.lookPathErr
			}
			if te.lookPathResult != "" {
				return te.lookPathResult, nil
			}
			return "/usr/bin/" + name, nil
		},
		Exec: func(path string, argv, env []string) error {
			te.execs = append(te.execs, execCall{path, argv, env})
			return te.execErr
		},
	}
	return te
}

func newFake() *kpxtest.Server {
	return &kpxtest.Server{DBHash: "0123456789abcdef0123456789abcdef", AssociateName: "secure-kp-test"}
}

func (te *testEnv) writeProfile(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(te.cfgDir, name+".toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNoArgsIsUsageError(t *testing.T) {
	te := newTestEnv(t, newFake())
	if code := Main(nil, te.Env); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	s := te.errb.String()
	if !strings.Contains(s, "usage") {
		t.Errorf("stderr lacks usage: %q", s)
	}
	if !strings.Contains(s, "SektionEins GmbH") || !strings.Contains(s, repoURL) {
		t.Errorf("stderr lacks company or URL: %q", s)
	}
}

func TestHelpShowsCompanyAndURL(t *testing.T) {
	for _, h := range []string{"-h", "--help"} {
		te := newTestEnv(t, newFake())
		if code := Main([]string{h}, te.Env); code != 0 {
			t.Fatalf("%s: exit %d, want 0", h, code)
		}
		s := te.out.String()
		if !strings.Contains(s, "SektionEins GmbH") || !strings.Contains(s, repoURL) {
			t.Errorf("%s: stdout lacks company or URL: %q", h, s)
		}
	}
}

func TestBadFlagIsUsageError(t *testing.T) {
	te := newTestEnv(t, newFake())
	if code := Main([]string{"-nope"}, te.Env); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

func TestExtraArgsRejected(t *testing.T) {
	for _, c := range []string{"associate", "list"} {
		te := newTestEnv(t, newFake())
		if code := Main([]string{c, "extra"}, te.Env); code != 2 {
			t.Errorf("%s extra: exit %d, want 2", c, code)
		}
	}
}

func TestMissingProfileFailsWithExitOne(t *testing.T) {
	te := newTestEnv(t, newFake())
	if code := Main([]string{"someprofile"}, te.Env); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.HasPrefix(te.errb.String(), "secure-kp: ") {
		t.Errorf("stderr %q lacks prefix", te.errb.String())
	}
}

func TestSocketPrecedence(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		env   string
		want  string
		calls int
	}{
		{"flag wins", []string{"-socket", "/flag.sock", "list"}, "/env.sock", "/flag.sock", 0},
		{"env next", []string{"associate"}, "/env.sock", "/env.sock", 0},
		{"default last", []string{"associate"}, "", "/default.sock", 1},
	}
	for _, c := range cases {
		fake := newFake()
		te := newTestEnv(t, fake)
		te.vars["SECURE_KP_SOCKET"] = c.env
		if c.args[len(c.args)-1] == "list" {
			// list never dials; check via associate with the flag instead.
			c.args = []string{"-socket", "/flag.sock", "associate"}
		}
		if code := Main(c.args, te.Env); code != 0 {
			t.Fatalf("%s: exit %d: %s", c.name, code, te.errb.String())
		}
		if len(te.sockets) != 1 || te.sockets[0] != c.want {
			t.Errorf("%s: sockets %v, want %s", c.name, te.sockets, c.want)
		}
		if te.defaultSockCalls != c.calls {
			t.Errorf("%s: DefaultSocket called %d times, want %d", c.name, te.defaultSockCalls, c.calls)
		}
	}
}

func TestVerboseSetsDebug(t *testing.T) {
	for _, v := range []bool{false, true} {
		te := newTestEnv(t, newFake())
		args := []string{"associate"}
		if v {
			args = []string{"-v", "associate"}
		}
		if code := Main(args, te.Env); code != 0 {
			t.Fatalf("exit %d: %s", code, te.errb.String())
		}
		if te.debugs[0] != v {
			t.Errorf("-v=%v: Debug set = %v", v, te.debugs[0])
		}
	}
}

func TestAssociateStoresPairing(t *testing.T) {
	fake := newFake()
	te := newTestEnv(t, fake)
	if code := Main([]string{"associate"}, te.Env); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errb.String())
	}
	ps, _ := te.store.List()
	if len(ps) != 1 {
		t.Fatalf("%d pairings, want 1", len(ps))
	}
	p := ps[0]
	if p.DBHash != fake.DBHash || p.ID != fake.AssociateName {
		t.Errorf("pairing %+v", p)
	}
	if p.IDKey == "" || p.IDSecret == "" || p.Created != "2026-11-02T10:00:00Z" {
		t.Errorf("pairing fields %+v", p)
	}
	want := "associated with database " + fake.DBHash[:12] + "… as \"secure-kp-test\""
	if !strings.Contains(te.errb.String(), want) {
		t.Errorf("stderr %q lacks %q", te.errb.String(), want)
	}
	if strings.Contains(te.errb.String(), p.IDSecret) || te.out.Len() != 0 {
		t.Error("secret or stdout leak")
	}
}

func TestListOutput(t *testing.T) {
	te := newTestEnv(t, newFake())
	te.writeProfile(t, "alpha", "url = \"secure-kp://alpha\"\ncommand = [\"hcloud\", \"server\", \"list\"]\n[secrets]\nHCLOUD_TOKEN = { uuid = \"0123456789abcdef0123456789abcdef\", field = \"password\" }\n")
	te.writeProfile(t, "beta", "url = \"secure-kp://beta\"\ncommand = [\"CHANGE-ME\"]\n")
	if code := Main([]string{"list"}, te.Env); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errb.String())
	}
	s := te.out.String()
	for _, w := range []string{"alpha", "beta", "hcloud server list", "secure-kp://alpha", "1 secret", "not runnable"} {
		if !strings.Contains(s, w) {
			t.Errorf("stdout lacks %q: %q", w, s)
		}
	}
	if len(te.sockets) != 0 {
		t.Error("list dialled")
	}
}

func TestListEmpty(t *testing.T) {
	te := newTestEnv(t, newFake())
	if code := Main([]string{"list"}, te.Env); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if te.out.Len() != 0 || !strings.Contains(te.errb.String(), te.cfgDir) || !strings.Contains(te.errb.String(), "secure-kp new") {
		t.Errorf("stdout %q stderr %q", te.out.String(), te.errb.String())
	}
}

func TestUsageErrorsStartWithUsageHeader(t *testing.T) {
	header := strings.SplitAfterN(usageText, "\n", 3)
	want := header[0] + header[1]
	for _, args := range [][]string{nil, {"-nope"}, {"list", "x"}, {"lookup"}, {"new"}, {"new", "p", "-bogus"}} {
		te := newTestEnv(t, newFake())
		if code := Main(args, te.Env); code != 2 {
			t.Fatalf("%v: exit %d, want 2", args, code)
		}
		s := te.errb.String()
		if !strings.HasPrefix(s, want) {
			t.Errorf("%v: stderr does not start with the usage header: %q", args, s)
		}
		for _, l := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
			if strings.HasPrefix(l, "flag ") {
				t.Errorf("%v: unprefixed flag message in %q", args, s)
			}
		}
	}
}

func TestBadFlagMessageOncePrefixed(t *testing.T) {
	for _, args := range [][]string{{"-x"}, {"new", "p", "-x"}} {
		te := newTestEnv(t, newFake())
		Main(args, te.Env)
		s := te.errb.String()
		if n := strings.Count(s, "flag provided but not defined: -x"); n != 1 {
			t.Errorf("%v: message %d times in %q", args, n, s)
		}
		if !strings.Contains(s, "secure-kp: flag provided but not defined: -x") {
			t.Errorf("%v: message lacks prefix: %q", args, s)
		}
	}
}

func TestSubcommandHelp(t *testing.T) {
	for _, args := range [][]string{{"new", "-h"}, {"new", "--help"}, {"new", "p", "-h"}, {"lookup", "-h"}, {"lookup", "--help"}} {
		fake := newFake()
		te := newTestEnv(t, fake)
		if code := Main(args, te.Env); code != 0 {
			t.Fatalf("%v: exit %d, want 0: %s", args, code, te.errb.String())
		}
		if te.out.String() != usageText || te.errb.Len() != 0 {
			t.Errorf("%v: stdout %q stderr %q", args, te.out.String(), te.errb.String())
		}
		if len(te.sockets) != 0 || len(fake.Calls()) != 0 {
			t.Errorf("%v: connected to KeePassXC", args)
		}
	}
}

func TestRelativeConfigDirRefused(t *testing.T) {
	te := newTestEnv(t, newFake())
	te.vars = map[string]string{}
	te.Home = ""
	if code := Main([]string{"list"}, te.Env); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(te.errb.String(), "cannot determine the home directory; set SECURE_KP_CONFIG_DIR") {
		t.Errorf("stderr %q", te.errb.String())
	}
	te = newTestEnv(t, newFake())
	te.Home = ""
	if code := Main([]string{"list"}, te.Env); code != 0 {
		t.Errorf("with SECURE_KP_CONFIG_DIR: exit %d: %s", code, te.errb.String())
	}
}
