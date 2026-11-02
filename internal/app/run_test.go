// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sektioneins/keepassxc-wrapper/internal/kpx"
	"github.com/sektioneins/keepassxc-wrapper/internal/kpx/kpxtest"
)

const runURL = "https://run.example"

func runSetup(t *testing.T, entries ...kpxtest.Entry) (*testEnv, *kpxtest.Server) {
	t.Helper()
	fake := newFake()
	for i := range entries {
		entries[i].URLs = []string{runURL}
	}
	fake.Entries = entries
	te := newTestEnv(t, fake)
	if code := Main([]string{"associate"}, te.Env); code != 0 {
		t.Fatalf("associate: %s", te.errb.String())
	}
	te.errb.Reset()
	return te, fake
}

func envHas(env []string, kv string) bool { return slices.Contains(env, kv) }

func countPrefix(env []string, p string) int {
	n := 0
	for _, e := range env {
		if strings.HasPrefix(e, p) {
			n++
		}
	}
	return n
}

const twoSecrets = `url = "` + runURL + `"
command = ["hcloud", "server", "list"]
[secrets]
HCLOUD_TOKEN = { uuid = "` + uuidA + `", field = "password" }
HCLOUD_USER = { uuid = "` + uuidB + `", field = "username" }
`

func TestRunExecsWithSecrets(t *testing.T) {
	te, fake := runSetup(t,
		kpxtest.Entry{Entry: kpx.Entry{UUID: uuidA, Name: "a", Password: "tok"}},
		kpxtest.Entry{Entry: kpx.Entry{UUID: uuidB, Name: "b", Login: "usr", Password: "x"}})
	te.writeProfile(t, "p", twoSecrets)
	if code := Main([]string{"p"}, te.Env); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errb.String())
	}
	if n := countCalls(fake, "get-logins"); n != 1 {
		t.Errorf("get-logins %d times, want 1", n)
	}
	if len(te.execs) != 1 {
		t.Fatalf("execs %d", len(te.execs))
	}
	x := te.execs[0]
	if !slices.Equal(x.Argv, []string{"hcloud", "server", "list"}) || x.Path != "/usr/bin/hcloud" {
		t.Errorf("path %q argv %q", x.Path, x.Argv)
	}
	if !envHas(x.Env, "HCLOUD_TOKEN=tok") || !envHas(x.Env, "HCLOUD_USER=usr") {
		t.Errorf("env %q", x.Env)
	}
}

func TestRunPassesFlagLikeArgs(t *testing.T) {
	te, _ := runSetup(t,
		kpxtest.Entry{Entry: kpx.Entry{UUID: uuidA, Name: "a", Password: "tok"}},
		kpxtest.Entry{Entry: kpx.Entry{UUID: uuidB, Name: "b", Login: "usr"}})
	te.writeProfile(t, "p", twoSecrets)
	args := []string{"--help", "-v", "-socket", "x"}
	if code := Main(append([]string{"p"}, args...), te.Env); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errb.String())
	}
	want := append([]string{"hcloud", "server", "list"}, args...)
	if len(te.execs) != 1 || !slices.Equal(te.execs[0].Argv, want) {
		t.Fatalf("execs %+v", te.execs)
	}
	if strings.Contains(te.errb.String(), ">>>") {
		t.Errorf("-v was enabled: %q", te.errb.String())
	}
}

func TestBuildEnvOverridesInherited(t *testing.T) {
	base := []string{"HCLOUD_TOKEN=old", "PATH=/bin", "NOEQ", "PATH=/dup", "A=b=c"}
	got := BuildEnv(base,
		map[string]string{"HCLOUD_TOKEN": "fromenv", "Z": "1", "PATH": "/p"},
		map[string]string{"HCLOUD_TOKEN": "new", "B": "2"})
	want := []string{"HCLOUD_TOKEN=new", "PATH=/p", "NOEQ", "A=b=c", "B=2", "Z=1"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if base[0] != "HCLOUD_TOKEN=old" || len(base) != 5 {
		t.Errorf("base mutated: %q", base)
	}
	got = BuildEnv([]string{"PATH=/bin", "PATH=/dup"}, nil, nil)
	if !slices.Equal(got, []string{"PATH=/bin"}) {
		t.Errorf("dups: %q", got)
	}
}

func TestRunEnvOverriddenBySecret(t *testing.T) {
	te, _ := runSetup(t, kpxtest.Entry{Entry: kpx.Entry{UUID: uuidA, Name: "a", Password: "new"}})
	te.Environ = []string{"HCLOUD_TOKEN=old", "PATH=/bin"}
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["c"]
[env]
HCLOUD_TOKEN = "fromenv"
[secrets]
HCLOUD_TOKEN = { uuid = "`+uuidA+`" }
`)
	if code := Main([]string{"p"}, te.Env); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errb.String())
	}
	env := te.execs[0].Env
	if countPrefix(env, "HCLOUD_TOKEN=") != 1 || !envHas(env, "HCLOUD_TOKEN=new") || !envHas(env, "PATH=/bin") {
		t.Errorf("env %q", env)
	}
}

func TestSecretValuesByteExact(t *testing.T) {
	const pw = "a=b c\nd ü"
	te, _ := runSetup(t, kpxtest.Entry{Entry: kpx.Entry{UUID: uuidA, Name: "a", Password: pw}})
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["c"]
[secrets]
T = { uuid = "`+uuidA+`" }
`)
	if code := Main([]string{"p"}, te.Env); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errb.String())
	}
	if !envHas(te.execs[0].Env, "T="+pw) {
		t.Errorf("env %q", te.execs[0].Env)
	}
}

func TestRunMissingFieldDoesNotExec(t *testing.T) {
	te, _ := runSetup(t, kpxtest.Entry{Entry: kpx.Entry{UUID: uuidA, Name: "a", Password: "SECRET-PW"}})
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["c"]
[secrets]
OK = { uuid = "`+uuidA+`" }
BAD = { uuid = "`+uuidA+`", field = "KPH: NOPE" }
`)
	if code := Main([]string{"p"}, te.Env); code != 1 {
		t.Fatalf("exit %d", code)
	}
	s := te.errb.String()
	if !strings.Contains(s, "BAD") || !strings.Contains(s, "KPH: NOPE") || strings.Contains(s, "SECRET-PW") {
		t.Errorf("stderr %q", s)
	}
	if strings.Contains(s, "OK (") {
		t.Errorf("resolved variable listed: %q", s)
	}
	if len(te.execs) != 0 {
		t.Error("exec called")
	}
}

func TestRunDeniedDoesNotExec(t *testing.T) {
	te, fake := runSetup(t, kpxtest.Entry{Entry: kpx.Entry{UUID: uuidA, Name: "a", Password: "pw"}},
		kpxtest.Entry{Entry: kpx.Entry{UUID: uuidB, Name: "b", Login: "u"}})
	fake.DenyLogins = true
	te.writeProfile(t, "p", twoSecrets)
	if code := Main([]string{"p"}, te.Env); code != 1 {
		t.Fatalf("exit %d", code)
	}
	s := te.errb.String()
	if !strings.Contains(s, "HCLOUD_TOKEN") || !strings.Contains(s, "HCLOUD_USER") || !strings.Contains(s, runURL) {
		t.Errorf("stderr %q", s)
	}
	if len(te.execs) != 0 {
		t.Error("exec called")
	}
}

func TestRunPlaceholderRefuses(t *testing.T) {
	te, fake := runSetup(t)
	before := len(fake.Calls())
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["CHANGE-ME"]
`)
	if code := Main([]string{"p"}, te.Env); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(te.errb.String(), "edit") || len(fake.Calls()) != before || len(te.execs) != 0 {
		t.Errorf("stderr %q calls %d", te.errb.String(), len(fake.Calls()))
	}
}

func TestRunNoSecretsSkipsKeePassXC(t *testing.T) {
	fake := newFake()
	te := newTestEnv(t, fake)
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["c"]
[env]
FOO = "bar"
`)
	if code := Main([]string{"p"}, te.Env); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errb.String())
	}
	if len(fake.Calls()) != 0 || len(te.sockets) != 0 {
		t.Error("KeePassXC contacted")
	}
	if len(te.execs) != 1 || !envHas(te.execs[0].Env, "FOO=bar") {
		t.Errorf("execs %+v", te.execs)
	}
}

func TestRunCommandNotFound(t *testing.T) {
	fake := newFake()
	te := newTestEnv(t, fake)
	te.lookPathErr = errors.New("not found")
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["nonesuch"]
`)
	if code := Main([]string{"p"}, te.Env); code != 127 {
		t.Fatalf("exit %d", code)
	}
	if len(te.execs) != 0 || !strings.Contains(te.errb.String(), "nonesuch") {
		t.Errorf("execs %d stderr %q", len(te.execs), te.errb.String())
	}
}

func TestRunTOTPFallback(t *testing.T) {
	te, fake := runSetup(t, kpxtest.Entry{Entry: kpx.Entry{UUID: uuidA, Name: "a", Password: "pw"}})
	fake.TOTP = map[string]string{uuidA: "123456"}
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["c"]
[secrets]
OTP = { uuid = "`+uuidA+`", field = "totp" }
`)
	if code := Main([]string{"p"}, te.Env); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errb.String())
	}
	if !envHas(te.execs[0].Env, "OTP=123456") {
		t.Errorf("env %q", te.execs[0].Env)
	}
}

func TestRunTOTPFailureIsUnresolved(t *testing.T) {
	te, _ := runSetup(t, kpxtest.Entry{Entry: kpx.Entry{UUID: uuidA, Name: "a", Password: "pw"}})
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["c"]
[secrets]
OTP = { uuid = "`+uuidA+`", field = "totp" }
`)
	if code := Main([]string{"p"}, te.Env); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(te.errb.String(), "OTP (uuid "+uuidA+", field totp)") || len(te.execs) != 0 {
		t.Errorf("stderr %q", te.errb.String())
	}
}

func TestRunExpiredWarning(t *testing.T) {
	te, _ := runSetup(t,
		kpxtest.Entry{Entry: kpx.Entry{UUID: uuidA, Name: "old", Password: "pw", Expired: true}},
		kpxtest.Entry{Entry: kpx.Entry{UUID: uuidB, Name: "unused", Expired: true}})
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["c"]
[secrets]
A = { uuid = "`+uuidA+`" }
B = { uuid = "`+uuidA+`", field = "username" }
`)
	_ = Main([]string{"p"}, te.Env)
	s := te.errb.String()
	if strings.Count(s, `warning: entry "old" is expired`) != 1 || strings.Contains(s, "unused") {
		t.Errorf("stderr %q", s)
	}
}

func TestRunExecErrorExitsOne(t *testing.T) {
	te, _ := runSetup(t)
	te.execErr = errors.New("boom")
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["c"]
`)
	if code := Main([]string{"p"}, te.Env); code != 1 || !strings.Contains(te.errb.String(), "exec /usr/bin/c: boom") {
		t.Errorf("exit %d stderr %q", code, te.errb.String())
	}
}

func TestRunUnknownProfile(t *testing.T) {
	te := newTestEnv(t, newFake())
	if code := Main([]string{"nope"}, te.Env); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(te.errb.String(), "secure-kp list") {
		t.Errorf("stderr %q", te.errb.String())
	}
}

func TestRunInvalidNameIsUsageError(t *testing.T) {
	te := newTestEnv(t, newFake())
	if code := Main([]string{"../x"}, te.Env); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestRunSendsStoredPairingAsKeys(t *testing.T) {
	te, fake := runSetup(t, kpxtest.Entry{Entry: kpx.Entry{UUID: uuidA, Name: "a", Password: "pw"}})
	te.writeProfile(t, "p", `url = "`+runURL+`"
command = ["c"]
[secrets]
T = { uuid = "`+uuidA+`" }
`)
	if code := Main([]string{"p"}, te.Env); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errb.String())
	}
	assertKeys(t, te, fake)
}

func assertKeys(t *testing.T, te *testEnv, fake *kpxtest.Server) {
	t.Helper()
	ps, _ := te.store.List()
	if len(ps) != 1 {
		t.Fatalf("pairings %d", len(ps))
	}
	for _, c := range fake.Calls() {
		if c.Action != "get-logins" {
			continue
		}
		ks, _ := c.Inner["keys"].([]any)
		m, _ := ks[0].(map[string]any)
		if len(ks) != 1 || m["id"] != ps[0].ID || m["key"] != ps[0].IDKey {
			t.Errorf("keys %v, want pairing %s", ks, ps[0].ID)
		}
		return
	}
	t.Error("no get-logins call")
}
