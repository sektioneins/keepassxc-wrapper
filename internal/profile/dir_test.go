// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package profile

import "testing"

func TestDirPrecedence(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"override", map[string]string{"SECURE_KP_CONFIG_DIR": "/o", "XDG_CONFIG_HOME": "/x"}, "/o"},
		{"xdg", map[string]string{"XDG_CONFIG_HOME": "/x"}, "/x/secure-kp"},
		{"home", map[string]string{}, "/h/.config/secure-kp"},
		{"empty override", map[string]string{"SECURE_KP_CONFIG_DIR": "", "XDG_CONFIG_HOME": "/x"}, "/x/secure-kp"},
		{"empty both", map[string]string{"SECURE_KP_CONFIG_DIR": "", "XDG_CONFIG_HOME": ""}, "/h/.config/secure-kp"},
	}
	for _, c := range cases {
		if got := Dir(env(c.env), "/h"); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
