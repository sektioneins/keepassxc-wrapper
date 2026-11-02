// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package profile

import "path/filepath"

// Dir returns the profile directory: $SECURE_KP_CONFIG_DIR, else
// $XDG_CONFIG_HOME/secure-kp, else <home>/.config/secure-kp. Empty variables
// count as unset.
func Dir(getenv func(string) string, home string) string {
	if d := getenv("SECURE_KP_CONFIG_DIR"); d != "" {
		return d
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "secure-kp")
	}
	return filepath.Join(home, ".config", "secure-kp")
}
