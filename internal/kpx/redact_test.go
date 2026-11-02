// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package kpx

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	out := Redact([]byte(`{"entries":[{"password":"pw-a","stringFields":[{"KPH: X":"tok"}],"name":"n"}],"keys":[{"id":"i","key":"abc"}]}`))
	for _, s := range []string{"pw-a", "tok", "abc"} {
		if strings.Contains(out, s) {
			t.Fatalf("%q leaked: %s", s, out)
		}
	}
	for _, s := range []string{"<redacted len=4>", `"name":"n"`} {
		if !strings.Contains(out, s) {
			t.Fatalf("missing %q: %s", s, out)
		}
	}
	assertEq(t, Redact([]byte("not json")), "<unparseable>")
}

func TestRedactOtherSecretKeysAndNonStrings(t *testing.T) {
	out := Redact([]byte(`{"totp":"123456","idKey":"idk-secret","idSecret":"ids-secret","password":12345,"key":{"nested":"deep-secret"},"login":"user-secret","name":"n"}`))
	for _, s := range []string{"user-secret", "123456", "idk-secret", "ids-secret", "deep-secret", "12345"} {
		if strings.Contains(out, s) {
			t.Fatalf("%q leaked: %s", s, out)
		}
	}
	if !strings.Contains(out, `"name":"n"`) {
		t.Fatalf("non-secret value lost: %s", out)
	}
}
