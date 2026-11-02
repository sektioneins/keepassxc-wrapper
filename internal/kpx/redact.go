// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package kpx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

var secretKeys = map[string]bool{
	"password": true, "login": true, "totp": true, "key": true, "idKey": true, "idSecret": true,
}

// Redact returns raw JSON with secret values replaced by "<redacted len=N>".
// The secret keys are password, login, totp, key, idKey, idSecret and every value
// inside stringFields. Unparseable input yields "<unparseable>".
func Redact(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "<unparseable>"
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(redactValue(v, false)); err != nil {
		return "<unparseable>"
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func mask(v any) string {
	if s, ok := v.(string); ok {
		return fmt.Sprintf("<redacted len=%d>", len(s))
	}
	return "<redacted>"
}

func redactValue(v any, all bool) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			switch {
			case all || secretKeys[k]:
				if _, nested := x.(string); nested || x == nil {
					t[k] = mask(x)
				} else {
					t[k] = redactValue(x, true)
				}
			case k == "stringFields":
				t[k] = redactValue(x, true)
			default:
				t[k] = redactValue(x, false)
			}
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = redactValue(x, all)
		}
		return t
	default:
		if all {
			return mask(v)
		}
		return v
	}
}
