// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package kpx

import (
	"encoding/json"
	"testing"
)

func TestEntryUnmarshal(t *testing.T) {
	// shape observed from KeePassXC 2.8.0
	raw := `{"group":"Misc","login":"","name":"kp-wrapper test A","password":"pw-a",
	  "stringFields":[{"KPH: HCLOUD_TOKEN":"tok"}],"uuid":"1f7160154af146b39991dd240877e4f3","expired":"true"}`
	var e Entry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	assertEq(t, e.Fields, map[string]string{"KPH: HCLOUD_TOKEN": "tok"})
	assertEq(t, e.Expired, true)
	assertEq(t, e.UUID, "1f7160154af146b39991dd240877e4f3")
	assertEq(t, e.Name, "kp-wrapper test A")
	assertEq(t, e.Group, "Misc")
	assertEq(t, e.Password, "pw-a")
}
