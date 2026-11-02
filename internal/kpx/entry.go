// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package kpx

import (
	"encoding/json"
	"fmt"
)

// Entry is a credential returned by get-logins.
type Entry struct {
	UUID, Name, Login, Password, Group, TOTP string
	Expired                                  bool
	// Fields holds the advanced string fields, keyed by full attribute name
	// such as "KPH: HCLOUD_TOKEN".
	Fields map[string]string
}

// UnmarshalJSON decodes KeePassXC's entry shape.
func (e *Entry) UnmarshalJSON(b []byte) error {
	var raw struct {
		UUID         string              `json:"uuid"`
		Name         string              `json:"name"`
		Login        string              `json:"login"`
		Password     string              `json:"password"`
		Group        string              `json:"group"`
		TOTP         string              `json:"totp"`
		Expired      string              `json:"expired"`
		StringFields []map[string]string `json:"stringFields"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*e = Entry{
		UUID: raw.UUID, Name: raw.Name, Login: raw.Login, Password: raw.Password,
		Group: raw.Group, TOTP: raw.TOTP, Expired: raw.Expired == "true",
	}
	if len(raw.StringFields) > 0 {
		e.Fields = make(map[string]string)
		for _, m := range raw.StringFields {
			for k, v := range m {
				e.Fields[k] = v
			}
		}
	}
	return nil
}

// errorCodeString decodes an errorCode that is either a JSON string or number.
func errorCodeString(raw json.RawMessage) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return "", fmt.Errorf("bad errorCode %s", raw)
	}
	return n.String(), nil
}

// UnmarshalJSON decodes an error reply, accepting errorCode as string or number.
func (e *ProtocolError) UnmarshalJSON(b []byte) error {
	var raw struct {
		Action    string          `json:"action"`
		ErrorCode json.RawMessage `json:"errorCode"`
		Error     string          `json:"error"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	code := ""
	if len(raw.ErrorCode) > 0 {
		var err error
		if code, err = errorCodeString(raw.ErrorCode); err != nil {
			return err
		}
	}
	*e = ProtocolError{Action: raw.Action, Code: code, Message: raw.Error}
	return nil
}
