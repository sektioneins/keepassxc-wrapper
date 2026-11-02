// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

package kpx

import "time"

// Test-only access to the unexported call API, from the external test package.

var TriggerUnlockForTest = triggerUnlock

func CallForTest(c *Client, action string, inner map[string]any, opts ...callOpt) (map[string]any, error) {
	return c.call(action, inner, 5*time.Second, opts...)
}

func WaitForForTest(c *Client, action string, d time.Duration) (map[string]any, error) {
	return c.waitFor(action, d)
}
