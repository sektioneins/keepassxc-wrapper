// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && cgo

package kpx

/*
#include <unistd.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"path/filepath"
	"unsafe"
)

// socketName is the file name of KeePassXC's browser-integration socket.
const socketName = "org.keepassxc.KeePassXC.BrowserServer"

// DefaultSocketPath returns KeePassXC's browser socket in the per-user
// temporary directory (confstr _CS_DARWIN_USER_TEMP_DIR, not $TMPDIR).
func DefaultSocketPath() (string, error) {
	n := C.confstr(C._CS_DARWIN_USER_TEMP_DIR, nil, 0)
	if n == 0 {
		return "", errors.New("cannot determine the per-user temporary directory")
	}
	buf := (*C.char)(C.malloc(n))
	defer C.free(unsafe.Pointer(buf))
	if C.confstr(C._CS_DARWIN_USER_TEMP_DIR, buf, n) == 0 {
		return "", errors.New("cannot determine the per-user temporary directory")
	}
	return filepath.Join(C.GoString(buf), socketName), nil
}
