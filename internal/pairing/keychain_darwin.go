// Copyright 2026 SektionEins GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && cgo

package pairing

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// kp_cfstr returns a new CFString holding the UTF-8 bytes of a Go string,
// or NULL. Only non-secret values (service, account, label) go through here.
static CFStringRef kp_cfstr(_GoString_ s) {
	size_t n = _GoStringLen(s);
	const char *p = n > 0 ? _GoStringPtr(s) : "";
	return CFStringCreateWithBytes(kCFAllocatorDefault, (const UInt8 *)p, (CFIndex)n, kCFStringEncodingUTF8, false);
}

// kp_query returns a new mutable query dictionary for generic passwords of
// service svc, limited to account acct when withAcct is set, or NULL.
static CFMutableDictionaryRef kp_query(_GoString_ svc, _GoString_ acct, int withAcct) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (q == NULL) {
		return NULL;
	}
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFStringRef s = kp_cfstr(svc);
	if (s == NULL) {
		CFRelease(q);
		return NULL;
	}
	CFDictionarySetValue(q, kSecAttrService, s);
	CFRelease(s);
	if (withAcct) {
		CFStringRef a = kp_cfstr(acct);
		if (a == NULL) {
			CFRelease(q);
			return NULL;
		}
		CFDictionarySetValue(q, kSecAttrAccount, a);
		CFRelease(a);
	}
	return q;
}

// kp_delete deletes every item of (svc, acct).
static OSStatus kp_delete(_GoString_ svc, _GoString_ acct) {
	CFMutableDictionaryRef q = kp_query(svc, acct, 1);
	if (q == NULL) {
		return errSecAllocate;
	}
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	return st;
}

// kp_add adds an item for (svc, acct) whose data is a copy of the n bytes at
// data. The bytes go straight into a CFData, never through a C string.
static OSStatus kp_add(_GoString_ svc, _GoString_ acct, _GoString_ label, const UInt8 *data, CFIndex n) {
	CFMutableDictionaryRef q = kp_query(svc, acct, 1);
	if (q == NULL) {
		return errSecAllocate;
	}
	CFStringRef l = kp_cfstr(label);
	if (l == NULL) {
		CFRelease(q);
		return errSecAllocate;
	}
	CFDictionarySetValue(q, kSecAttrLabel, l);
	CFRelease(l);
	CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, n);
	if (d == NULL) {
		CFRelease(q);
		return errSecAllocate;
	}
	CFDictionarySetValue(q, kSecValueData, d);
	CFRelease(d);
	OSStatus st = SecItemAdd(q, NULL);
	CFRelease(q);
	return st;
}

// kp_copy_accounts stores in *out a new CFArray of the account names (as
// CFStrings) of every item of svc. The caller releases *out.
static OSStatus kp_copy_accounts(_GoString_ svc, CFArrayRef *out) {
	*out = NULL;
	CFMutableDictionaryRef q = kp_query(svc, svc, 0);
	if (q == NULL) {
		return errSecAllocate;
	}
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);
	CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
	CFTypeRef res = NULL;
	OSStatus st = SecItemCopyMatching(q, &res);
	CFRelease(q);
	if (st != errSecSuccess) {
		if (res != NULL) {
			CFRelease(res);
		}
		return st;
	}
	if (res == NULL || CFGetTypeID(res) != CFArrayGetTypeID()) {
		if (res != NULL) {
			CFRelease(res);
		}
		return errSecInternalComponent;
	}
	CFMutableArrayRef accts = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
	if (accts == NULL) {
		CFRelease(res);
		return errSecAllocate;
	}
	CFIndex count = CFArrayGetCount((CFArrayRef)res);
	for (CFIndex i = 0; i < count; i++) {
		CFTypeRef item = CFArrayGetValueAtIndex((CFArrayRef)res, i);
		if (item == NULL || CFGetTypeID(item) != CFDictionaryGetTypeID()) {
			continue;
		}
		CFTypeRef a = CFDictionaryGetValue((CFDictionaryRef)item, kSecAttrAccount);
		if (a == NULL || CFGetTypeID(a) != CFStringGetTypeID()) {
			continue;
		}
		CFArrayAppendValue(accts, a);
	}
	CFRelease(res);
	*out = accts;
	return errSecSuccess;
}

// kp_copy_data stores in *out a new CFData with the data of the item of
// (svc, acct). The caller releases *out.
static OSStatus kp_copy_data(_GoString_ svc, _GoString_ acct, CFDataRef *out) {
	*out = NULL;
	CFMutableDictionaryRef q = kp_query(svc, acct, 1);
	if (q == NULL) {
		return errSecAllocate;
	}
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFTypeRef res = NULL;
	OSStatus st = SecItemCopyMatching(q, &res);
	CFRelease(q);
	if (st != errSecSuccess) {
		if (res != NULL) {
			CFRelease(res);
		}
		return st;
	}
	if (res == NULL || CFGetTypeID(res) != CFDataGetTypeID()) {
		if (res != NULL) {
			CFRelease(res);
		}
		return errSecInternalComponent;
	}
	*out = (CFDataRef)res;
	return errSecSuccess;
}

// kp_utf8 returns a malloc'd UTF-8 copy of s, or NULL. The caller frees it.
static char *kp_utf8(CFStringRef s) {
	if (s == NULL) {
		return NULL;
	}
	CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	char *buf = malloc((size_t)max);
	if (buf == NULL) {
		return NULL;
	}
	if (!CFStringGetCString(s, buf, max, kCFStringEncodingUTF8)) {
		free(buf);
		return NULL;
	}
	return buf;
}

// kp_account_at returns a malloc'd UTF-8 copy of the i-th string in accts.
static char *kp_account_at(CFArrayRef accts, CFIndex i) {
	return kp_utf8((CFStringRef)CFArrayGetValueAtIndex(accts, i));
}

// kp_error_message returns a malloc'd description of st, or NULL.
static char *kp_error_message(OSStatus st) {
	CFStringRef m = SecCopyErrorMessageString(st, NULL);
	if (m == NULL) {
		return NULL;
	}
	char *s = kp_utf8(m);
	CFRelease(m);
	return s;
}

static void kp_release_array(CFArrayRef a) { CFRelease(a); }
static void kp_release_data(CFDataRef d) { CFRelease(d); }
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"slices"
	"unsafe"
)

// service is the Keychain service name of every pairing item. Tests change it
// so that they never touch real pairings.
var service = "secure-kp"

type keychainStore struct{}

// NewKeychainStore returns a Store backed by generic password items in the
// login keychain: service "secure-kp", account = database hash, data = the
// Pairing as JSON.
func NewKeychainStore() Store {
	return keychainStore{}
}

// List returns every pairing in the Keychain, sorted by database hash.
func (keychainStore) List() ([]Pairing, error) {
	var accts C.CFArrayRef
	st := C.kp_copy_accounts(service, &accts)
	if st == C.errSecItemNotFound {
		return []Pairing{}, nil
	}
	if st != C.errSecSuccess {
		return nil, keychainError("listing pairings", st)
	}
	names := make([]string, 0)
	n := C.CFArrayGetCount(accts)
	for i := C.CFIndex(0); i < n; i++ {
		p := C.kp_account_at(accts, i)
		if p == nil {
			C.kp_release_array(accts)
			return nil, fmt.Errorf("keychain: listing pairings: cannot read an account name")
		}
		names = append(names, C.GoString(p))
		C.free(unsafe.Pointer(p))
	}
	C.kp_release_array(accts)
	slices.Sort(names)
	names = slices.Compact(names)

	out := make([]Pairing, 0, len(names))
	for _, acct := range names {
		p, found, err := readItem(acct)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, p)
		}
	}
	return out, nil
}

// readItem reads and decodes the item of acct. found is false when the item
// vanished after it was listed.
func readItem(acct string) (p Pairing, found bool, err error) {
	var d C.CFDataRef
	st := C.kp_copy_data(service, acct, &d)
	if st == C.errSecItemNotFound {
		return Pairing{}, false, nil
	}
	if st != C.errSecSuccess {
		return Pairing{}, false, keychainError(fmt.Sprintf("reading pairing %q", acct), st)
	}
	data := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(d)), C.int(C.CFDataGetLength(d)))
	C.kp_release_data(d)
	defer clear(data)
	// The decoder's error text can quote bytes of the data, so it is not
	// passed on.
	if err := json.Unmarshal(data, &p); err != nil {
		return Pairing{}, false, fmt.Errorf("keychain: item for account %q is not valid pairing JSON", acct)
	}
	return p, true, nil
}

// Put stores p, replacing any item with the same DBHash.
func (keychainStore) Put(p Pairing) error {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("keychain: encoding pairing: %w", err)
	}
	defer clear(data)
	if err := deleteItem(p.DBHash); err != nil {
		return err
	}
	short := p.DBHash
	if len(short) > 12 {
		short = short[:12]
	}
	label := fmt.Sprintf("%s pairing %s", service, short)
	st := C.kp_add(service, p.DBHash, label, (*C.UInt8)(unsafe.Pointer(&data[0])), C.CFIndex(len(data)))
	if st != C.errSecSuccess {
		return keychainError(fmt.Sprintf("storing pairing %q", p.DBHash), st)
	}
	return nil
}

// deleteItem removes the item of account acct. A missing item is not an error.
func deleteItem(acct string) error {
	st := C.kp_delete(service, acct)
	if st == C.errSecSuccess || st == C.errSecItemNotFound {
		return nil
	}
	return keychainError(fmt.Sprintf("deleting pairing %q", acct), st)
}

func keychainError(op string, st C.OSStatus) error {
	msg := "unknown error"
	if p := C.kp_error_message(st); p != nil {
		msg = C.GoString(p)
		C.free(unsafe.Pointer(p))
	}
	return fmt.Errorf("keychain: %s: %s (OSStatus %d)", op, msg, int(st))
}
