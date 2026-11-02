# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`secure-kp` is a macOS-only Go CLI. `secure-kp <profile> [args...]` loads a TOML profile, fetches the profile's secrets from KeePassXC over its browser-integration unix socket (one access dialog per call), puts them in the environment and `syscall.Exec`s the profile's command. The pairing with KeePassXC lives in the macOS Keychain. README.md is the user documentation; keep it in step with the built behaviour.

The design spec and implementation plan are local only and never committed: `docs/superpowers/specs/2026-11-02-secure-kp-design.md` and `docs/superpowers/plans/2026-11-02-secure-kp.md`. `spike/kpx/main.go` is a throwaway protocol spike kept as reference; it is not part of the build.

## Commands

```
just build          # CGO_ENABLED=1 go build -trimpath -o dist/secure-kp ./cmd/secure-kp
just test           # go test ./...
just vet
just test-keychain  # go test -tags keychain ./internal/pairing/...  (real Keychain, see below)
just install        # copy to $PREFIX/bin (PREFIX defaults to ~/.local)
just install-link   # relative symlink $PREFIX/bin/secure-kp -> this repo's dist/secure-kp

go test ./internal/kpx -run TestGetLoginsNoMatch -v   # single test
go test -race ./...                                   # the plan runs kpx and app tests with -race
```

Module commands must run offline: `GOFLAGS=-mod=mod GOPROXY=off go mod tidy`. The only third-party modules are `golang.org/x/crypto` (nacl/box) and `github.com/BurntSushi/toml`; don't add others.

The Claude sandbox blocks unix-socket connects and the Keychain. Anything that talks to the real KeePassXC socket or Keychain (`just test-keychain`, `dist/secure-kp associate|lookup|<profile>`) has to be run by the user with the `!` prefix.

## Architecture

- `internal/kpx`: the KeePassXC browser protocol over any `net.Conn`. `Client` does the handshake and an unexported `call`; `actions.go` has `DatabaseHash`, `WaitUnlocked`, `Associate`, `TestAssociate`, `GetLogins`, `GetTOTP`. `Redact` masks secrets in debug output.
- `internal/kpx/kpxtest`: an in-process fake KeePassXC served over `net.Pipe` (not a unix socket, because of the sandbox and the 104-byte socket path limit). Tests in `kpx` and `app` drive it through fields such as `Locked`, `UnlockAfter`, `DenyLogins`, `CloseOn`, `PushBefore` and inspect `Calls()`.
- `internal/pairing`: `Store` interface with `MemStore` for tests and a cgo Security.framework Keychain store (`keychain_darwin.go`). Never shell out to `/usr/bin/security`.
- `internal/profile`: profile directory, strict TOML loading and validation, `List`, and `Generate`/`Write` for the `new` subcommand.
- `internal/app`: `Main(args, *Env) int` and the subcommands (`associate`, `lookup`, `new`, `list`, running a profile). Every OS touchpoint (stdout/stderr, getenv, environ, Keychain store, dial, LookPath, Exec, clock) is injected through `Env`, so the whole CLI is testable against the fake server. `cmd/secure-kp` only wires the real implementations.

### Protocol facts that the code depends on (verified against KeePassXC 2.8.0)

- Framing is raw JSON objects back to back, no length prefix or newline; read with a streaming `json.Decoder`.
- `change-public-keys` is plaintext; everything after is a NaCl box envelope `{action, message, nonce, clientID}`. The reply nonce must equal the request nonce incremented little-endian (`sodium_increment`); a mismatch is an error.
- Error replies are unencrypted `{action, error, errorCode}` with `errorCode` usually a string. Codes in use: 1 database not opened (locked), 8 association failed, 15 no logins found.
- KeePassXC pushes unsolicited messages (`database-locked`, `database-unlocked`); `call` skips any message whose `action` differs.
- Each new connection must prove the pairing with `test-associate` before `get-logins`, or it gets error 8.
- Connection order for a run: `change-public-keys`, `get-databasehash` with `triggerUnlock` (if locked, wait up to 2 min for `database-unlocked`, then ask again), pick the pairing whose hash matches, `test-associate`, then exactly one `get-logins` for the profile URL. `triggerUnlock:"true"` is sent in both the inner message and the outer envelope.
- Custom URL schemes match as additional URLs, so profiles use `secure-kp://<profile>`. Only attributes named `KPH: …` are returned (in `stringFields`, and only with "Return advanced string fields" enabled).
- A profile with no `[secrets]` never contacts KeePassXC.

## Rules

- Secrets never go to disk, argv, stdout or stderr. `-v` debug output redacts `password`, `totp`, `key`, `idKey`, `idSecret` and every `stringFields` value; there is deliberately no reveal option. `lookup` and `new` print names, UUIDs and field names only.
- Messages go to stderr prefixed `secure-kp: `; stdout is only for `lookup`, `list` and `--help` output. The usage text starts with `secure-kp: run commands with secrets from KeePassXC` and `Copyright 2026 SektionEins GmbH, https://github.com/sektioneins/keepassxc-wrapper`.
- Exit codes: 0 success, 1 runtime error, 2 usage error, 127 command not found; otherwise the wrapped command's own code (it replaces the process).
- Arguments after the profile name are passed to the command untouched; global flags (`-v`, `-socket`) only count before it.
- Every `.go` file starts with `// Copyright 2026 SektionEins GmbH` and `// SPDX-License-Identifier: Apache-2.0`.
- Prose (README, messages, comments) is British English without em or en dashes as punctuation, and never refers to other internal tools.
- Never commit `docs/superpowers/`, `.claude/`, `spike/` or `.superpowers/`. Stage files by explicit path.
