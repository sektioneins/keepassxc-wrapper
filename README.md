# secure-kp

`secure-kp` runs command-line tools with API keys and other secrets taken straight from your KeePassXC database. Instead of keeping a token in a config file or exporting it in your shell, you type

```
secure-kp hcloud-s1 server list
```

instead of `hcloud server list`. KeePassXC shows one confirmation dialog, `secure-kp` puts the approved secrets into the environment, and then it hands over to `hcloud`. Nothing is cached, so the next call asks again.

`secure-kp` talks to KeePassXC through its browser integration, the same local socket the KeePassXC-Browser extension uses. It never needs your master password, and it stores its pairing with KeePassXC in the macOS Keychain.

It runs on macOS only and is meant for local use on your own machine.

## How it works

Each tool you want to wrap gets a small profile. A profile names the command to run, any plain environment variables it needs, and which KeePassXC entries and fields go into which variables. It also names a URL such as `secure-kp://hcloud-s1`. You add that URL to every entry the profile needs, and `secure-kp` then asks KeePassXC for all of them in a single request. That is why you see one dialog per call, however many secrets the profile uses.

When you run a profile, `secure-kp`:

1. loads the profile from `~/.config/secure-kp/<name>.toml`,
2. connects to KeePassXC and proves its pairing (if the database is locked, KeePassXC shows its unlock window and `secure-kp` waits up to two minutes),
3. sends one request for the profile's URL and waits while you confirm the dialog,
4. checks that every configured secret came back, and stops without running anything if one is missing or you denied access,
5. replaces itself with the command, passing on your arguments and the secrets in its environment.

Because `secure-kp` replaces itself with the command rather than starting it as a child process, exit codes, signals and terminal handling behave as if you had run the tool directly.

## Requirements

You need macOS, [KeePassXC](https://keepassxc.org/) 2.8 or later, Go 1.26 or later and [just](https://github.com/casey/just) to build it.

## Installation

```
just build      # writes dist/secure-kp
just install    # copies it to ~/.local/bin (set PREFIX to change ~/.local)
```

If you would rather have rebuilds take effect at once, `just install-link` creates a relative symlink to `dist/secure-kp` in the same place instead of copying the binary.

## Setting up KeePassXC

Open KeePassXC's settings, go to Browser Integration and enable it. You don't need to tick any browser. On the Advanced tab, turn on 'Return advanced string fields', and leave 'Never ask before accessing credentials' switched off.

`secure-kp` can read these fields of an entry: the password, the username, the current TOTP code, and custom attributes whose names start with `KPH: ` (with a space after the colon). KeePassXC only hands out custom attributes with that prefix, so a token stored as `HCLOUD_TOKEN` stays invisible until you rename it to `KPH: HCLOUD_TOKEN`. The prefix is a leftover from KeePassHttp, the plugin KeePassXC's browser integration replaced, and it works as an opt-in: attributes without it never leave the database through this route. Notes and attachments can't be read at all.

For every entry a profile should use, open the entry's Browser Integration tab and add the profile's URL, for example `secure-kp://hcloud-s1`, as an additional URL. The entry's main URL can stay as it is.

## First steps

Pair `secure-kp` with the open database once:

```
secure-kp associate
```

KeePassXC asks you to name the connection. If you use several databases, open each one and run `associate` again. Each pairing is stored as its own Keychain item.

Next, create a profile. `new` asks KeePassXC for every entry that carries the profile's URL and writes a profile with all usable fields already filled in:

```
secure-kp new hcloud-s1 --command hcloud
```

Open `~/.config/secure-kp/hcloud-s1.toml`, rename the variables to what your tool expects and delete the lines you don't need. The comments at the top list what KeePassXC returned. Then run it:

```
secure-kp hcloud-s1 server list
```

To make this transparent, add an alias to your shell configuration:

```
alias hcloud='secure-kp hcloud-s1'
```

## Profiles

Profiles live in `~/.config/secure-kp/`, one TOML file per profile. If `XDG_CONFIG_HOME` is set, they live in `$XDG_CONFIG_HOME/secure-kp/` instead, and `SECURE_KP_CONFIG_DIR` overrides both.

```toml
url     = "secure-kp://hcloud-s1"
command = ["hcloud"]

[env]
HCLOUD_CONTEXT = "s1"

[secrets]
HCLOUD_TOKEN = { uuid = "1f7160154af146b39991dd240877e4f3", field = "KPH: HCLOUD_TOKEN" }
SSH_PASS     = { uuid = "c0f0d43092f14ca499387b759edb541c" }
```

`url` is the URL sent to KeePassXC. `command` is the program plus any fixed arguments; whatever you type after the profile name is appended. `[env]` sets plain variables exactly as written, with no expansion. `[secrets]` maps a variable to an entry's UUID and a field, which is `password` (the default), `username`, `totp` or the full name of a `KPH: ` attribute. Secrets override `[env]`, and both override variables already set in your shell.

Unknown keys are treated as errors, so a typo doesn't go unnoticed. A profile created by `new` without `--command` contains `command = ["CHANGE-ME"]` and refuses to run until you edit it.

## Commands

```
secure-kp [-v] [-socket PATH] <profile> [args...]   run a profile
secure-kp associate                                 pair with the open KeePassXC database
secure-kp lookup <url>                              list matching entries (names, UUIDs, fields; never values)
secure-kp new <profile> [--command CMD] [--url URL] [--force]
                                                    create a profile from a lookup
secure-kp list                                      list profiles without contacting KeePassXC
```

`associate`, `lookup`, `new` and `list` are reserved and can't be used as profile names. Global flags go before the profile name. Everything after it, including arguments that look like flags, goes to the wrapped command untouched.

`-v` writes the messages exchanged with KeePassXC to stderr with every secret value masked. There is deliberately no option to reveal them. `-socket` (or `SECURE_KP_SOCKET`) points to a different KeePassXC socket; by default `secure-kp` uses the one in your per-user temporary directory.

`secure-kp` exits with 1 when something goes wrong before the command starts, 2 for usage errors and 127 when the command can't be found. Otherwise the exit code is the wrapped command's own.

## Things to know

Never tick 'Remember' in KeePassXC's access dialog. If you do, KeePassXC stops asking for those entries, and `secure-kp` has no way to bring the dialog back.

KeePassXC leaves out expired entries unless 'Allow returning expired credentials' is on in its Browser Integration settings, so a profile that uses one stops with a missing secret. If the setting is on, `secure-kp` runs the command and prints a warning naming each expired entry it used.

Once the command runs, its secrets sit in its environment, and other processes running under your user account can read that environment. Wrapping a tool keeps keys out of files and shell history, but it doesn't protect them from software already running as you.

The Keychain item is tied to the `secure-kp` binary that created it. After a rebuild or update, macOS asks once whether the new binary may read it.

## Licence

Copyright 2026 SektionEins GmbH. Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE).

Source and issues: https://github.com/sektioneins/keepassxc-wrapper
