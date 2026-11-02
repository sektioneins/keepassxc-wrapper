prefix := env("PREFIX", home_directory() / ".local")

build:
    CGO_ENABLED=1 go build -trimpath -o dist/secure-kp ./cmd/secure-kp

test:
    go test ./...

vet:
    go vet ./...

test-keychain:
    go test -tags keychain ./internal/pairing/...

install: build
    mkdir -p "{{prefix}}/bin"
    cp dist/secure-kp "{{prefix}}/bin/.secure-kp.new"
    mv -f "{{prefix}}/bin/.secure-kp.new" "{{prefix}}/bin/secure-kp"

# Symlink the built binary into PREFIX/bin, so that rebuilding updates it.
install-link: build
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{prefix}}/bin"
    bindir=$(cd "{{prefix}}/bin" && pwd -P)
    target="$(cd dist && pwd -P)/secure-kp"
    # relative path from bindir to target: strip the common prefix, climb out of the rest
    common=$bindir
    while [[ $target != "$common"/* ]]; do
        common=${common%/*}   # becomes empty at the root, where "$common"/* matches everything
    done
    rel=${target#"$common"/}
    rest=${bindir#"$common"}
    while [[ -n $rest ]]; do
        rel=../$rel
        rest=${rest%/*}
    done
    ln -sfn "$rel" "$bindir/secure-kp"
    echo "$bindir/secure-kp -> $rel"
