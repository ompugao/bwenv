# bwenv

[sorah/envchain](https://github.com/sorah/envchain) with bitwarden backend.
bw allows storing secrets in [Bitwarden](https://bitwarden.com) using [rbw](https://github.com/doy/rbw), and set them as environment variables when running a new process.

Secrets are stored as `KEY=VALUE` lines in the notes field of a Bitwarden entry (one entry per **namespace**, grouped in a **folder**). When the last key is removed from a namespace, the entry is deleted automatically.

## Prerequisites

[`rbw`](https://github.com/doy/rbw) must be installed and configured (`rbw config set email ...; rbw register; rbw login`).

## Install

```sh
cargo install --path .
```

## Usage

### Inject secrets into a command

```sh
bwenv <namespace> <command> [args...]
```

```sh
bwenv prod/db psql "$DATABASE_URL"
```

### Manage secrets

```sh
# Add or update keys (prompts for each value)
bwenv set <namespace> KEY1 KEY2 ...
bwenv set prod/db DATABASE_URL SECRET_KEY --noecho   # hide input

# List namespaces
bwenv list

# List keys in a namespace
bwenv list <namespace>
bwenv list <namespace> --show-value

# Remove keys (deletes the entry when the last key is removed)
bwenv unset <namespace> KEY1 KEY2 ...
```

### Folder

By default all namespaces live in the `bwenv` Bitwarden folder. Override with `--folder` or `BWENV_FOLDER`:

```sh
BWENV_FOLDER=work bwenv staging/api node server.js
```
