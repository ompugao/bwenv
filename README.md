# envrbw

Inject [Bitwarden](https://bitwarden.com) secrets as environment variables, using [rbw](https://github.com/doy/rbw) as the backend.

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
envrbw <namespace> <command> [args...]
```

```sh
envrbw prod/db psql "$DATABASE_URL"
```

### Manage secrets

```sh
# Add or update keys (prompts for each value)
envrbw set <namespace> KEY1 KEY2 ...
envrbw set prod/db DATABASE_URL SECRET_KEY --noecho   # hide input

# List namespaces
envrbw list

# List keys in a namespace
envrbw list <namespace>
envrbw list <namespace> --show-value

# Remove keys (deletes the entry when the last key is removed)
envrbw unset <namespace> KEY1 KEY2 ...
```

### Folder

By default all namespaces live in the `envrbw` Bitwarden folder. Override with `--folder` or `ENVRBW_FOLDER`:

```sh
ENVRBW_FOLDER=work envrbw staging/api node server.js
```

## envwarden compatibility

Entries created by [envwarden](https://github.com/envwarden/envwarden) (SecureNote type, values in custom fields) can be used with `exec` mode. They are read-only; `set` will not migrate them to the notes-field format.
