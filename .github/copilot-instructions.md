# bwenv – Copilot Instructions

## What this project is

`bwenv` is a Rust CLI that injects Bitwarden secrets (via the `rbw` CLI) as environment variables. It stores key/value pairs as `KEY=VALUE` lines in the notes field of Bitwarden Login or SecureNote entries, grouped under a **namespace** (one entry per namespace) within a Bitwarden **folder** (default: `"bwenv"`).

The `rbw/` subdirectory is a vendored copy of the upstream [rbw](https://github.com/doy/rbw) project with its own separate Cargo workspace; it is not part of the `bwenv` build.

## Build, test, and lint commands

```bash
# Build
cargo build

# Run all tests
cargo test

# Run a single test by name
cargo test <test_name>

# Format check
cargo fmt --check

# Lint
cargo clippy --all-targets -- -Dwarnings
```

## Architecture

Three source files, no library crate:

```
src/
  main.rs   – CLI definition (clap derive), command dispatch, exec mode
  rbw.rs    – subprocess wrappers around the `rbw` binary (list, get, add, edit)
  store.rs  – KEY=VALUE parse/serialize/update/remove for notes-field content
```

**Data flow for `exec`:** `main.rs` calls `rbw::get_item` → parses notes via `store::parse` → sets env vars → `exec(2)` replaces the process (Unix) or spawns a child (non-Unix).

**Data flow for `set`:** reads existing notes via `rbw::get_item` → `store::update` → writes back via `rbw::create_item` (new) or `rbw::edit_item` (existing).

## Key conventions

- **Notes format:** `KEY=VALUE` lines (split on first `=`; blank lines and `#` comments are skipped). Serialization always sorts keys alphabetically. Values may contain `=`.
- **Folder resolution:** CLI `--folder` flag → `BWENV_FOLDER` env var → `"bwenv"` default.
- **rbw subprocess writes:** `rbw add`/`rbw edit` are driven by piping to stdin (rbw detects non-TTY and reads stdin instead of launching an editor). `RBW_TTY=/dev/tty` is set so pinentry still works for unlock prompts even when stdin is piped.
- **Login vs SecureNote format:** Login entries (created by `bwenv set`) require an empty first line (the password field) before the notes content. SecureNote entries (envwarden-compatible) are written without the leading empty line — `rbw` internally prepends one during parsing.
- **envwarden compatibility:** If an item's notes field is empty, `load_env_pairs` falls back to reading `text`/`hidden` custom fields (read-only; existing envwarden entries can be used for `exec` but not modified by `bwenv`).
- **"not found" detection:** `rbw::get_item` returns `Ok(None)` by matching known stderr substrings (`"no entry found"`, `"no items found"`, `"Entry not found"`). Update this list if rbw changes its error messages.
- **Error handling:** Uses `anyhow` throughout (`bail!`, `.context(...)`). No custom error types.
