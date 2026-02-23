//! Wrappers around the `rbw` CLI for reading and writing Bitwarden entries.
//!
//! Auth (unlock / login) is handled automatically by rbw itself — every rbw
//! command runs `rbw unlock` / `rbw login` as needed before executing.  We
//! just run the commands and propagate errors.
//!
//! Write strategy: pipe content directly to rbw's stdin.  When stdin is not a
//! terminal, `rbw::edit::edit()` reads the entire stdin rather than launching
//! an editor.  This avoids any temp-file / EDITOR tricks.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use spinners::{Spinner, Spinners, Stream};
use std::io::Write as _;
use std::process::{Command, Stdio};

// ── JSON shapes returned by `rbw list --raw` and `rbw get --raw` ─────────────

#[derive(Debug, Deserialize)]
pub struct ListItem {
    pub name: String,
    pub folder: Option<String>,
    #[serde(rename = "type")]
    pub item_type: String,
}

#[derive(Debug, Deserialize)]
pub struct RbwItem {
    /// Entry type: "Login", "Note", etc.
    #[serde(rename = "type")]
    pub item_type: Option<String>,
    pub notes: Option<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List namespace names: all items in `folder`, regardless of type.
pub fn list_namespaces(folder: &str) -> Result<Vec<String>> {
    ensure_unlocked()?;

    let mut sp = Spinner::with_stream(
        Spinners::Dots,
        "Fetching namespaces…".into(),
        Stream::Stderr,
    );
    let mut cmd = Command::new("rbw");
    cmd.args(["list", "--raw"]);
    set_rbw_tty(&mut cmd);
    let output = cmd.output().context("failed to run `rbw list`")?;
    sp.stop_with_newline();

    check_status("rbw list", &output)?;

    let items: Vec<ListItem> = serde_json::from_slice(&output.stdout)
        .context("failed to parse `rbw list --raw` output")?;

    let names = items
        .into_iter()
        .filter(|i| i.folder.as_deref().unwrap_or("") == folder)
        .map(|i| i.name)
        .collect();

    Ok(names)
}

/// Fetch a single item's notes.
/// Returns `None` if the item does not exist in the given folder.
pub fn get_item(name: &str, folder: &str) -> Result<Option<RbwItem>> {
    ensure_unlocked()?;

    let mut sp = Spinner::with_stream(
        Spinners::Dots,
        format!("Fetching '{name}'…"),
        Stream::Stderr,
    );
    let mut cmd = Command::new("rbw");
    cmd.args(["get", "--raw", "--folder", folder, name]);
    set_rbw_tty(&mut cmd);
    let output = cmd.output().context("failed to run `rbw get`")?;
    sp.stop_with_newline();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("no entry found")
            || stderr.contains("no items found")
            || stderr.contains("Entry not found")
        {
            return Ok(None);
        }
        bail!("`rbw get` failed ({}): {}", output.status, stderr.trim());
    }

    let item: RbwItem =
        serde_json::from_slice(&output.stdout).context("failed to parse `rbw get --raw` output")?;

    Ok(Some(item))
}

/// Create a new entry (Login type) with `notes_content` in the given folder.
///
/// `rbw add` always creates a Login entry.  When stdin is piped (not a TTY),
/// rbw reads the editor content directly from stdin.  Format: first line =
/// password (empty), rest = notes.
pub fn create_item(name: &str, folder: &str, notes_content: &str) -> Result<()> {
    // Prepend empty line so rbw's parse_editor treats it as an empty password.
    let stdin_content = format!("\n{notes_content}\n");
    pipe_to_rbw(&["add", "--folder", folder, name], &stdin_content)
}

/// Edit an existing entry, replacing its notes with `notes_content`.
///
/// For Login entries (created by `create_item`): pipe `\n<content>` so the
/// first line (password) stays empty.
/// For SecureNote entries: rbw internally prepends `\n`
/// before parsing, so pipe the content directly.
pub fn edit_item(
    name: &str,
    folder: &str,
    notes_content: &str,
    is_secure_note: bool,
) -> Result<()> {
    let stdin_content = if is_secure_note {
        format!("{notes_content}\n")
    } else {
        format!("\n{notes_content}\n")
    };
    pipe_to_rbw(&["edit", "--folder", folder, name], &stdin_content)
}

/// Delete an entry by name and folder.
pub fn delete_item(name: &str, folder: &str) -> Result<()> {
    ensure_unlocked()?;

    let mut sp = Spinner::with_stream(
        Spinners::Dots,
        "Deleting from Bitwarden…".into(),
        Stream::Stderr,
    );
    let mut cmd = Command::new("rbw");
    cmd.args(["remove", "--folder", folder, name]);
    set_rbw_tty(&mut cmd);
    let output = cmd.output().context("failed to run `rbw remove`")?;
    sp.stop_with_newline();
    check_status("rbw remove", &output)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Ensure the rbw vault is unlocked before running commands.  This triggers
/// `rbw unlock` (and pinentry) up front, so that subsequent rbw commands don't
/// need to prompt — avoiding TTY conflicts with piped stdin/stdout.
fn ensure_unlocked() -> Result<()> {
    let mut cmd = Command::new("rbw");
    cmd.args(["unlocked"]);
    set_rbw_tty(&mut cmd);
    let output = cmd.output().context("failed to run `rbw unlocked`")?;
    if !output.status.success() {
        // Not unlocked — run `rbw unlock` which will invoke pinentry.
        let mut cmd = Command::new("rbw");
        cmd.args(["unlock"]);
        set_rbw_tty(&mut cmd);
        let status = cmd
            .status()
            .context("failed to run `rbw unlock`")?;
        if !status.success() {
            bail!("`rbw unlock` failed ({})", status);
        }
    }
    Ok(())
}

/// Pass the real TTY device path (e.g. `/dev/pts/3`) so that the rbw-agent
/// daemon — which has no controlling terminal — can tell pinentry which TTY to
/// use.  `/dev/tty` would only work inside the current process tree; the agent
/// needs an absolute device path.
fn set_rbw_tty(cmd: &mut Command) {
    if let Some(tty) = real_tty_path() {
        cmd.env("RBW_TTY", tty);
    }
}

/// Resolve the real TTY device path from stderr (fd 2).
/// Falls back to `/dev/tty` if the real path cannot be determined.
fn real_tty_path() -> Option<std::ffi::OsString> {
    // Try stderr first (bwenv may have stdout piped), then stdin.
    for fd in ["2", "0"] {
        let link = format!("/proc/self/fd/{fd}");
        if let Ok(path) = std::fs::read_link(&link) {
            if path.to_string_lossy().starts_with("/dev/") {
                return Some(path.into_os_string());
            }
        }
    }
    // Last resort: /dev/tty (works if caller has a ctty).
    if std::path::Path::new("/dev/tty").exists() {
        return Some("/dev/tty".into());
    }
    None
}

/// Run an rbw command with the given args, piping `stdin_content` to its stdin.
/// rbw's `edit::edit()` detects a non-TTY stdin and reads from it directly.
fn pipe_to_rbw(args: &[&str], stdin_content: &str) -> Result<()> {
    ensure_unlocked()?;

    let mut cmd = Command::new("rbw");
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    set_rbw_tty(&mut cmd);

    let mut sp = Spinner::with_stream(
        Spinners::Dots,
        "Saving to Bitwarden…".into(),
        Stream::Stderr,
    );
    let mut child = cmd.spawn().context("failed to spawn rbw")?;

    child
        .stdin
        .take()
        .context("failed to open rbw stdin")?
        .write_all(stdin_content.as_bytes())
        .context("failed to write to rbw stdin")?;

    let status = child.wait().context("failed to wait for rbw")?;
    sp.stop_with_newline();
    if !status.success() {
        bail!("rbw exited with status {}", status);
    }
    Ok(())
}

/// Convert a failed `Command` output into an error message.
fn check_status(cmd: &str, output: &std::process::Output) -> Result<()> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("`{}` failed ({}): {}", cmd, output.status, stderr.trim());
    }
    Ok(())
}
