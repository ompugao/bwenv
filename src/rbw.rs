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
    pub fields: Option<Vec<RbwField>>,
}

#[derive(Debug, Deserialize)]
pub struct RbwField {
    pub name: String,
    pub value: Option<String>,
    #[serde(rename = "type")]
    pub field_type: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List namespace names: all items in `folder`, regardless of type.
pub fn list_namespaces(folder: &str) -> Result<Vec<String>> {
    let mut sp = Spinner::with_stream(
        Spinners::Dots,
        "Fetching namespaces…".into(),
        Stream::Stderr,
    );
    let output = Command::new("rbw")
        .args(["list", "--raw"])
        .output()
        .context("failed to run `rbw list`")?;
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

/// Fetch a single item's notes and custom fields.
/// Returns `None` if the item does not exist in the given folder.
pub fn get_item(name: &str, folder: &str) -> Result<Option<RbwItem>> {
    let mut sp = Spinner::with_stream(
        Spinners::Dots,
        format!("Fetching '{name}'…"),
        Stream::Stderr,
    );
    let output = Command::new("rbw")
        .args(["get", "--raw", "--folder", folder, name])
        .output()
        .context("failed to run `rbw get`")?;
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
/// For SecureNote entries (envwarden-compatible): rbw internally prepends `\n`
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
    let mut sp = Spinner::with_stream(
        Spinners::Dots,
        "Deleting from Bitwarden…".into(),
        Stream::Stderr,
    );
    let output = Command::new("rbw")
        .args(["remove", "--folder", folder, name])
        .output()
        .context("failed to run `rbw remove`")?;
    sp.stop_with_newline();
    check_status("rbw remove", &output)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Run an rbw command with the given args, piping `stdin_content` to its stdin.
/// rbw's `edit::edit()` detects a non-TTY stdin and reads from it directly.
///
/// We also set `RBW_TTY` so the rbw-agent can use pinentry for unlock prompts
/// even though our stdin is a pipe (not a terminal).
fn pipe_to_rbw(args: &[&str], stdin_content: &str) -> Result<()> {
    let mut cmd = Command::new("rbw");
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Pass the controlling terminal so rbw-agent can launch pinentry even
    // though our stdin is a pipe.  /dev/tty always refers to the ctty.
    if std::path::Path::new("/dev/tty").exists() {
        cmd.env("RBW_TTY", "/dev/tty");
    }

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
