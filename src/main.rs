mod rbw;
mod store;

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use rpassword::read_password;
use std::collections::HashMap;
use std::env;
use std::process::Command;

const DEFAULT_FOLDER: &str = "envrbw";
const FOLDER_ENV: &str = "ENVRBW_FOLDER";

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "envrbw")]
#[command(version)]
#[command(about = "Inject Bitwarden secrets (via rbw) as environment variables")]
#[command(long_about = None)]
struct Cli {
    /// Bitwarden folder that holds envrbw namespaces
    /// [env: ENVRBW_FOLDER] [default: envrbw]
    #[arg(long, global = true, value_name = "FOLDER")]
    folder: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Namespace (for exec mode)
    #[arg(value_name = "NAMESPACE")]
    namespace: Option<String>,

    /// Command to execute (for exec mode)
    #[arg(value_name = "PROG", requires = "namespace")]
    exec_command: Option<String>,

    /// Arguments for the command (for exec mode)
    #[arg(
        value_name = "ARGS",
        requires = "exec_command",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    exec_args: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Set (create or update) environment variable keys in a namespace
    Set {
        /// Namespace to store variables in
        namespace: String,

        /// Environment variable names to set
        #[arg(required = true)]
        vars: Vec<String>,

        /// Do not echo user input
        #[arg(short, long)]
        noecho: bool,
    },

    /// List namespaces, or list keys in a namespace
    List {
        /// Namespace to list keys from (lists all namespaces if omitted)
        namespace: Option<String>,

        /// Show values alongside keys
        #[arg(short = 'v', long)]
        show_value: bool,
    },

    /// Remove keys from a namespace
    Unset {
        /// Namespace to remove keys from
        namespace: String,

        /// Environment variable names to remove
        #[arg(required = true)]
        vars: Vec<String>,
    },
}

// ── Command implementations ────────────────────────────────────────────────────

fn cmd_exec(folder: &str, namespace: &str, cmd: &str, args: &[String]) -> Result<()> {
    let pairs = load_env_pairs(folder, namespace)?;

    // SAFETY: single-threaded at this point; no other thread reads the env.
    for (k, v) in &pairs {
        unsafe { env::set_var(k, v) };
    }

    // Replace current process with the target command (Unix exec semantics).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let err = Command::new(cmd).args(args).exec();
        Err(anyhow::Error::from(err).context(format!("exec failed: {cmd}")))
    }
    #[cfg(not(unix))]
    {
        let status = Command::new(cmd)
            .args(args)
            .status()
            .with_context(|| format!("failed to run {cmd}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn cmd_set(folder: &str, namespace: &str, vars: &[String], noecho: bool) -> Result<()> {
    // Fetch existing content (or empty string for new namespace).
    let (existing_notes, is_secure_note) = existing_notes(folder, namespace)?;
    let is_new = existing_notes.is_empty();

    let mut notes = existing_notes;
    for key in vars {
        let prompt = format!("{namespace}.{key}");
        let value: String = if noecho {
            eprint!("{prompt} (noecho): ");
            read_password().context("failed to read password")?
        } else {
            eprint!("{prompt}: ");
            let mut buf = String::new();
            std::io::stdin()
                .read_line(&mut buf)
                .context("failed to read line")?;
            buf.trim_end_matches(['\n', '\r']).to_string()
        };
        notes = store::update(&notes, key, &value);
    }

    write_namespace(folder, namespace, &notes, is_new, is_secure_note)
}

fn cmd_list(folder: &str, namespace: Option<&str>, show_value: bool) -> Result<()> {
    match namespace {
        None => {
            let mut names = rbw::list_namespaces(folder)?;
            names.sort();
            for name in names {
                println!("{name}");
            }
        }
        Some(ns) => {
            let pairs = load_env_pairs(folder, ns)?;
            if pairs.is_empty() {
                eprintln!(
                    "WARNING: namespace `{ns}` not found or empty.\n\
                     You can set variables via: envrbw set {ns} SOME_VAR"
                );
                return Ok(());
            }
            let mut keys: Vec<&String> = pairs.keys().collect();
            keys.sort();
            for key in keys {
                if show_value {
                    println!("{}={}", key, pairs[key]);
                } else {
                    println!("{key}");
                }
            }
        }
    }
    Ok(())
}

fn cmd_unset(folder: &str, namespace: &str, vars: &[String]) -> Result<()> {
    let (existing, is_secure_note) = existing_notes(folder, namespace)?;
    if existing.is_empty() {
        bail!("namespace `{namespace}` not found in folder `{folder}`");
    }

    let mut notes = existing;
    for key in vars {
        match store::remove(&notes, key) {
            Some(updated) => notes = updated,
            None => eprintln!("WARNING: key `{key}` not found in namespace `{namespace}`"),
        }
    }

    write_namespace(folder, namespace, &notes, false, is_secure_note)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Resolve the folder: CLI flag > env var > default.
fn resolve_folder(cli_folder: Option<&str>) -> String {
    cli_folder
        .map(str::to_string)
        .or_else(|| env::var(FOLDER_ENV).ok())
        .unwrap_or_else(|| DEFAULT_FOLDER.to_string())
}

/// Load env pairs for a namespace, merging notes-field KEY=VALUE lines and,
/// as a fallback, any custom `fields[]` entries (envwarden compatibility).
fn load_env_pairs(folder: &str, namespace: &str) -> Result<HashMap<String, String>> {
    let item = rbw::get_item(namespace, folder)?
        .with_context(|| format!("namespace `{namespace}` not found in folder `{folder}`"))?;

    let mut pairs = HashMap::new();

    // Primary: notes field KEY=VALUE lines.
    if let Some(notes) = &item.notes {
        pairs.extend(store::parse(notes));
    }

    // Fallback: custom fields (envwarden-compatible, read-only).
    if pairs.is_empty() {
        if let Some(fields) = &item.fields {
            for f in fields {
                if matches!(f.field_type.as_str(), "text" | "hidden") {
                    if let Some(v) = &f.value {
                        pairs.insert(f.name.clone(), v.clone());
                    }
                }
            }
        }
    }

    Ok(pairs)
}

/// Return the current notes content for a namespace, or an empty string if it
/// does not yet exist. Also returns whether the item is a SecureNote.
fn existing_notes(folder: &str, namespace: &str) -> Result<(String, bool)> {
    match rbw::get_item(namespace, folder)? {
        Some(item) => {
            let is_secure_note = item.item_type.as_deref() == Some("Note");
            Ok((item.notes.unwrap_or_default(), is_secure_note))
        }
        None => Ok((String::new(), false)),
    }
}

/// Write (create or edit) a namespace note.
fn write_namespace(folder: &str, namespace: &str, notes: &str, is_new: bool, is_secure_note: bool) -> Result<()> {
    if is_new {
        rbw::create_item(namespace, folder, notes)
    } else {
        rbw::edit_item(namespace, folder, notes, is_secure_note)
    }
}

// ── Entry point ────────────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let folder = resolve_folder(cli.folder.as_deref());

    if let Some(command) = cli.command {
        match command {
            Commands::Set {
                namespace,
                vars,
                noecho,
            } => cmd_set(&folder, &namespace, &vars, noecho),

            Commands::List {
                namespace,
                show_value,
            } => cmd_list(&folder, namespace.as_deref(), show_value),

            Commands::Unset { namespace, vars } => cmd_unset(&folder, &namespace, &vars),
        }
    } else if let (Some(namespace), Some(command)) = (cli.namespace, cli.exec_command) {
        cmd_exec(&folder, &namespace, &command, &cli.exec_args)
    } else {
        Cli::command().print_help().ok();
        std::process::exit(2);
    }
}
