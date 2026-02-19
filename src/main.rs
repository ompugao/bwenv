mod rbw;
mod store;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use rpassword::read_password;
use std::collections::HashMap;
use std::env;
use std::process::Command;

const DEFAULT_FOLDER: &str = "bwenv";
const FOLDER_ENV: &str = "BWENV_FOLDER";

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "bwenv")]
#[command(version)]
#[command(about = "Inject Bitwarden secrets (via rbw) as environment variables")]
#[command(long_about = None)]
struct Cli {
    /// Bitwarden folder that holds bwenv namespaces
    /// [env: BWENV_FOLDER] [default: bwenv]
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
    let (existing_notes, is_new, is_secure_note) = match existing_notes(folder, namespace)? {
        Some((notes, secure)) => (notes, false, secure),
        None => (String::new(), true, false),
    };

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
                     You can set variables via: bwenv set {ns} SOME_VAR"
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
    let (existing, is_secure_note) = existing_notes(folder, namespace)?
        .with_context(|| format!("namespace `{namespace}` not found in folder `{folder}`"))?;

    let mut notes = existing;
    for key in vars {
        match store::remove(&notes, key) {
            Some(updated) => notes = updated,
            None => eprintln!("WARNING: key `{key}` not found in namespace `{namespace}`"),
        }
    }

    write_namespace(folder, namespace, &notes, false, is_secure_note)?;

    // If all keys have been removed, delete the entry entirely.
    if store::parse(&notes).is_empty() {
        rbw::delete_item(namespace, folder)?;
        eprintln!("namespace `{namespace}` is now empty and has been removed");
    }

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Resolve the folder: CLI flag > env var > default.
fn resolve_folder(cli_folder: Option<&str>) -> String {
    cli_folder
        .map(str::to_string)
        .or_else(|| env::var(FOLDER_ENV).ok())
        .unwrap_or_else(|| DEFAULT_FOLDER.to_string())
}

/// Load env pairs for a namespace from the notes-field KEY=VALUE lines.
fn load_env_pairs(folder: &str, namespace: &str) -> Result<HashMap<String, String>> {
    let item = rbw::get_item(namespace, folder)?
        .with_context(|| format!("namespace `{namespace}` not found in folder `{folder}`"))?;

    Ok(item.notes.as_deref().map(store::parse).unwrap_or_default())
}

/// Return the current notes content for a namespace, or `None` if it does not
/// exist. Also returns whether the item is a SecureNote.
fn existing_notes(folder: &str, namespace: &str) -> Result<Option<(String, bool)>> {
    match rbw::get_item(namespace, folder)? {
        Some(item) => {
            let is_secure_note = item.item_type.as_deref() == Some("Note");
            Ok(Some((item.notes.unwrap_or_default(), is_secure_note)))
        }
        None => Ok(None),
    }
}

/// Write (create or edit) a namespace note.
fn write_namespace(
    folder: &str,
    namespace: &str,
    notes: &str,
    is_new: bool,
    is_secure_note: bool,
) -> Result<()> {
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
