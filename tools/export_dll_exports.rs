//! Helper tool to export all functions from a set of Windows DLLs into JSON.
//!
//! This is **not** part of the main RedBofAnalizer crate build – it lives in
//! `tools/` and can be compiled/run manually when you want to refresh the
//! OpSec API database inputs.
//!
//! Usage (from repo root, on Windows, with dumpbin or link available in PATH):
//!   1. Edit `tools/dll_list.txt` if needed.
//!   2. Build and run with `rustc tools/export_dll_exports.rs -o export_dll_exports.exe`
//!   3. Run:
//!        .\export_dll_exports.exe ^
//!          --dll-list RedBofAnalizer/tools/dll_list.txt ^
//!          --out-dir RedBofAnalizer/data/opsec_exports
//!
//! This will create one JSON file per DLL, e.g.:
//!   RedBofAnalizer/data/opsec_exports/kernel32.dll.json
//!
//! JSON schema per file:
//!   {
//!     "dll": "kernel32.dll",
//!     "exports": [
//!       { "name": "CreateFileA", "ordinal": 1, "is_forwarder": false },
//!       { "name": "WriteFile",   "ordinal": 2, "is_forwarder": false }
//!     ]
//!   }

use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

#[derive(Debug, Serialize)]
struct ExportedFunction {
    name: String,
    ordinal: Option<u32>,
    is_forwarder: bool,
}

#[derive(Debug, Serialize)]
struct DllExportList {
    dll: String,
    exports: Vec<ExportedFunction>,
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 5 {
        eprintln!(
            "Usage: {} --dll-list <dll_list.txt> --out-dir <output_directory>",
            args.get(0).map(String::as_str).unwrap_or("export_dll_exports")
        );
        std::process::exit(1);
    }

    let mut dll_list_path: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dll-list" if i + 1 < args.len() => {
                dll_list_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--out-dir" if i + 1 < args.len() => {
                out_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: {} --dll-list <dll_list.txt> --out-dir <output_directory>",
                    args[0]
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                std::process::exit(1);
            }
        }
    }

    let dll_list_path = dll_list_path.expect("--dll-list is required");
    let out_dir = out_dir.expect("--out-dir is required");

    fs::create_dir_all(&out_dir)?;

    let dlls = read_dll_list(&dll_list_path)?;

    for dll in dlls {
        if dll.trim().is_empty() {
            continue;
        }

        let dll_file = if dll.to_lowercase().ends_with(".dll") {
            dll.clone()
        } else {
            format!("{}.dll", dll)
        };

        let full_path = resolve_system32_path(&dll_file);
        eprintln!("[*] Processing {} -> {:?}", dll_file, full_path);

        let exports = match run_dumpbin_and_parse(&full_path) {
            Ok(list) => list,
            Err(err) => {
                eprintln!("  [!] Failed to parse exports for {}: {}", dll_file, err);
                continue;
            }
        };

        let json_struct = DllExportList {
            dll: dll_file.clone(),
            exports,
        };

        let out_file = out_dir.join(format!("{}.json", dll_file));
        eprintln!("  [+] Writing {}", out_file.display());
        let mut f = File::create(out_file)?;
        serde_json::to_writer_pretty(&mut f, &json_struct)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        writeln!(&mut f)?;
    }

    Ok(())
}

fn read_dll_list(path: &Path) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut dlls = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        dlls.push(trimmed.to_string());
    }

    Ok(dlls)
}

/// Try to resolve a DLL path under System32; fall back to the raw name if not found.
fn resolve_system32_path(dll_name: &str) -> PathBuf {
    // Prefer SYSTEMROOT or WINDIR environment variables.
    let system_root = env::var("SystemRoot")
        .or_else(|_| env::var("WINDIR"))
        .unwrap_or_else(|_| "C:\\Windows".to_string());

    let mut path = PathBuf::from(system_root);
    path.push("System32");
    path.push(dll_name);

    if path.exists() {
        path
    } else {
        // Fall back to just the DLL name; rely on search path at runtime.
        PathBuf::from(dll_name)
    }
}

/// Run `dumpbin /exports` (or `link /dump /exports`) and parse the export table.
fn run_dumpbin_and_parse(dll_path: &Path) -> io::Result<Vec<ExportedFunction>> {
    // First try dumpbin.
    let output = Command::new("dumpbin")
        .arg("/exports")
        .arg(dll_path)
        .output()
        .or_else(|_| {
            // Fallback to link /dump /exports if dumpbin is not available as a separate tool.
            Command::new("link")
                .arg("/dump")
                .arg("/exports")
                .arg(dll_path)
                .output()
        })?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "dumpbin/link failed for {} with status {:?}",
                dll_path.display(),
                output.status.code()
            ),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_dumpbin_exports(&stdout)
}

/// Very lightweight parser for `dumpbin /exports` output.
///
/// We look for the "ordinal" table and then parse subsequent lines that look like:
///   ordinal hint RVA      name
///   1       0   00001000  CreateFileA
///   2       1   00002000  WriteFile
///
/// Forwarded exports often include " (forwarded to ...)" after the name.
fn parse_dumpbin_exports(text: &str) -> io::Result<Vec<ExportedFunction>> {
    let mut exports = Vec::new();
    let mut in_table = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        // Detect the heading of the exports table.
        if trimmed.to_lowercase().starts_with("ordinal") && trimmed.to_lowercase().contains("name") {
            in_table = true;
            continue;
        }

        if !in_table {
            continue;
        }

        // Table rows are typically space-separated: ordinal hint RVA [forwarder] name
        // We split and pick out fields heuristically.
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            // Likely footer or something else; stop if we reach a separator.
            if trimmed.starts_with("Summary") {
                break;
            }
            continue;
        }

        // First token is ordinal.
        let ordinal = parts[0].parse::<u32>().ok();

        // Name is usually the last token, but forwarders can append "(forwarded to ...)".
        let mut name = parts[parts.len() - 1].to_string();
        let mut is_forwarder = false;

        // If we see "(forwarded" anywhere in the line, treat as forwarder.
        if trimmed.contains("(forwarded") {
            is_forwarder = true;
            // Sometimes the "name" token already excludes the parentheses, so we just keep it.
        }

        // Filter out lines that don't look like real symbol names.
        if name == "[NONAME]" {
            // Skip unnamed exports; they are address-only and not useful for our OpSec DB.
            continue;
        }

        exports.push(ExportedFunction {
            name,
            ordinal,
            is_forwarder,
        });
    }

    Ok(exports)
}


