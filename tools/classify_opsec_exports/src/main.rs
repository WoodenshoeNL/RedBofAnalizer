//! Helper tool to classify exported functions from selected DLLs into
//! Critical, High, and Medium OpSec categories based on the existing
//! OpSec documentation (`docs/OPSEC_TAB.md`).
//!
//! It reads the JSON files produced by `export_dll_exports` from
//! `data/opsec_exports`, then produces three text files with
//! `<dll>!<function>` entries:
//!   - `critical_apis.txt`
//!   - `high_apis.txt`
//!   - `medium_apis.txt`
//!
//! Usage (from repo root):
//!   cargo run --manifest-path RedBofAnalizer/tools/classify_opsec_exports/Cargo.toml -- \
//!     --in-dir RedBofAnalizer/data/opsec_exports \
//!     --out-dir RedBofAnalizer/data/opsec_lists

use std::collections::{BTreeSet, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ExportedFunction {
    name: String,
    ordinal: Option<u32>,
    is_forwarder: bool,
}

#[derive(Debug, Deserialize)]
struct DllExportList {
    dll: String,
    exports: Vec<ExportedFunction>,
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 5 {
        eprintln!(
            "Usage: {} --in-dir <exports_json_dir> --out-dir <output_directory>",
            args.get(0).map(String::as_str).unwrap_or("classify_opsec_exports")
        );
        std::process::exit(1);
    }

    let mut in_dir: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--in-dir" if i + 1 < args.len() => {
                in_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--out-dir" if i + 1 < args.len() => {
                out_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: {} --in-dir <exports_json_dir> --out-dir <output_directory>",
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

    let in_dir = in_dir.expect("--in-dir is required");
    let out_dir = out_dir.expect("--out-dir is required");

    fs::create_dir_all(&out_dir)?;

    let critical_set = critical_apis_set();
    let high_set = high_apis_set();
    let medium_explicit_set = medium_apis_set();

    let mut critical_out: BTreeSet<String> = BTreeSet::new();
    let mut high_out: BTreeSet<String> = BTreeSet::new();
    let mut medium_out: BTreeSet<String> = BTreeSet::new();

    for entry in fs::read_dir(&in_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let file = File::open(&path)?;
        let dll_exports: DllExportList = match serde_json::from_reader(file) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[!] Failed to parse JSON {}: {}", path.display(), e);
                continue;
            }
        };

        let dll_name = dll_exports.dll;

        for export in dll_exports.exports {
            let func_name = export.name.trim();
            if func_name.is_empty() {
                continue;
            }

            // Use the raw exported name as-is; forwarders will usually not match any
            // of the canonical names and will fall into Medium (unknown) by default.
            let key = format!("{}!{}", dll_name, func_name);

            if critical_set.contains(func_name) {
                critical_out.insert(key);
            } else if high_set.contains(func_name) {
                high_out.insert(key);
            } else if medium_explicit_set.contains(func_name) {
                medium_out.insert(key);
            } else {
                // Follow the analyzer's behavior: unknown APIs are treated as MediumRisk.
                medium_out.insert(key);
            }
        }
    }

    write_list(&out_dir.join("critical_apis.txt"), &critical_out)?;
    write_list(&out_dir.join("high_apis.txt"), &high_out)?;
    write_list(&out_dir.join("medium_apis.txt"), &medium_out)?;

    Ok(())
}

fn write_list(path: &Path, items: &BTreeSet<String>) -> io::Result<()> {
    let mut f = File::create(path)?;
    for item in items {
        writeln!(f, "{}", item)?;
    }
    Ok(())
}

fn critical_apis_set() -> HashSet<&'static str> {
    // From docs/OPSEC_TAB.md, "CriticalRisk APIs (9 APIs)"
    let names = [
        "NtCreateThreadEx",
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtQueueApcThread",
        "NtCreateSection",
        "NtMapViewOfSection",
        "EtwEventWrite",
        "EtwEventWriteFull",
        "LsaRetrievePrivateData",
    ];
    names.iter().cloned().collect()
}

fn high_apis_set() -> HashSet<&'static str> {
    // From docs/OPSEC_TAB.md, "HighRisk APIs (35 APIs)"
    let names = [
        // Process Injection
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "NtUnmapViewOfSection",
        "MapViewOfFile",
        "NtResumeThread",
        "ResumeThread",
        "GetThreadContext",
        "NtGetContextThread",
        "NtReadVirtualMemory",
        "NtOpenProcess",
        "NtOpenThread",
        "LdrLoadDll",
        "LdrGetProcedureAddress",
        // Token Manipulation
        "DuplicateTokenEx",
        "SetThreadToken",
        // Unhooking
        "NtProtectVirtualMemory",
        "VirtualProtect",
        "VirtualProtectEx",
        // Thread Manipulation
        "QueueUserAPC",
        "SetThreadContext",
        "NtSetContextThread",
        "NtSetInformationThread",
        // Persistence
        "CreateServiceA",
        "CreateServiceW",
        "ChangeServiceConfigA",
        "StartServiceA",
        "StartServiceW",
        "ITaskScheduler",
        "SchRpcRegisterTask",
        "IWbemServices",
        "IWbemEventConsumerProvider",
        // AMSI Bypass
        "AmsiScanBuffer",
        // Anti-Debug / Evasion
        "NtQuerySystemInformation",
        // Credential Access
        "CredEnumerateA",
        "CredEnumerateW",
        "CredReadA",
        "CredReadW",
        "SamEnumerateDomainsInSamServer",
    ];
    names.iter().cloned().collect()
}

fn medium_apis_set() -> HashSet<&'static str> {
    // From docs/OPSEC_TAB.md, "MediumRisk APIs (40 APIs)"
    let names = [
        // Token Manipulation
        "OpenProcessToken",
        // Anti-Debugging
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "QueryPerformanceCounter",
        "SetUnhandledExceptionFilter",
        "AddVectoredExceptionHandler",
        "NtQueryInformationThread",
        "NtQueryObject",
        // Process Injection
        "CreateFileMappingA",
        "CreateFileMappingW",
        "NtSuspendThread",
        "SuspendThread",
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "ReadProcessMemory",
        "FlushInstructionCache",
        // Persistence
        "RegSetValueExA",
        "RegCreateKeyExA",
        "RegSetValueExW",
        "RegCreateKeyExW",
        "RegDeleteValueA",
        "RegDeleteValueW",
        "OpenSCManagerA",
        "OpenSCManagerW",
        "DeleteService",
        "SHGetSpecialFolderPathA",
        "SHGetSpecialFolderPathW",
        "CoCreateInstance",
        "CoGetClassObject",
        // AMSI
        "AmsiInitialize",
        // Discovery
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
        "EnumProcesses",
        "EnumServicesStatusA",
        "EnumServicesStatusW",
    ];
    names.iter().cloned().collect()
}


