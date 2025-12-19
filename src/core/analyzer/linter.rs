//! BOF Linting System
//!
//! This module implements lint rules for static analysis of BOF files.
//! Each rule detects potential issues, suspicious patterns, or best practice violations.

use crate::core::models::bof::{BofFile, Import, MachineType, RelocationType};
use crate::core::models::lint::{LintFinding, Severity, Location};

/// Lint rule codes
pub mod codes {
    pub const BOF001: &str = "BOF001";
    pub const BOF002: &str = "BOF002";
    pub const BOF003: &str = "BOF003";
    pub const BOF004: &str = "BOF004";
    pub const BOF005: &str = "BOF005";
    pub const BOF006: &str = "BOF006";
    pub const BOF007: &str = "BOF007";
    pub const BOF008: &str = "BOF008";
    pub const BOF009: &str = "BOF009";
    pub const BOF010: &str = "BOF010";
    pub const BOF011: &str = "BOF011";
    pub const BOF012: &str = "BOF012";
}

/// High entropy threshold for detecting packed/encrypted sections
const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

/// Run all lint rules against a BOF file
pub fn run_lints(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    // Run all lint rules
    findings.extend(check_bof001_data_parse(bof));
    findings.extend(check_bof002_missing_entry_point(bof));
    findings.extend(check_bof003_entry_point_signature(bof));
    findings.extend(check_bof004_suspicious_apis(bof));
    findings.extend(check_bof005_direct_syscalls(bof));
    findings.extend(check_bof006_missing_cleanup(bof));
    findings.extend(check_bof007_unusual_section_flags(bof));
    findings.extend(check_bof008_high_entropy(bof));
    findings.extend(check_bof009_undefined_symbols(bof));
    findings.extend(check_bof010_unexpected_relocations(bof));
    findings.extend(check_bof011_loader_unfriendly_sections(bof));
    findings.extend(check_bof012_beacon_import_whitelist(bof));

    // Sort by severity (errors first, then warnings, then info)
    findings.sort_by(|a, b| {
        let severity_order = |s: &Severity| match s {
            Severity::Error => 0,
            Severity::Warning => 1,
            Severity::Info => 2,
        };
        severity_order(&a.severity).cmp(&severity_order(&b.severity))
    });

    findings
}

/// BOF001: BeaconDataExtract without BeaconDataParse
///
/// Detects when BeaconDataExtract is used without a corresponding BeaconDataParse call.
/// This typically indicates a bug where argument data is extracted without proper initialization.
fn check_bof001_data_parse(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    let has_data_parse = bof.imports.iter().any(|imp| {
        imp.library == "Beacon" && imp.function == "BeaconDataParse"
    });

    let has_data_extract = bof.imports.iter().any(|imp| {
        imp.library == "Beacon" && 
        (imp.function == "BeaconDataExtract" || 
         imp.function == "BeaconDataInt" ||
         imp.function == "BeaconDataShort" ||
         imp.function == "BeaconDataLength")
    });

    if has_data_extract && !has_data_parse {
        // Find the first data extraction function for location info
        let extract_import = bof.imports.iter().find(|imp| {
            imp.library == "Beacon" && 
            (imp.function == "BeaconDataExtract" || 
             imp.function == "BeaconDataInt" ||
             imp.function == "BeaconDataShort" ||
             imp.function == "BeaconDataLength")
        });

        findings.push(LintFinding {
            code: codes::BOF001.to_string(),
            severity: Severity::Error,
            message: "BeaconData* functions used without BeaconDataParse".to_string(),
            location: Location {
                symbol: extract_import.map(|imp| imp.symbol_name.clone()),
                section: None,
                address: None,
                line: None,
            },
            explanation: "BeaconDataExtract, BeaconDataInt, BeaconDataShort, and BeaconDataLength \
                require a prior call to BeaconDataParse to initialize the data parser. \
                Without initialization, these functions will read garbage data or crash."
                .to_string(),
            suggestion: Some(
                "Add a call to BeaconDataParse(&parser, args, len) before using other BeaconData* functions."
                    .to_string(),
            ),
        });
    }

    findings
}

/// BOF002: Missing entry point
///
/// Every BOF must have a 'go' function as its entry point.
fn check_bof002_missing_entry_point(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    if bof.entry_point.is_none() {
        // Check if there's a 'go' symbol that might not be properly detected
        let has_go_symbol = bof.symbols.iter().any(|s| s.name == "go" || s.name == "_go");
        
        if !has_go_symbol {
            findings.push(LintFinding {
                code: codes::BOF002.to_string(),
                severity: Severity::Error,
                message: "Missing entry point 'go' function".to_string(),
                location: Location {
                    symbol: None,
                    section: None,
                    address: None,
                    line: None,
                },
                explanation: "BOF files require a 'go' function as the entry point. This function \
                    is called by the Beacon when executing the BOF. The signature should be: \
                    void go(char* args, int len)"
                    .to_string(),
                suggestion: Some(
                    "Add an entry point function: void go(char* args, int len) { ... }".to_string(),
                ),
            });
        } else {
            // There's a 'go' symbol but it wasn't detected as entry point
            findings.push(LintFinding {
                code: codes::BOF002.to_string(),
                severity: Severity::Warning,
                message: "Entry point 'go' found but may not be properly exported".to_string(),
                location: Location {
                    symbol: Some("go".to_string()),
                    section: None,
                    address: None,
                    line: None,
                },
                explanation: "A 'go' symbol exists but was not detected as the entry point. \
                    This may indicate the function is static or not properly exported."
                    .to_string(),
                suggestion: Some(
                    "Ensure the 'go' function is not declared static and is properly exported."
                        .to_string(),
                ),
            });
        }
    }

    findings
}

/// BOF003: Invalid entry point signature
///
/// The 'go' function should have a specific signature: void go(char* args, int len)
/// We can detect some issues by checking if the symbol type looks correct.
fn check_bof003_entry_point_signature(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    if let Some(entry) = &bof.entry_point {
        // Check for common naming issues
        if entry.name != "go" && entry.name != "_go" {
            findings.push(LintFinding {
                code: codes::BOF003.to_string(),
                severity: Severity::Error,
                message: format!(
                    "Entry point has unexpected name: '{}' (expected 'go')",
                    entry.name
                ),
                location: Location {
                    symbol: Some(entry.name.clone()),
                    section: entry.section.and_then(|idx| {
                        bof.sections.get(idx).map(|s| s.name.clone())
                    }),
                    address: Some(entry.value),
                    line: None,
                },
                explanation: "The Beacon loader expects the entry point to be named 'go'. \
                    Other names will not be recognized."
                    .to_string(),
                suggestion: Some("Rename the entry point function to 'go'.".to_string()),
            });
        }

        // Check if entry point is in a code section
        if let Some(section_idx) = entry.section {
            if let Some(section) = bof.sections.get(section_idx) {
                let is_code_section = section.characteristics & 0x00000020 != 0; // IMAGE_SCN_CNT_CODE
                let is_executable = section.characteristics & 0x20000000 != 0; // IMAGE_SCN_MEM_EXECUTE
                
                if !is_code_section && !is_executable {
                    findings.push(LintFinding {
                        code: codes::BOF003.to_string(),
                        severity: Severity::Warning,
                        message: format!(
                            "Entry point 'go' is in non-executable section '{}'",
                            section.name
                        ),
                        location: Location {
                            symbol: Some(entry.name.clone()),
                            section: Some(section.name.clone()),
                            address: Some(entry.value),
                            line: None,
                        },
                        explanation: "The entry point function should be in an executable code section. \
                            Being in a non-executable section may cause issues."
                            .to_string(),
                        suggestion: Some(
                            "Ensure the 'go' function is compiled into the .text section.".to_string(),
                        ),
                    });
                }
            }
        }
    }

    findings
}

/// BOF004: Suspicious API patterns
///
/// Detects potentially dangerous or suspicious API usage patterns.
fn check_bof004_suspicious_apis(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    // Define suspicious API patterns with their risk descriptions
    let suspicious_patterns: Vec<(&str, &str, Severity, &str)> = vec![
        // Process injection APIs
        ("WriteProcessMemory", "Process memory write capability", Severity::Warning, 
         "WriteProcessMemory can be used for process injection. Ensure this is intentional."),
        ("VirtualAllocEx", "Remote memory allocation capability", Severity::Warning,
         "VirtualAllocEx allocates memory in another process, commonly used in injection."),
        ("CreateRemoteThread", "Remote thread creation capability", Severity::Warning,
         "CreateRemoteThread is a common injection technique that may trigger security tools."),
        ("NtCreateThreadEx", "Native thread creation capability", Severity::Warning,
         "NtCreateThreadEx is used for stealthier thread creation in remote processes."),
        ("QueueUserAPC", "APC injection capability", Severity::Info,
         "QueueUserAPC can be used for APC injection attacks."),
        ("SetThreadContext", "Thread context manipulation", Severity::Warning,
         "SetThreadContext is used in thread hijacking techniques."),
        
        // Credential/Token APIs
        ("MiniDumpWriteDump", "Memory dumping capability", Severity::Warning,
         "MiniDumpWriteDump can dump process memory, commonly used for credential theft."),
        ("LsaLookupAuthenticationPackage", "LSA access", Severity::Info,
         "Accessing LSA may indicate credential-related operations."),
        ("SamConnect", "SAM database access", Severity::Warning,
         "SAM database access may indicate credential dumping attempts."),
        ("LogonUser", "Token creation capability", Severity::Info,
         "LogonUser creates tokens, may be used for privilege operations."),
        
        // Registry persistence
        ("RegSetValueEx", "Registry modification capability", Severity::Info,
         "Registry modifications may be used for persistence."),
        ("RegCreateKeyEx", "Registry key creation capability", Severity::Info,
         "Registry key creation may be used for persistence."),
        
        // Network APIs that may indicate C2
        ("InternetOpen", "HTTP client capability", Severity::Info,
         "HTTP communication may indicate network activity separate from Beacon."),
        ("WinHttpOpen", "HTTP client capability", Severity::Info,
         "HTTP communication may indicate network activity separate from Beacon."),
        ("WSAStartup", "Socket capability", Severity::Info,
         "Socket usage may indicate direct network communication."),
        
        // Defense evasion
        ("NtUnmapViewOfSection", "Section unmapping capability", Severity::Warning,
         "Section unmapping is used in process hollowing techniques."),
        ("NtProtectVirtualMemory", "Memory protection manipulation", Severity::Info,
         "Direct syscall for memory protection changes."),
        ("AmsiScanBuffer", "AMSI interaction", Severity::Info,
         "AMSI interaction detected - may be checking or bypassing AMSI."),
    ];

    for import in &bof.imports {
        for (api_name, capability, severity, explanation) in &suspicious_patterns {
            if import.function.contains(api_name) {
                findings.push(LintFinding {
                    code: codes::BOF004.to_string(),
                    severity: *severity,
                    message: format!(
                        "Suspicious API detected: {} - {}",
                        import.function, capability
                    ),
                    location: Location {
                        symbol: Some(import.symbol_name.clone()),
                        section: None,
                        address: None,
                        line: None,
                    },
                    explanation: explanation.to_string(),
                    suggestion: Some(format!(
                        "Review the usage of {} to ensure it's necessary and intentional.",
                        import.function
                    )),
                });
            }
        }
    }

    // Check for suspicious API combinations
    let has_virtual_alloc_ex = bof.imports.iter().any(|i| i.function.contains("VirtualAllocEx"));
    let has_write_process_memory = bof.imports.iter().any(|i| i.function.contains("WriteProcessMemory"));
    let has_create_remote_thread = bof.imports.iter().any(|i| i.function.contains("CreateRemoteThread"));

    if has_virtual_alloc_ex && has_write_process_memory && has_create_remote_thread {
        findings.push(LintFinding {
            code: codes::BOF004.to_string(),
            severity: Severity::Warning,
            message: "Classic process injection pattern detected".to_string(),
            location: Location {
                symbol: None,
                section: None,
                address: None,
                line: None,
            },
            explanation: "This BOF uses VirtualAllocEx + WriteProcessMemory + CreateRemoteThread, \
                which is a well-known process injection pattern. This combination is commonly \
                flagged by security tools."
                .to_string(),
            suggestion: Some(
                "Consider using alternative injection techniques if stealth is required.".to_string(),
            ),
        });
    }

    findings
}

/// BOF005: Direct syscall detection
///
/// Detects patterns that indicate direct syscall usage.
fn check_bof005_direct_syscalls(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    // Check for Nt/Zw function imports that bypass ntdll
    let nt_functions: Vec<&Import> = bof.imports.iter()
        .filter(|imp| {
            (imp.function.starts_with("Nt") || imp.function.starts_with("Zw")) &&
            imp.library.to_lowercase() != "ntdll"
        })
        .collect();

    for nt_func in nt_functions {
        findings.push(LintFinding {
            code: codes::BOF005.to_string(),
            severity: Severity::Info,
            message: format!(
                "Native API {} imported from {} (not ntdll)",
                nt_func.function, nt_func.library
            ),
            location: Location {
                symbol: Some(nt_func.symbol_name.clone()),
                section: None,
                address: None,
                line: None,
            },
            explanation: "Native APIs (Nt*/Zw*) imported from libraries other than ntdll \
                may indicate direct syscall stubs or custom implementations."
                .to_string(),
            suggestion: None,
        });
    }

    // Check for syscall-related symbol names
    let syscall_indicators = ["syscall", "syswhisper", "halo", "freshycall", "indirect"];
    
    for symbol in &bof.symbols {
        let symbol_lower = symbol.name.to_lowercase();
        for indicator in &syscall_indicators {
            if symbol_lower.contains(indicator) {
                findings.push(LintFinding {
                    code: codes::BOF005.to_string(),
                    severity: Severity::Info,
                    message: format!(
                        "Possible syscall-related symbol: {}",
                        symbol.name
                    ),
                    location: Location {
                        symbol: Some(symbol.name.clone()),
                        section: symbol.section.and_then(|idx| {
                            bof.sections.get(idx).map(|s| s.name.clone())
                        }),
                        address: Some(symbol.value),
                        line: None,
                    },
                    explanation: format!(
                        "Symbol name contains '{}', which may indicate syscall stub usage \
                        (e.g., SysWhispers, HalosGate, etc.).",
                        indicator
                    ),
                    suggestion: Some(
                        "Direct syscalls can evade userland hooks but may be detected by kernel telemetry."
                            .to_string(),
                    ),
                });
                break;
            }
        }
    }

    // Check .text section for syscall instruction pattern (0F 05 on x64)
    if matches!(bof.header.machine, MachineType::X64) {
        for section in &bof.sections {
            if section.name == ".text" || (section.characteristics & 0x00000020 != 0) {
                // Look for syscall instruction: 0F 05
                let syscall_count = count_byte_pattern(&section.data, &[0x0F, 0x05]);
                
                if syscall_count > 0 {
                    findings.push(LintFinding {
                        code: codes::BOF005.to_string(),
                        severity: Severity::Warning,
                        message: format!(
                            "Found {} potential syscall instruction(s) in section '{}'",
                            syscall_count, section.name
                        ),
                        location: Location {
                            symbol: None,
                            section: Some(section.name.clone()),
                            address: None,
                            line: None,
                        },
                        explanation: "The syscall instruction (0F 05) was found in executable code. \
                            This indicates direct syscall usage, which bypasses ntdll hooks but \
                            may be detected by kernel-level monitoring."
                            .to_string(),
                        suggestion: Some(
                            "Ensure direct syscalls are intentional and understand the OPSEC implications."
                                .to_string(),
                        ),
                    });
                }
            }
        }
    }

    findings
}

/// BOF006: Missing cleanup (handles not closed)
///
/// Detects when handles are opened but corresponding close functions are not imported.
fn check_bof006_missing_cleanup(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    // Define handle-opening functions and their corresponding close functions
    let handle_pairs: Vec<(&str, &[&str])> = vec![
        ("CreateFile", &["CloseHandle"]),
        ("OpenProcess", &["CloseHandle"]),
        ("OpenThread", &["CloseHandle"]),
        ("CreateThread", &["CloseHandle"]),
        ("CreateEvent", &["CloseHandle"]),
        ("CreateMutex", &["CloseHandle"]),
        ("CreateSemaphore", &["CloseHandle"]),
        ("CreatePipe", &["CloseHandle"]),
        ("DuplicateHandle", &["CloseHandle"]),
        ("OpenProcessToken", &["CloseHandle"]),
        ("OpenThreadToken", &["CloseHandle"]),
        ("DuplicateToken", &["CloseHandle"]),
        ("RegOpenKey", &["RegCloseKey"]),
        ("RegCreateKey", &["RegCloseKey"]),
        ("FindFirstFile", &["FindClose"]),
        ("CreateToolhelp32Snapshot", &["CloseHandle"]),
        ("HeapCreate", &["HeapDestroy"]),
        ("VirtualAlloc", &["VirtualFree"]),
        ("LocalAlloc", &["LocalFree"]),
        ("GlobalAlloc", &["GlobalFree"]),
        ("HeapAlloc", &["HeapFree"]),
        ("MapViewOfFile", &["UnmapViewOfFile"]),
        ("CreateFileMapping", &["CloseHandle"]),
        ("LoadLibrary", &["FreeLibrary"]),
        ("socket", &["closesocket"]),
        ("WSASocket", &["closesocket"]),
        ("CoInitialize", &["CoUninitialize"]),
        ("CoCreateInstance", &["Release"]), // COM object
    ];

    // Check each handle-opening function
    for (open_func, close_funcs) in &handle_pairs {
        let has_open = bof.imports.iter().any(|imp| {
            imp.function.contains(open_func)
        });

        if has_open {
            let has_close = bof.imports.iter().any(|imp| {
                close_funcs.iter().any(|close| imp.function.contains(close))
            });

            if !has_close {
                findings.push(LintFinding {
                    code: codes::BOF006.to_string(),
                    severity: Severity::Warning,
                    message: format!(
                        "Resource opened with {} but no corresponding cleanup function found",
                        open_func
                    ),
                    location: Location {
                        symbol: bof.imports.iter()
                            .find(|imp| imp.function.contains(open_func))
                            .map(|imp| imp.symbol_name.clone()),
                        section: None,
                        address: None,
                        line: None,
                    },
                    explanation: format!(
                        "The BOF uses {} to open a resource but does not appear to import \
                        a corresponding cleanup function ({}). This may cause resource leaks.",
                        open_func,
                        close_funcs.join(" or ")
                    ),
                    suggestion: Some(format!(
                        "Consider adding {} to properly clean up resources.",
                        close_funcs[0]
                    )),
                });
            }
        }
    }

    findings
}

/// BOF007: Unusual section flags
///
/// Detects sections with unusual or suspicious flag combinations.
fn check_bof007_unusual_section_flags(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    // Section characteristic flags
    const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
    #[allow(dead_code)]
    const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
    #[allow(dead_code)]
    const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    #[allow(dead_code)]
    const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

    for section in &bof.sections {
        let chars = section.characteristics;
        
        // Check for writable and executable (W^X violation)
        let is_write = chars & IMAGE_SCN_MEM_WRITE != 0;
        let is_execute = chars & IMAGE_SCN_MEM_EXECUTE != 0;
        
        if is_write && is_execute {
            findings.push(LintFinding {
                code: codes::BOF007.to_string(),
                severity: Severity::Warning,
                message: format!(
                    "Section '{}' is both writable and executable (W^X violation)",
                    section.name
                ),
                location: Location {
                    symbol: None,
                    section: Some(section.name.clone()),
                    address: None,
                    line: None,
                },
                explanation: "Having a section that is both writable and executable violates \
                    the Write XOR Execute (W^X) security principle. This is suspicious and \
                    may be flagged by security tools."
                    .to_string(),
                suggestion: Some(
                    "Separate code and data into different sections with appropriate permissions."
                        .to_string(),
                ),
            });
        }

        // Check for code section without execute flag
        let is_code = chars & IMAGE_SCN_CNT_CODE != 0;
        if is_code && !is_execute {
            findings.push(LintFinding {
                code: codes::BOF007.to_string(),
                severity: Severity::Info,
                message: format!(
                    "Section '{}' is marked as code but not executable",
                    section.name
                ),
                location: Location {
                    symbol: None,
                    section: Some(section.name.clone()),
                    address: None,
                    line: None,
                },
                explanation: "This section contains code but is not marked as executable. \
                    The loader may need to adjust permissions at runtime."
                    .to_string(),
                suggestion: None,
            });
        }

        // Check for non-standard section names with execute permissions
        let standard_exec_sections = [".text", ".code"];
        if is_execute && !standard_exec_sections.contains(&section.name.as_str()) {
            // Allow sections that start with standard prefixes
            let is_standard_prefix = standard_exec_sections.iter()
                .any(|prefix| section.name.starts_with(prefix));
            
            if !is_standard_prefix {
                findings.push(LintFinding {
                    code: codes::BOF007.to_string(),
                    severity: Severity::Info,
                    message: format!(
                        "Non-standard section '{}' has execute permission",
                        section.name
                    ),
                    location: Location {
                        symbol: None,
                        section: Some(section.name.clone()),
                        address: None,
                        line: None,
                    },
                    explanation: "Executable code is typically in sections named '.text'. \
                        Non-standard section names with execute permissions may indicate \
                        obfuscation or custom build configurations."
                        .to_string(),
                    suggestion: None,
                });
            }
        }

        // Check for empty sections with non-zero virtual size (possible TLS or special section)
        if section.raw_size == 0 && section.virtual_size > 0 {
            findings.push(LintFinding {
                code: codes::BOF007.to_string(),
                severity: Severity::Info,
                message: format!(
                    "Section '{}' has zero raw size but non-zero virtual size",
                    section.name
                ),
                location: Location {
                    symbol: None,
                    section: Some(section.name.clone()),
                    address: None,
                    line: None,
                },
                explanation: "This section has no raw data but reserves virtual space. \
                    This is normal for .bss (uninitialized data) but unusual for other sections."
                    .to_string(),
                suggestion: None,
            });
        }
    }

    findings
}

/// BOF008: High entropy sections (packing detection)
///
/// Detects sections with unusually high entropy, which may indicate packing or encryption.
fn check_bof008_high_entropy(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    for section in &bof.sections {
        // Skip empty sections
        if section.data.is_empty() {
            continue;
        }

        if section.entropy >= HIGH_ENTROPY_THRESHOLD {
            // Determine severity based on section type
            let is_code = section.characteristics & 0x00000020 != 0;
            let severity = if is_code {
                Severity::Warning
            } else {
                Severity::Info
            };

            findings.push(LintFinding {
                code: codes::BOF008.to_string(),
                severity,
                message: format!(
                    "Section '{}' has high entropy ({:.2})",
                    section.name, section.entropy
                ),
                location: Location {
                    symbol: None,
                    section: Some(section.name.clone()),
                    address: None,
                    line: None,
                },
                explanation: format!(
                    "Section '{}' has an entropy of {:.2} (threshold: {:.1}). \
                    High entropy may indicate:\n\
                    - Packed or compressed code\n\
                    - Encrypted data\n\
                    - Embedded binary data\n\
                    - Random or obfuscated content\n\n\
                    This may trigger security tool alerts.",
                    section.name, section.entropy, HIGH_ENTROPY_THRESHOLD
                ),
                suggestion: Some(
                    "Consider if the high entropy is necessary. If this is packed/encrypted code, \
                    be aware it may be flagged by security tools."
                        .to_string(),
                ),
            });
        }

        // Also check for suspiciously low entropy in code sections (might indicate NOPs or padding)
        let is_code = section.characteristics & 0x00000020 != 0 || 
                      section.characteristics & 0x20000000 != 0;
        
        if is_code && section.entropy < 1.0 && section.data.len() > 100 {
            findings.push(LintFinding {
                code: codes::BOF008.to_string(),
                severity: Severity::Info,
                message: format!(
                    "Code section '{}' has unusually low entropy ({:.2})",
                    section.name, section.entropy
                ),
                location: Location {
                    symbol: None,
                    section: Some(section.name.clone()),
                    address: None,
                    line: None,
                },
                explanation: "Very low entropy in a code section may indicate excessive padding, \
                    NOP sleds, or repetitive instructions. This is unusual for normal compiled code."
                    .to_string(),
                suggestion: None,
            });
        }
    }

    findings
}

/// BOF009: Undefined symbols and special helper functions
///
/// Mirrors boflint.py behaviour by flagging undefined symbols that are not
/// normal import thunks, and giving specific diagnostics for common helpers
/// like stack probes and exception handlers.
fn check_bof009_undefined_symbols(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    // Helper lists (based on boflint.py)
    const STACK_CHECK_FUNCS: &[&str] = &["___chkstk_ms", "__chkstk"];
    const SECURITY_COOKIE_FUNCS: &[&str] = &["__stack_chk_fail", "__security_init_cookie"];
    const EXCEPTION_FUNCS: &[&str] = &["__C_specific_handler", "__cxa_begin_catch"];
    const MEM_FUNCS: &[&str] = &["memset", "memmove", "memcpy"];

    for symbol in &bof.symbols {
        // Undefined / external symbol
        if !symbol.is_external {
            continue;
        }

        // Skip normal import thunks (__imp_*) – those are handled via `imports`
        if symbol.name.starts_with("__imp_") {
            continue;
        }

        let mut base_name = symbol.name.as_str();
        // Strip stdcall-style suffixes (e.g., name@8)
        if let Some((name_only, _)) = base_name.split_once('@') {
            base_name = name_only;
        }

        let mut handled = false;
        let section_name = symbol
            .section
            .and_then(|idx| bof.sections.get(idx).map(|s| s.name.clone()));

        // Stack check functions
        if STACK_CHECK_FUNCS.contains(&base_name) {
            findings.push(LintFinding {
                code: codes::BOF009.to_string(),
                severity: Severity::Error,
                message: format!(
                    "Stack check helper '{}' referenced as undefined symbol",
                    base_name
                ),
                location: Location {
                    symbol: Some(symbol.name.clone()),
                    section: section_name.clone(),
                    address: Some(symbol.value),
                    line: None,
                },
                explanation: "This symbol is typically generated when large stack allocations \
                    or stack protection are enabled. BOFs should avoid compiler-inserted stack \
                    probes and security cookies because the corresponding runtime support code \
                    is not available in the Beacon environment."
                    .to_string(),
                suggestion: Some(
                    "Reduce large stack allocations and disable stack protection / security \
                    cookies for the BOF module."
                        .to_string(),
                ),
            });
            handled = true;
        }

        // Security cookie / stack protector helpers
        if !handled
            && (SECURITY_COOKIE_FUNCS.contains(&base_name)
                || base_name.contains("security_check_cookie"))
        {
            findings.push(LintFinding {
                code: codes::BOF009.to_string(),
                severity: Severity::Error,
                message: format!(
                    "Security cookie helper '{}' referenced as undefined symbol",
                    base_name
                ),
                location: Location {
                    symbol: Some(symbol.name.clone()),
                    section: section_name.clone(),
                    address: Some(symbol.value),
                    line: None,
                },
                explanation: "This symbol is used by compiler-inserted security cookie / stack \
                    protection machinery. BOFs should be compiled with these protections \
                    disabled, otherwise the runtime support code will be missing at load time."
                    .to_string(),
                suggestion: Some(
                    "Disable security cookies / stack protection for the BOF module."
                        .to_string(),
                ),
            });
            handled = true;
        }

        // Exception handling helpers
        if !handled
            && (EXCEPTION_FUNCS.contains(&base_name)
                || base_name.contains("except_handler")
                || base_name.contains("CxxFrameHandler"))
        {
            findings.push(LintFinding {
                code: codes::BOF009.to_string(),
                severity: Severity::Warning,
                message: format!(
                    "Exception handling helper '{}' referenced as undefined symbol",
                    base_name
                ),
                location: Location {
                    symbol: Some(symbol.name.clone()),
                    section: section_name.clone(),
                    address: Some(symbol.value),
                    line: None,
                },
                explanation: "This symbol is associated with structured exception handling (SEH) \
                    or C++ exception support. Traditional BOF loaders do not support full \
                    exception handling, and using it may cause crashes or undefined behaviour."
                    .to_string(),
                suggestion: Some(
                    "Avoid using compiler-level exception handling inside BOFs (disable C++ \
                    exceptions / SEH for this module)."
                        .to_string(),
                ),
            });
            handled = true;
        }

        // Memory helpers like memset/memcpy/memmove
        if !handled && MEM_FUNCS.contains(&base_name) {
            findings.push(LintFinding {
                code: codes::BOF009.to_string(),
                severity: Severity::Warning,
                message: format!(
                    "Standard C runtime function '{}' referenced as undefined symbol",
                    base_name
                ),
                location: Location {
                    symbol: Some(symbol.name.clone()),
                    section: section_name.clone(),
                    address: Some(symbol.value),
                    line: None,
                },
                explanation: "This symbol is a standard C runtime helper. Depending on the \
                    BOF loader, these helpers may or may not be shimmed automatically. \
                    Leaving them undefined can cause runtime failures."
                    .to_string(),
                suggestion: Some(
                    "Either link against a runtime that provides these helpers or replace \
                    them with inline implementations within the BOF."
                        .to_string(),
                ),
            });
            handled = true;
        }

        // Check if it's a known Beacon API (these are valid without __imp_ prefix)
        const BEACON_APIS: &[&str] = &[
            "BeaconPrintf", "BeaconOutput", "BeaconDownload",
            "BeaconDataParse", "BeaconDataPtr", "BeaconDataInt", 
            "BeaconDataShort", "BeaconDataLength", "BeaconDataExtract",
            "BeaconUseToken", "BeaconRevertToken", "BeaconIsAdmin",
            "BeaconGetSpawnTo", "BeaconSpawnTemporaryProcess", 
            "BeaconInjectProcess", "BeaconInjectTemporaryProcess", 
            "BeaconCleanupProcess",
            "BeaconFormatAlloc", "BeaconFormatReset", "BeaconFormatFree",
            "BeaconFormatAppend", "BeaconFormatPrintf", "BeaconFormatToString",
            "BeaconFormatInt", "BeaconFormatShort", "BeaconFormatLength",
            "BeaconVirtualAlloc", "BeaconVirtualAllocEx", "BeaconVirtualFree",
            "BeaconVirtualProtect", "BeaconVirtualProtectEx",
            "toWideChar",
            "BeaconInformation", "BeaconGetSyscallInformation",
            "BeaconAddValue", "BeaconGetValue", "BeaconRemoveValue",
            "BeaconGetIntValue", "BeaconGetShortValue", "BeaconGetCharValue",
            "BeaconGetPtrValue", "BeaconGetSizeValue", "BeaconGetDataValue",
            "BeaconDataStoreAlloc", "BeaconDataStoreReset", "BeaconDataStoreFree",
            "BeaconDataStoreAdd", "BeaconDataStoreGet", "BeaconDataStoreRemove",
            "BeaconDataStoreSize", "BeaconDataStoreGetItem",
            "BeaconDataStoreProtectItem", "BeaconDataStoreUnprotectItem",
            "BeaconDataStoreMaxEntries",
            "BeaconGetCustomUserData", "BeaconGetUserData",
            "BeaconGetThreadContext", "BeaconSetThreadContext", "BeaconResumeThread",
            "BeaconOpenProcess", "BeaconOpenThread", "BeaconCloseHandle",
            "BeaconUnmapViewOfFile", "BeaconVirtualQuery", "BeaconDuplicateHandle",
            "BeaconReadProcessMemory", "BeaconWriteProcessMemory",
            "BeaconDisableBeaconGate", "BeaconEnableBeaconGate",
            "BeaconDisableBeaconGateMasking", "BeaconEnableBeaconGateMasking",
        ];
        
        if !handled && BEACON_APIS.contains(&base_name) {
            // Beacon APIs are valid as external symbols without __imp_ prefix
            // They are resolved by the loader at runtime
            handled = true;
        }

        // Generic undefined symbol
        if !handled {
            findings.push(LintFinding {
                code: codes::BOF009.to_string(),
                severity: Severity::Error,
                message: format!("Undefined symbol '{}'", base_name),
                location: Location {
                    symbol: Some(symbol.name.clone()),
                    section: section_name.clone(),
                    address: Some(symbol.value),
                    line: None,
                },
                explanation: "This symbol is referenced but not defined in any section and is \
                    not recognised as a normal import thunk. The BOF is likely missing a \
                    dependency or was linked incorrectly."
                    .to_string(),
                suggestion: Some(
                    "Ensure all external references are either imported via __imp_ symbols or \
                    defined within the BOF object file."
                        .to_string(),
                ),
            });
        }
    }

    findings
}

/// BOF010: Unexpected / unknown relocation types
///
/// Flags relocations whose type could not be mapped to a known AMD64/x86
/// relocation kind. This mirrors boflint.py's warnings about unexpected
/// relocation types.
fn check_bof010_unexpected_relocations(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    let mut unknown_count = 0usize;
    let mut first_unknown: Option<&crate::core::models::bof::Relocation> = None;

    for reloc in &bof.relocations {
        if let RelocationType::Unknown(_raw) = reloc.relocation_type {
            unknown_count += 1;
            if first_unknown.is_none() {
                first_unknown = Some(reloc);
            }
        }
    }

    if unknown_count == 0 {
        return findings;
    }

    let (section_name, raw_type) = if let Some(reloc) = first_unknown {
        let section_name = bof
            .sections
            .get(reloc.section_index)
            .map(|s| s.name.clone());
        let raw_type = match reloc.relocation_type {
            RelocationType::Unknown(v) => v,
            _ => 0,
        };
        (section_name, raw_type)
    } else {
        (None, 0u16)
    };

    findings.push(LintFinding {
        code: codes::BOF010.to_string(),
        severity: Severity::Warning,
        message: format!(
            "Found {} relocation(s) with unknown or unexpected relocation type",
            unknown_count
        ),
        location: Location {
            symbol: None,
            section: section_name,
            address: None,
            line: None,
        },
        explanation: format!(
            "One or more relocation entries could not be mapped to a known AMD64/x86 relocation \
            kind. This may indicate non-standard relocation types that some loaders do not \
            support. First unknown relocation raw type value: 0x{:04X}.",
            raw_type
        ),
        suggestion: Some(
            "Review the toolchain and linker flags used to build the BOF. Prefer standard \
            relocation types (REL32/ADDR32/ADDR64) for maximum loader compatibility."
                .to_string(),
        ),
    });

    findings
}

/// BOF011: Loader-unfriendly sections (.bss / .rdata / .pdata)
///
/// Mirrors boflint.py's section warnings by flagging BOFs that rely on
/// initialised .rdata or non-empty .bss / .pdata sections, which are not
/// supported by all BOF loaders.
fn check_bof011_loader_unfriendly_sections(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    for section in &bof.sections {
        match section.name.as_str() {
            ".bss" => {
                if section.raw_size > 0 || section.virtual_size > 0 {
                    findings.push(LintFinding {
                        code: codes::BOF011.to_string(),
                        severity: Severity::Warning,
                        message: "Section '.bss' contains data – not all loaders support \
                            uninitialised data sections in BOFs"
                            .to_string(),
                        location: Location {
                            symbol: None,
                            section: Some(section.name.clone()),
                            address: None,
                            line: None,
                        },
                        explanation: "Some BOF loaders assume that BOFs only contain code and \
                            a small amount of initialised data. Relying on a non-empty .bss \
                            section for uninitialised globals may break in environments that \
                            do not allocate or zero this section."
                            .to_string(),
                        suggestion: Some(
                            "Prefer heap allocations or explicit stack variables instead of \
                            relying on .bss for BOFs, or verify that your target loader \
                            supports .bss."
                                .to_string(),
                        ),
                    });
                }
            }
            ".rdata" => {
                if section.raw_size > 0 {
                    findings.push(LintFinding {
                        code: codes::BOF011.to_string(),
                        severity: Severity::Warning,
                        message: "Section '.rdata' contains read-only data – not all loaders \
                            support dedicated read-only sections in BOFs"
                            .to_string(),
                        location: Location {
                            symbol: None,
                            section: Some(section.name.clone()),
                            address: None,
                            line: None,
                        },
                        explanation: "Read-only data in a dedicated .rdata section is common \
                            for normal PE files, but some BOF loaders only map the .text/.data \
                            segments and may ignore .rdata entirely."
                            .to_string(),
                        suggestion: Some(
                            "Consider moving constant data into .data or into code \
                            (e.g., encoded literals) if you need to support loaders that \
                            do not handle .rdata."
                                .to_string(),
                        ),
                    });
                }
            }
            ".pdata" => {
                if section.raw_size > 0 {
                    findings.push(LintFinding {
                        code: codes::BOF011.to_string(),
                        severity: Severity::Warning,
                        message: "Section '.pdata' is present – this usually indicates \
                            exception handling metadata, which many BOF loaders do not support"
                            .to_string(),
                        location: Location {
                            symbol: None,
                            section: Some(section.name.clone()),
                            address: None,
                            line: None,
                        },
                        explanation: ".pdata typically contains unwind / exception handling \
                            metadata. Many BOF loaders do not register or honour this data, \
                            so relying on structured exception handling may cause crashes."
                            .to_string(),
                        suggestion: Some(
                            "Avoid C++ exceptions and compiler-generated SEH in BOFs, or \
                            verify that your target loader supports .pdata."
                                .to_string(),
                        ),
                    });
                }
            }
            _ => {}
        }
    }

    findings
}

/// BOF012: Beacon API import whitelist
///
/// Mirrors boflint.py's behaviour by enforcing a whitelist of recognised
/// Beacon/loader APIs for imports classified as coming from the \"Beacon\"
/// library.
fn check_bof012_beacon_import_whitelist(bof: &BofFile) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    // Union of known implant function sets from boflint.py
    const BEACON_ALLOWED_FUNCS: &[&str] = &[
        // CS-style
        "BeaconDataParse",
        "BeaconDataPtr",
        "BeaconDataInt",
        "BeaconDataShort",
        "BeaconDataLength",
        "BeaconDataExtract",
        "BeaconFormatAlloc",
        "BeaconFormatReset",
        "BeaconFormatAppend",
        "BeaconFormatPrintf",
        "BeaconFormatToString",
        "BeaconFormatFree",
        "BeaconFormatInt",
        "BeaconOutput",
        "BeaconPrintf",
        "BeaconUseToken",
        "BeaconRevertToken",
        "BeaconIsAdmin",
        "BeaconGetSpawnTo",
        "BeaconInjectProcess",
        "BeaconInjectTemporaryProcess",
        "BeaconSpawnTemporaryProcess",
        "BeaconCleanupProcess",
        "toWideChar",
        "BeaconInformation",
        "BeaconAddValue",
        "BeaconGetValue",
        "BeaconRemoveValue",
        "BeaconDataStoreGetItem",
        "BeaconDataStoreProtectItem",
        "BeaconDataStoreUnprotectItem",
        "BeaconDataStoreMaxEntries",
        "BeaconGetCustomUserData",
        "BeaconGetSyscallInformation",
        "BeaconVirtualAlloc",
        "BeaconVirtualAllocEx",
        "BeaconVirtualProtect",
        "BeaconVirtualProtectEx",
        "BeaconVirtualFree",
        "BeaconGetThreadContext",
        "BeaconSetThreadContext",
        "BeaconResumeThread",
        "BeaconOpenProcess",
        "BeaconOpenThread",
        "BeaconCloseHandle",
        "BeaconUnmapViewOfFile",
        "BeaconVirtualQuery",
        "BeaconDuplicateHandle",
        "BeaconReadProcessMemory",
        "BeaconWriteProcessMemory",
        "BeaconDisableBeaconGate",
        "BeaconEnableBeaconGate",
        // Common OS imports that boflint treats specially
        "GetProcAddress",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "LoadLibraryA",
        "LoadLibraryW",
        "FreeLibrary",
        // OC2 additions
        "BeaconThrow",
    ];

    for import in &bof.imports {
        if import.library != "Beacon" {
            continue;
        }

        if !BEACON_ALLOWED_FUNCS.contains(&import.function.as_str()) {
            findings.push(LintFinding {
                code: codes::BOF012.to_string(),
                severity: Severity::Error,
                message: format!(
                    "Imported symbol '{}' is not a recognised Beacon/loader API",
                    import.function
                ),
                location: Location {
                    symbol: Some(import.symbol_name.clone()),
                    section: None,
                    address: None,
                    line: None,
                },
                explanation: "This import is classified as coming from the \"Beacon\" library \
                    but is not in the known list of Beacon/loader APIs. This usually indicates \
                    that a regular Win32 or CRT function was misclassified as Beacon API or \
                    that the import name is incorrect."
                    .to_string(),
                suggestion: Some(
                    "Verify that the import name matches a real Beacon API, or adjust the \
                    build so normal Win32/CRT functions are imported from their proper DLLs \
                    (e.g., KERNEL32, msvcrt)."
                        .to_string(),
                ),
            });
        }
    }

    findings
}

/// Count occurrences of a byte pattern in data
fn count_byte_pattern(data: &[u8], pattern: &[u8]) -> usize {
    if pattern.is_empty() || data.len() < pattern.len() {
        return 0;
    }

    data.windows(pattern.len())
        .filter(|window| *window == pattern)
        .count()
}

/// Filter lint findings by severity
#[allow(dead_code)]
pub fn filter_by_severity(findings: &[LintFinding], min_severity: Severity) -> Vec<&LintFinding> {
    findings.iter()
        .filter(|f| {
            match (min_severity, f.severity) {
                (Severity::Error, Severity::Error) => true,
                (Severity::Warning, Severity::Error) |
                (Severity::Warning, Severity::Warning) => true,
                (Severity::Info, _) => true,
                _ => false,
            }
        })
        .collect()
}

/// Get summary statistics for lint findings
pub fn get_lint_summary(findings: &[LintFinding]) -> LintSummary {
    let error_count = findings.iter().filter(|f| f.severity == Severity::Error).count();
    let warning_count = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    let info_count = findings.iter().filter(|f| f.severity == Severity::Info).count();

    LintSummary {
        total: findings.len(),
        errors: error_count,
        warnings: warning_count,
        infos: info_count,
    }
}

/// Summary of lint findings
#[derive(Debug, Clone)]
pub struct LintSummary {
    pub total: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
}

impl std::fmt::Display for LintSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} issues ({} errors, {} warnings, {} info)",
            self.total, self.errors, self.warnings, self.infos
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_byte_pattern() {
        let data = vec![0x0F, 0x05, 0x90, 0x0F, 0x05];
        assert_eq!(count_byte_pattern(&data, &[0x0F, 0x05]), 2);
        
        let data2 = vec![0x90, 0x90, 0x90];
        assert_eq!(count_byte_pattern(&data2, &[0x0F, 0x05]), 0);
    }

    #[test]
    fn test_lint_summary() {
        let findings = vec![
            LintFinding {
                code: "TEST".to_string(),
                severity: Severity::Error,
                message: "test".to_string(),
                location: Location {
                    symbol: None,
                    section: None,
                    address: None,
                    line: None,
                },
                explanation: "test".to_string(),
                suggestion: None,
            },
            LintFinding {
                code: "TEST".to_string(),
                severity: Severity::Warning,
                message: "test".to_string(),
                location: Location {
                    symbol: None,
                    section: None,
                    address: None,
                    line: None,
                },
                explanation: "test".to_string(),
                suggestion: None,
            },
        ];

        let summary = get_lint_summary(&findings);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.warnings, 1);
        assert_eq!(summary.infos, 0);
    }
}

