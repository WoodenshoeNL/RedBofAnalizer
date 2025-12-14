//! YARA rule matching module
//!
//! This module provides YARA rule matching against BOF files.
//! It scans BOF sections and code for patterns defined in YARA rules.

use crate::core::models::bof::BofFile;
use anyhow::{Result, Context};
use std::path::PathBuf;
use std::collections::{HashMap, HashSet};

#[cfg(feature = "yara")]
use yara::{Compiler, Rules, MetadataValue};
use hex;

/// YARA analysis result
#[derive(Debug, Clone, serde::Serialize)]
pub struct YaraAnalysis {
    /// YARA matches found
    pub matches: Vec<YaraMatch>,
    /// Statistics
    pub stats: YaraStats,
    /// Whether YARA engine is available
    pub engine_available: bool,
    /// Compilation errors (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compilation_errors: Option<Vec<String>>,
}

/// A single YARA rule match
#[derive(Debug, Clone, serde::Serialize)]
pub struct YaraMatch {
    /// Rule name that matched
    pub rule_name: String,
    /// Rule namespace (if any)
    pub namespace: Option<String>,
    /// Section where match occurred
    pub section: String,
    /// Offset within section
    pub offset: u64,
    /// Length of match
    pub length: usize,
    /// Matched strings/patterns
    pub matched_strings: Vec<MatchedString>,
    /// Rule metadata (tags, description, etc.)
    pub metadata: HashMap<String, String>,
    /// Severity level (if defined in rule)
    pub severity: Option<String>,
}

/// A matched string from a YARA rule
#[derive(Debug, Clone, serde::Serialize)]
pub struct MatchedString {
    /// String identifier from rule
    pub identifier: String,
    /// Offset where string was found
    pub offset: u64,
    /// Matched data (hex encoded for binary matches)
    pub data: String,
}

/// YARA statistics
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct YaraStats {
    /// Total rules loaded
    pub rules_loaded: usize,
    /// Total matches found
    pub total_matches: usize,
    /// Unique rules that matched
    pub unique_rules_matched: usize,
    /// Sections scanned
    pub sections_scanned: usize,
}

/// YARA rule source
#[derive(Debug, Clone)]
#[allow(dead_code)] // Will be used when YARA bindings are integrated
pub enum YaraRuleSource {
    /// Load from file
    File(PathBuf),
    /// Load from string
    String(String),
    /// Load from directory (all .yar files)
    Directory(PathBuf),
}

/// Analyze BOF with YARA rules
pub fn analyze_with_yara(
    bof: &BofFile,
    rule_sources: &[YaraRuleSource],
    use_default_rules: bool,
) -> Result<YaraAnalysis> {
    #[cfg(feature = "yara")]
    {
        // Try to initialize YARA compiler
        let compiler = match Compiler::new() {
            Ok(c) => c,
            Err(e) => {
                // YARA not available, return empty results
                log::warn!("YARA compiler initialization failed: {}", e);
        return Ok(YaraAnalysis {
            matches: Vec::new(),
            stats: YaraStats::default(),
            engine_available: false,
            compilation_errors: None,
        });
            }
        };
    
    // Compile rules and collect any errors
    let (compiled_rules, compilation_errors) = match compile_yara_rules(rule_sources, compiler, use_default_rules) {
        Ok(rules) => (rules, None),
        Err(e) => {
            // Failed to compile rules, but engine is available
            let error_msg = e.to_string();
            log::warn!("YARA rule compilation failed: {}", error_msg);
            
            // Extract individual error lines from the error message
            let errors: Vec<String> = error_msg
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            
            return Ok(YaraAnalysis {
                matches: Vec::new(),
                stats: YaraStats {
                    rules_loaded: 0,
                    total_matches: 0,
                    unique_rules_matched: 0,
                    sections_scanned: 0,
                },
                engine_available: true,
                compilation_errors: Some(errors),
            });
        }
    };
    
    // Scan all BOF sections
    let mut all_matches = Vec::new();
    let mut unique_rules = HashSet::new();
    let mut sections_scanned = 0;
    
    // First, scan all section data
    for section in &bof.sections {
        if section.data.is_empty() {
            continue;
        }
        
        sections_scanned += 1;
        
        // Scan this section - Rules::scan_mem returns Result<Vec<Rule>, Error>
        let scan_results = match compiled_rules.scan_mem(&section.data, 0) {
            Ok(results) => results,
            Err(e) => {
                // Log error but continue with other sections
                log::warn!("YARA scan failed for section {}: {}", section.name, e);
                continue;
            }
        };
        
        // Process matches from this section
        for rule_match in scan_results {
            // Get rule identifier directly from the Rule struct (field, not method)
            let rule_identifier = rule_match.identifier.to_string();
            unique_rules.insert(rule_identifier.clone());
            
            // Extract metadata from the rule
            let mut metadata = HashMap::new();
            let mut severity = None;
            
            // Iterate over rule metadata (tags and metadata values)
            for meta in &rule_match.metadatas {
                let key = meta.identifier.to_string();
                let value_str = match &meta.value {
                    MetadataValue::Integer(i) => i.to_string(),
                    MetadataValue::String(s) => s.to_string(),
                    MetadataValue::Boolean(b) => b.to_string(),
                };
                metadata.insert(key.clone(), value_str.clone());
                
                // Extract severity if present in metadata
                if key == "severity" {
                    severity = Some(value_str);
                }
            }
            
            // Extract matched strings from the rule
            let mut matched_strings = Vec::new();
            let mut min_offset = u64::MAX;
            let mut max_offset = 0u64;
            
            for string_match in &rule_match.strings {
                let string_identifier = string_match.identifier.to_string();
                
                // Iterate over match instances for this string
                for match_instance in &string_match.matches {
                    let offset = match_instance.offset as u64;
                    let data = &match_instance.data;
                    
                    // Track overall match bounds
                    if offset < min_offset {
                        min_offset = offset;
                    }
                    let match_end = offset + data.len() as u64;
                    if match_end > max_offset {
                        max_offset = match_end;
                    }
                    
                    // Encode matched data as hex for binary matches, or as string for text
                    let data_str = if data.iter().all(|&b| b.is_ascii() && (b.is_ascii_alphanumeric() || b.is_ascii_punctuation() || b.is_ascii_whitespace())) {
                        // Printable ASCII - show as string
                        String::from_utf8_lossy(data).to_string()
                    } else {
                        // Binary data - encode as hex
                        hex::encode(data)
                    };
                    
                    matched_strings.push(MatchedString {
                        identifier: string_identifier.clone(),
                        offset,
                        data: data_str,
                    });
                }
            }
            
            // Calculate overall match offset and length
            let offset = if min_offset != u64::MAX { min_offset } else { 0 };
            let length = if max_offset > offset { (max_offset - offset) as usize } else { 0 };
            
            all_matches.push(YaraMatch {
                rule_name: rule_identifier,
                namespace: None, // Namespace extraction - verify API if needed
                section: section.name.clone(),
                offset,
                length,
                matched_strings,
                metadata,
                severity,
            });
        }
    }
    
    // Also scan symbol names (import symbols contain API names)
    // Create a virtual section with all symbol names concatenated
    let mut symbol_data = Vec::new();
    for symbol in &bof.symbols {
        symbol_data.extend_from_slice(symbol.name.as_bytes());
        symbol_data.push(0); // Null terminator between names
    }
    
    if !symbol_data.is_empty() {
        sections_scanned += 1;
        if let Ok(scan_results) = compiled_rules.scan_mem(&symbol_data, 0) {
            // Process matches from symbol table
            for rule_match in scan_results {
                let rule_identifier = rule_match.identifier.to_string();
                unique_rules.insert(rule_identifier.clone());
                
                // Extract metadata from the rule
                let mut metadata = HashMap::new();
                let mut severity = None;
                
                for meta in &rule_match.metadatas {
                    let key = meta.identifier.to_string();
                    let value_str = match &meta.value {
                        MetadataValue::Integer(i) => i.to_string(),
                        MetadataValue::String(s) => s.to_string(),
                        MetadataValue::Boolean(b) => b.to_string(),
                    };
                    metadata.insert(key.clone(), value_str.clone());
                    
                    if key == "severity" {
                        severity = Some(value_str);
                    }
                }
                
                // Extract matched strings from the rule
                let mut matched_strings = Vec::new();
                let mut min_offset = u64::MAX;
                let mut max_offset = 0u64;
                
                for string_match in &rule_match.strings {
                    let string_identifier = string_match.identifier.to_string();
                    
                    for match_instance in &string_match.matches {
                        let offset = match_instance.offset as u64;
                        let data = &match_instance.data;
                        
                        if offset < min_offset {
                            min_offset = offset;
                        }
                        let match_end = offset + data.len() as u64;
                        if match_end > max_offset {
                            max_offset = match_end;
                        }
                        
                        let data_str = if data.iter().all(|&b| b.is_ascii() && (b.is_ascii_alphanumeric() || b.is_ascii_punctuation() || b.is_ascii_whitespace())) {
                            String::from_utf8_lossy(data).to_string()
                        } else {
                            hex::encode(data)
                        };
                        
                        matched_strings.push(MatchedString {
                            identifier: string_identifier.clone(),
                            offset,
                            data: data_str,
                        });
                    }
                }
                
                let offset = if min_offset != u64::MAX { min_offset } else { 0 };
                let length = if max_offset > offset { (max_offset - offset) as usize } else { 0 };
                
                all_matches.push(YaraMatch {
                    rule_name: rule_identifier,
                    namespace: None,
                    section: ".symbols".to_string(),
                    offset,
                    length,
                    matched_strings,
                    metadata,
                    severity,
                });
            }
        }
    }
    
    // Count total rules loaded from the compiled Rules object
    let total_rules_loaded = compiled_rules.get_rules().len();
    let total_matches = all_matches.len();
    let unique_rules_matched = unique_rules.len();
    
    Ok(YaraAnalysis {
        matches: all_matches,
        stats: YaraStats {
            rules_loaded: total_rules_loaded,
            total_matches,
            unique_rules_matched,
            sections_scanned,
        },
        engine_available: true,
        compilation_errors: compilation_errors,
    })
    }
    
    #[cfg(not(feature = "yara"))]
    {
        // YARA feature not enabled
        Ok(YaraAnalysis {
            matches: Vec::new(),
            stats: YaraStats::default(),
            engine_available: false,
        })
    }
}

/// Compile YARA rules from various sources
#[cfg(feature = "yara")]
fn compile_yara_rules(rule_sources: &[YaraRuleSource], mut compiler: Compiler, use_default_rules: bool) -> Result<Rules> {
    let mut errors = Vec::new();
    
    // Add default rules if requested or if no custom rules provided
    if use_default_rules || rule_sources.is_empty() {
        let default_rules = create_default_bof_rules();
        compiler = compiler.add_rules_str(&default_rules)
            .map_err(|e| {
                let error_msg = format!("Failed to add default YARA rules: {}", e);
                errors.push(error_msg.clone());
                log::warn!("{}", error_msg);
                e
            })?;
    }
    
    // Load rules from provided sources
    // Continue loading other rules even if some fail
    if !rule_sources.is_empty() {
        // Note: add_rules_* methods consume and return the compiler
        for source in rule_sources {
            match source {
                YaraRuleSource::File(path) => {
                    // Check if file exists first
                    if !path.exists() {
                        let error_msg = format!("YARA rule file does not exist: {:?}", path);
                        errors.push(error_msg.clone());
                        log::warn!("{}", error_msg);
                        return Err(anyhow::anyhow!(error_msg));
                    }
                    if !path.is_file() {
                        let error_msg = format!("YARA rule path is not a file: {:?}", path);
                        errors.push(error_msg.clone());
                        log::warn!("{}", error_msg);
                        return Err(anyhow::anyhow!(error_msg));
                    }
                    
                    // Try to read the file first to give a better error message
                    match std::fs::read_to_string(&path) {
                        Ok(_) => {
                            // File is readable, try to add it
                            compiler = compiler.add_rules_file(&path)
                                .map_err(|e| {
                                    let error_msg = format!("Failed to compile YARA rules from {:?}: {}\nThis usually means the YARA rule file has syntax errors. Check the file for issues.", path, e);
                                    errors.push(error_msg.clone());
                                    log::warn!("{}", error_msg);
                                    anyhow::anyhow!(error_msg)
                                })?;
                            log::info!("Successfully loaded YARA rule file: {:?}", path);
                        }
                        Err(e) => {
                            let error_msg = format!("Failed to read YARA rule file {:?}: {}", path, e);
                            errors.push(error_msg.clone());
                            log::warn!("{}", error_msg);
                            return Err(anyhow::anyhow!(error_msg));
                        }
                    }
                }
                YaraRuleSource::String(rules_str) => {
                    compiler = compiler.add_rules_str(rules_str)
                        .map_err(|e| {
                            let error_msg = format!("Failed to add YARA rules from string: {}", e);
                            errors.push(error_msg.clone());
                            log::warn!("{}", error_msg);
                            e
                        })?;
                }
                YaraRuleSource::Directory(dir) => {
                    // Check if directory exists first
                    if !dir.exists() {
                        errors.push(format!("YARA rules directory does not exist: {:?}", dir));
                        continue;
                    }
                    if !dir.is_dir() {
                        errors.push(format!("YARA rules path is not a directory: {:?}", dir));
                        continue;
                    }
                    
                    // Load all .yar files from directory
                    match std::fs::read_dir(dir) {
                        Ok(entries) => {
                            for entry in entries {
                                match entry {
                                    Ok(entry) => {
                                        let path = entry.path();
                                        if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                                            compiler = compiler.add_rules_file(&path)
                                                .map_err(|e| {
                                                    let error_msg = format!("Failed to load YARA rules from {:?}: {}", path, e);
                                                    errors.push(error_msg.clone());
                                                    log::warn!("{}", error_msg);
                                                    e
                                                })?;
                                            log::info!("Successfully loaded YARA rule file: {:?}", path);
                                        }
                                    }
                                    Err(e) => {
                                        let error_msg = format!("Failed to read directory entry: {}", e);
                                        errors.push(error_msg);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let error_msg = format!("Failed to read directory {:?}: {}", dir, e);
                            errors.push(error_msg);
                        }
                    }
                }
            }
        }
    }
    
    // Compile all rules - compile_rules consumes the compiler
    match compiler.compile_rules() {
        Ok(rules) => {
            // Log warnings if there were errors loading some rules, but compilation succeeded
            if !errors.is_empty() {
                log::warn!("YARA rule compilation succeeded with {} warning(s):", errors.len());
                for error in &errors {
                    log::warn!("  {}", error);
                }
            }
            Ok(rules)
        }
        Err(e) => {
            // If compilation fails, include all accumulated errors
            let mut full_error = format!("Failed to compile YARA rules: {}", e);
            if !errors.is_empty() {
                full_error.push_str("\nAdditional errors encountered:");
                for error in &errors {
                    full_error.push_str(&format!("\n  {}", error));
                }
            }
            Err(anyhow::anyhow!(full_error))
        }
    }
}

/// Create default BOF-specific YARA rules
/// Rules are organized into categories: Security, Functionality, and OpSec
pub fn create_default_bof_rules() -> String {
    r#"// Default BOF-specific YARA rules
// These rules detect common BOF patterns and behaviors
// Organized by category: Security, Functionality, OpSec

// ============================================================================
// FUNCTIONALITY CATEGORY - Beacon API and Standard Operations
// ============================================================================

rule BOF_BeaconAPI {
    meta:
        category = "functionality"
        description = "Detects Beacon API usage in BOF"
        severity = "info"
        tags = "beacon,api"
    strings:
        // Plain API names (might appear in strings or comments)
        $beacon_api1 = "BeaconPrintf" ascii
        $beacon_api2 = "BeaconDataParse" ascii
        $beacon_api3 = "BeaconOutput" ascii
        $beacon_api4 = "BeaconUseToken" ascii
        $beacon_api5 = "BeaconInjectProcess" ascii
        $beacon_api6 = "BeaconSpawnTemporaryProcess" ascii
        $beacon_api7 = "BeaconRevertToken" ascii
        $beacon_api8 = "BeaconIsAdmin" ascii
        $beacon_api9 = "BeaconFormatAlloc" ascii
        $beacon_api10 = "BeaconVirtualAlloc" ascii
        $beacon_api11 = "BeaconDownload" ascii
        // Import symbol patterns (appear in symbol table)
        $beacon_imp1 = "__imp_BeaconPrintf" ascii
        $beacon_imp2 = "__imp_BeaconDataParse" ascii
        $beacon_imp3 = "__imp_BeaconOutput" ascii
        $beacon_imp4 = "__imp_BeaconUseToken" ascii
        $beacon_imp5 = "__imp_BeaconInjectProcess" ascii
        // Alternative import format
        $beacon_imp6 = "__imp_BEACON$BeaconPrintf" ascii
        $beacon_imp7 = "__imp_BEACON$BeaconDataParse" ascii
        $beacon_imp8 = "__imp_BEACON$BeaconOutput" ascii
    condition:
        any of them
}

rule BOF_EntryPoint {
    meta:
        category = "functionality"
        description = "Detects BOF entry point function"
        severity = "info"
        tags = "entry,function"
    strings:
        $go_function = "go" ascii
        $go_imp = "__imp_go" ascii
    condition:
        any of them
}

rule BOF_FileOperations {
    meta:
        category = "functionality"
        description = "Detects file system operations"
        severity = "low"
        tags = "file,io"
    strings:
        $create_file = "CreateFile" ascii
        $read_file = "ReadFile" ascii
        $write_file = "WriteFile" ascii
        $delete_file = "DeleteFile" ascii
        $find_first = "FindFirstFile" ascii
        $find_next = "FindNextFile" ascii
        $get_file_attr = "GetFileAttributes" ascii
        $imp_create = "__imp_KERNEL32$CreateFile" ascii
        $imp_read = "__imp_KERNEL32$ReadFile" ascii
        $imp_write = "__imp_KERNEL32$WriteFile" ascii
    condition:
        2 of them
}

rule BOF_RegistryOperations {
    meta:
        category = "functionality"
        description = "Detects registry operations"
        severity = "low"
        tags = "registry"
    strings:
        $reg_open = "RegOpenKey" ascii
        $reg_query = "RegQueryValue" ascii
        $reg_set = "RegSetValue" ascii
        $reg_create = "RegCreateKey" ascii
        $reg_delete = "RegDeleteKey" ascii
        $imp_reg_open = "__imp_ADVAPI32$RegOpenKey" ascii
        $imp_reg_query = "__imp_ADVAPI32$RegQueryValue" ascii
        $imp_reg_set = "__imp_ADVAPI32$RegSetValue" ascii
    condition:
        2 of them
}

rule BOF_NetworkActivity {
    meta:
        category = "functionality"
        description = "Detects network-related APIs"
        severity = "medium"
        tags = "network"
    strings:
        $socket = "socket" ascii
        $connect = "connect" ascii
        $send = "send" ascii
        $recv = "recv" ascii
        $wsa = "WSA" ascii
        $wininet = "InternetOpen" ascii
        $winhttp = "WinHttp" ascii
        $http_send = "HttpSendRequest" ascii
    condition:
        2 of them
}

rule BOF_SystemInfo {
    meta:
        category = "functionality"
        description = "Detects system information gathering APIs"
        severity = "low"
        tags = "reconnaissance"
    strings:
        $get_computer = "GetComputerName" ascii
        $get_username = "GetUserName" ascii
        $get_system = "GetSystemInfo" ascii
        $get_version = "GetVersion" ascii
        $get_hostname = "gethostname" ascii
        $imp_computer = "__imp_KERNEL32$GetComputerName" ascii
        $imp_username = "__imp_ADVAPI32$GetUserName" ascii
    condition:
        2 of them
}

// ============================================================================
// SECURITY CATEGORY - High-Risk Operations and Techniques
// ============================================================================

rule BOF_ProcessInjection {
    meta:
        category = "security"
        description = "Detects process injection patterns"
        severity = "high"
        tags = "injection,process"
    strings:
        // Plain API names
        $virtual_alloc = "VirtualAlloc" ascii
        $virtual_alloc_ex = "VirtualAllocEx" ascii
        $write_memory = "WriteProcessMemory" ascii
        $read_memory = "ReadProcessMemory" ascii
        $create_remote = "CreateRemoteThread" ascii
        $open_process = "OpenProcess" ascii
        // Import symbol patterns
        $imp_virtual = "__imp_KERNEL32$VirtualAlloc" ascii
        $imp_virtual_ex = "__imp_KERNEL32$VirtualAllocEx" ascii
        $imp_write = "__imp_KERNEL32$WriteProcessMemory" ascii
        $imp_create = "__imp_KERNEL32$CreateRemoteThread" ascii
        $imp_open = "__imp_KERNEL32$OpenProcess" ascii
    condition:
        3 of them
}

rule BOF_DirectSyscalls {
    meta:
        category = "security"
        description = "Detects direct syscall usage (Nt* functions)"
        severity = "critical"
        tags = "syscall,unhooking"
    strings:
        // Nt* syscall patterns
        $nt_create_thread = "NtCreateThreadEx" ascii
        $nt_write_virtual = "NtWriteVirtualMemory" ascii
        $nt_read_virtual = "NtReadVirtualMemory" ascii
        $nt_allocate_virtual = "NtAllocateVirtualMemory" ascii
        $nt_protect_virtual = "NtProtectVirtualMemory" ascii
        $nt_open_process = "NtOpenProcess" ascii
        $nt_query_info = "NtQueryInformationProcess" ascii
        $nt_create_process = "NtCreateProcess" ascii
        // Import patterns
        $imp_nt_create = "__imp_NTDLL$NtCreateThreadEx" ascii
        $imp_nt_write = "__imp_NTDLL$NtWriteVirtualMemory" ascii
        $imp_nt_protect = "__imp_NTDLL$NtProtectVirtualMemory" ascii
        // Syscall instruction patterns (x64: 0F 05, x86: CD 2E)
        $syscall_x64 = { 0F 05 }
        $syscall_x86 = { CD 2E }
    condition:
        any of ($nt_*) or any of ($imp_nt_*) or any of ($syscall_*)
}

rule BOF_Unhooking {
    meta:
        category = "security"
        description = "Detects API unhooking techniques"
        severity = "high"
        tags = "unhooking,evasion"
    strings:
        // Memory protection changes for unhooking
        $virtual_protect = "VirtualProtect" ascii
        $virtual_protect_ex = "VirtualProtectEx" ascii
        $nt_protect = "NtProtectVirtualMemory" ascii
        $nt_write = "NtWriteVirtualMemory" ascii
        // Common unhooking patterns
        $get_proc_address = "GetProcAddress" ascii
        $load_library = "LoadLibrary" ascii
        $imp_virtual_protect = "__imp_KERNEL32$VirtualProtect" ascii
        $imp_get_proc = "__imp_KERNEL32$GetProcAddress" ascii
        $imp_nt_protect = "__imp_NTDLL$NtProtectVirtualMemory" ascii
        $imp_nt_write = "__imp_NTDLL$NtWriteVirtualMemory" ascii
    condition:
        (any of ($virtual_protect, $virtual_protect_ex, $imp_virtual_protect) or any of ($nt_protect, $imp_nt_protect)) and (any of ($nt_write, $imp_nt_write) or any of ($get_proc_address, $imp_get_proc, $load_library))
}

rule BOF_TokenManipulation {
    meta:
        category = "security"
        description = "Detects token manipulation APIs"
        severity = "high"
        tags = "token,privilege"
    strings:
        // Plain API names
        $impersonate = "ImpersonateLoggedOnUser" ascii
        $duplicate_token = "DuplicateTokenEx" ascii
        $open_process_token = "OpenProcessToken" ascii
        $open_thread_token = "OpenThreadToken" ascii
        $set_thread_token = "SetThreadToken" ascii
        $adjust_token = "AdjustTokenPrivileges" ascii
        $lookup_privilege = "LookupPrivilegeValue" ascii
        // Import symbol patterns
        $imp_impersonate = "__imp_ADVAPI32$ImpersonateLoggedOnUser" ascii
        $imp_duplicate = "__imp_ADVAPI32$DuplicateTokenEx" ascii
        $imp_open = "__imp_ADVAPI32$OpenProcessToken" ascii
        $imp_set = "__imp_ADVAPI32$SetThreadToken" ascii
    condition:
        2 of them
}

rule BOF_AntiDebug {
    meta:
        category = "security"
        description = "Detects anti-debugging techniques"
        severity = "high"
        tags = "anti-debug,evasion"
    strings:
        $is_debugger = "IsDebuggerPresent" ascii
        $check_remote = "CheckRemoteDebuggerPresent" ascii
        $nt_query = "NtQueryInformationProcess" ascii
        $nt_set = "NtSetInformationThread" ascii
        $peb_being = "BeingDebugged" ascii
        $output_debug = "OutputDebugString" ascii
        $imp_is_debug = "__imp_KERNEL32$IsDebuggerPresent" ascii
        $imp_check = "__imp_KERNEL32$CheckRemoteDebuggerPresent" ascii
        $imp_nt_query = "__imp_NTDLL$NtQueryInformationProcess" ascii
    condition:
        2 of them
}

rule BOF_ProcessHollowing {
    meta:
        category = "security"
        description = "Detects process hollowing techniques"
        severity = "critical"
        tags = "hollowing,evasion"
    strings:
        $create_process = "CreateProcess" ascii
        $create_process_suspended = "CREATE_SUSPENDED" ascii
        $nt_unmap = "NtUnmapViewOfSection" ascii
        $virtual_alloc_ex = "VirtualAllocEx" ascii
        $write_process = "WriteProcessMemory" ascii
        $set_context = "SetThreadContext" ascii
        $resume_thread = "ResumeThread" ascii
        $imp_create = "__imp_KERNEL32$CreateProcess" ascii
        $imp_unmap = "__imp_NTDLL$NtUnmapViewOfSection" ascii
    condition:
        4 of ($create_process, $create_process_suspended, $nt_unmap, $imp_unmap, $virtual_alloc_ex, $write_process, $set_context, $resume_thread, $imp_create)
}

rule BOF_DLLInjection {
    meta:
        category = "security"
        description = "Detects DLL injection patterns"
        severity = "high"
        tags = "injection,dll"
    strings:
        $load_library = "LoadLibrary" ascii
        $load_library_ex = "LoadLibraryEx" ascii
        $create_remote = "CreateRemoteThread" ascii
        $virtual_alloc_ex = "VirtualAllocEx" ascii
        $write_process = "WriteProcessMemory" ascii
        $imp_load = "__imp_KERNEL32$LoadLibrary" ascii
        $imp_create = "__imp_KERNEL32$CreateRemoteThread" ascii
    condition:
        (any of ($load_library, $load_library_ex, $imp_load)) and (any of ($create_remote, $imp_create) or any of ($virtual_alloc_ex, $write_process))
}

rule BOF_MemoryProtection {
    meta:
        category = "security"
        description = "Detects memory protection manipulation"
        severity = "medium"
        tags = "memory,protection"
    strings:
        $virtual_protect = "VirtualProtect" ascii
        $virtual_protect_ex = "VirtualProtectEx" ascii
        $nt_protect = "NtProtectVirtualMemory" ascii
        $page_execute = "PAGE_EXECUTE" ascii
        $page_execute_read = "PAGE_EXECUTE_READ" ascii
        $page_execute_readwrite = "PAGE_EXECUTE_READWRITE" ascii
        $imp_virtual = "__imp_KERNEL32$VirtualProtect" ascii
        $imp_nt = "__imp_NTDLL$NtProtectVirtualMemory" ascii
    condition:
        2 of them
}

// ============================================================================
// OPSEC CATEGORY - Operational Security Issues
// ============================================================================

rule BOF_HardcodedIPs {
    meta:
        category = "opsec"
        description = "Detects hardcoded IP addresses"
        severity = "high"
        tags = "hardcoded,ip,opsec"
    strings:
        // IPv4 patterns (basic detection)
        $ipv4_1 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        // Common private IP ranges
        $private_ip1 = "192.168." ascii
        $private_ip2 = "10.0." ascii
        $private_ip3 = "172.16." ascii
        $localhost = "127.0.0.1" ascii
    condition:
        any of ($ipv4_1, $localhost) or 2 of ($private_ip1, $private_ip2, $private_ip3)
}

rule BOF_HardcodedDomains {
    meta:
        category = "opsec"
        description = "Detects hardcoded domain names"
        severity = "high"
        tags = "hardcoded,domain,opsec"
    strings:
        // Common domain patterns
        $domain1 = /[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}/
        $http = "http://" ascii
        $https = "https://" ascii
        $www = "www." ascii
        // Common suspicious domains
        $pastebin = "pastebin.com" ascii
        $github = "github.com" ascii
        $dropbox = "dropbox.com" ascii
    condition:
        ($http or $https or $www) and any of ($domain1, $pastebin, $github, $dropbox)
}

rule BOF_HardcodedPaths {
    meta:
        category = "opsec"
        description = "Detects hardcoded file paths"
        severity = "medium"
        tags = "hardcoded,path,opsec"
    strings:
        // Windows paths
        $c_drive = "C:\\" ascii
        $windows = "\\Windows\\" ascii
        $system32 = "\\System32\\" ascii
        $temp = "\\Temp\\" ascii
        $appdata = "\\AppData\\" ascii
        $program_files = "\\Program Files\\" ascii
        // Common suspicious paths
        $desktop = "\\Desktop\\" ascii
        $downloads = "\\Downloads\\" ascii
    condition:
        2 of them
}

rule BOF_HardcodedStrings {
    meta:
        category = "opsec"
        description = "Detects hardcoded suspicious strings"
        severity = "medium"
        tags = "hardcoded,strings,opsec"
    strings:
        // Common hardcoded strings that leak info
        $error_msg = "Error:" ascii
        $failed = "Failed" ascii
        $success = "Success" ascii
        $password = "password" ascii
        $secret = "secret" ascii
        $key = "key" ascii
        $api_key = "api_key" ascii
        $token = "token" ascii
        $authorization = "Authorization" ascii
        $bearer = "Bearer" ascii
    condition:
        3 of them
}

rule BOF_ErrorMessages {
    meta:
        category = "opsec"
        description = "Detects error messages that might leak information"
        severity = "medium"
        tags = "error,opsec"
    strings:
        $error = "Error" ascii
        $exception = "Exception" ascii
        $failed_to = "Failed to" ascii
        $unable_to = "Unable to" ascii
        $cannot = "Cannot" ascii
        $access_denied = "Access denied" ascii
        $permission = "Permission" ascii
    condition:
        2 of them
}

rule BOF_SuspiciousPatterns {
    meta:
        category = "opsec"
        description = "Detects suspicious code patterns"
        severity = "medium"
        tags = "suspicious,pattern"
    strings:
        // Suspicious function names
        $bypass = "bypass" ascii
        $evade = "evade" ascii
        $stealth = "stealth" ascii
        $hide = "hide" ascii
        // Suspicious variable names
        $malware = "malware" ascii
        $payload = "payload" ascii
        $shellcode = "shellcode" ascii
        $backdoor = "backdoor" ascii
    condition:
        2 of them
}

rule BOF_StringObfuscation {
    meta:
        category = "opsec"
        description = "Detects potential string obfuscation indicators"
        severity = "info"
        tags = "obfuscation,string"
    strings:
        // Common obfuscation patterns
        $xor = "xor" ascii
        $decode = "decode" ascii
        $decrypt = "decrypt" ascii
        $decipher = "decipher" ascii
        $unpack = "unpack" ascii
        $deobfuscate = "deobfuscate" ascii
    condition:
        2 of them
}

rule BOF_Base64Encoding {
    meta:
        category = "opsec"
        description = "Detects base64 encoding patterns"
        severity = "low"
        tags = "encoding,base64"
    strings:
        // Base64 character set (simplified pattern)
        $base64_chars = /[A-Za-z0-9+\/]{20,}/
        // Base64 padding
        $base64_pad = "==" ascii
    condition:
        $base64_chars and $base64_pad
}

rule BOF_HexEncoding {
    meta:
        category = "opsec"
        description = "Detects hex encoding patterns"
        severity = "low"
        tags = "encoding,hex"
    strings:
        // Long hex strings
        $hex_pattern = /[0-9A-Fa-f]{32,}/
    condition:
        $hex_pattern
}

rule BOF_CommandExecution {
    meta:
        category = "opsec"
        description = "Detects command execution APIs"
        severity = "high"
        tags = "command,execution"
    strings:
        $system = "system" ascii
        $exec = "exec" ascii
        $shell_execute = "ShellExecute" ascii
        $create_process = "CreateProcess" ascii
        $winexec = "WinExec" ascii
        $cmd = "cmd.exe" ascii
        $powershell = "powershell" ascii
        $imp_shell = "__imp_SHELL32$ShellExecute" ascii
        $imp_create = "__imp_KERNEL32$CreateProcess" ascii
    condition:
        2 of them
}

rule BOF_Persistence {
    meta:
        category = "opsec"
        description = "Detects persistence mechanisms"
        severity = "high"
        tags = "persistence"
    strings:
        $reg_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $reg_runonce = "RunOnce" ascii
        $startup = "Startup" ascii
        $task_scheduler = "TaskScheduler" ascii
        $service = "Service" ascii
        $create_service = "CreateService" ascii
        $imp_create = "__imp_ADVAPI32$CreateService" ascii
    condition:
        2 of them
}

rule BOF_NetworkBeaconing {
    meta:
        category = "opsec"
        description = "Detects network beaconing patterns"
        severity = "medium"
        tags = "beaconing,network"
    strings:
        $sleep = "Sleep" ascii
        $wait = "Wait" ascii
        $timeout = "timeout" ascii
        $interval = "interval" ascii
        $beacon = "beacon" ascii
        $imp_sleep = "__imp_KERNEL32$Sleep" ascii
    condition:
        (any of ($sleep, $imp_sleep) or $wait) and ($timeout or $interval or $beacon)
}
"#.to_string()
}

/// Save default BOF rules to a file
#[allow(dead_code)] // Exported for potential external use
pub fn save_default_rules_to_file(path: &PathBuf) -> Result<()> {
    let rules = create_default_bof_rules();
    std::fs::write(path, rules)
        .with_context(|| format!("Failed to write default YARA rules to {:?}", path))?;
    Ok(())
}

