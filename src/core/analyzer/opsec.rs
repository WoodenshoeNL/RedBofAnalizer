//! OpSec (Operational Security) analysis module
//!
//! This module provides advanced OpSec analysis including:
//! - API categorization by OpSec implications
//! - Risky API combination detection
//! - Suspicious pattern detection
//! - Enhanced OpSec scoring

use crate::core::models::bof::{Import, Symbol, BofFile};
use std::collections::{HashMap, HashSet};

/// OpSec category for APIs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpsecCategory {
    /// Low OpSec risk - standard operations
    LowRisk,
    /// Medium OpSec risk - potentially detectable
    MediumRisk,
    /// High OpSec risk - highly detectable or suspicious
    HighRisk,
    /// Critical OpSec risk - very likely to be detected
    CriticalRisk,
}

/// Location information for a finding
#[derive(Debug, Clone)]
pub struct FindingLocation {
    /// Symbol name (function or data symbol) that uses this API/pattern
    pub symbol: Option<String>,
    /// Offset within the symbol (if available)
    #[allow(dead_code)] // Reserved for future use in detailed disassembly navigation
    pub offset: Option<u64>,
    /// Address in the binary (if available)
    pub address: Option<u64>,
    /// Section name (if available)
    #[allow(dead_code)] // Reserved for future use in detailed disassembly navigation
    pub section: Option<String>,
    /// Import information (for API findings)
    pub import_info: Option<ImportLocation>,
}

/// Import location information
#[derive(Debug, Clone)]
pub struct ImportLocation {
    /// Library name (e.g., "kernel32.dll")
    pub library: String,
    /// Function name
    pub function: String,
    /// Symbol name in the import table
    #[allow(dead_code)] // Reserved for future use in detailed import analysis
    pub symbol_name: String,
}

/// API OpSec classification
#[derive(Debug, Clone)]
pub struct ApiOpsecInfo {
    pub category: OpsecCategory,
    pub description: String,
    #[allow(dead_code)] // Reserved for future use in detailed reporting
    pub detection_vectors: Vec<String>,
    /// Location information for this API finding
    pub locations: Vec<FindingLocation>,
}

/// Risky API combination
#[derive(Debug, Clone)]
pub struct RiskyCombination {
    pub apis: Vec<String>,
    pub risk_level: OpsecCategory,
    pub description: String,
    pub recommendation: String,
    /// Location information for this combination
    pub locations: Vec<FindingLocation>,
}

/// OpSec finding grouped by function
#[derive(Debug, Clone)]
pub struct FunctionOpsecInfo {
    /// Function name
    pub function_name: String,
    /// Function address (if available)
    pub function_address: Option<u64>,
    /// Risky APIs used by this function
    pub risky_apis: Vec<(String, ApiOpsecInfo)>,
    /// Risky combinations present in this function
    #[allow(dead_code)] // Reserved for future use when associating combinations with specific functions
    pub risky_combinations: Vec<RiskyCombination>,
    /// Suspicious patterns detected in this function
    #[allow(dead_code)] // Reserved for future use when associating patterns with specific functions
    pub suspicious_patterns: Vec<SuspiciousPattern>,
}

/// OpSec analysis result
#[derive(Debug, Clone)]
pub struct EnhancedOpsecAnalysis {
    pub api_classifications: Vec<(String, ApiOpsecInfo)>,
    pub risky_combinations: Vec<RiskyCombination>,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    /// OpSec findings grouped by function
    pub function_findings: Vec<FunctionOpsecInfo>,
    /// Overall OpSec score (0-100, higher is better)
    pub opsec_score: u8,
    /// Estimated overall stealth (0-100, higher is stealthier)
    pub overall_stealth_score: u8,
    /// Injection noisiness (0-100, higher is noisier/more detectable)
    pub injection_noise_score: u8,
    /// Anti-debug / evasion aggressiveness (0-100, higher is more aggressive)
    pub anti_debug_evasion_score: u8,
    /// Persistence profile (0-100, higher means stronger / more permanent persistence)
    pub persistence_profile_score: u8,
    pub recommendations: Vec<String>,
}

/// Suspicious pattern detected
#[derive(Debug, Clone)]
pub struct SuspiciousPattern {
    pub pattern_type: PatternType,
    pub description: String,
    pub severity: OpsecCategory,
    /// Legacy location string (kept for backward compatibility)
    pub location: Option<String>,
    /// Detailed location information
    pub locations: Vec<FindingLocation>,
}

/// Type of suspicious pattern
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)] // Some variants are reserved for future use / extended patterns
pub enum PatternType {
    DirectSyscall,
    ProcessInjection,
    TokenManipulation,
    Unhooking,
    /// Anti-debugging and evasion behavior
    AntiDebugging,
    /// Possible configuration or string obfuscation
    StringObfuscation,
    /// Very high entropy regions (packed/obfuscated)
    HighEntropy,
    /// Suspicious DLL usage
    SuspiciousDll,
    /// Network-related behavior with OpSec impact
    NetworkActivity,
    /// File system access with OpSec impact
    FileSystemAccess,
    /// Persistence-related behavior (registry/services/etc.)
    Persistence,
}

// API OpSec database
lazy_static::lazy_static! {
    static ref API_OPSEC_DB: HashMap<&'static str, ApiOpsecInfo> = {
        let mut map = HashMap::new();
        
        // High-risk process operations
        map.insert("CreateRemoteThread", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Creates a thread in another process - common injection technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string(), "Behavioral analysis".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("WriteProcessMemory", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Writes to another process memory - injection technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("VirtualAllocEx", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Allocates memory in another process - injection technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("NtCreateThreadEx", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Direct syscall for thread creation - bypasses hooks".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("NtWriteVirtualMemory", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Direct syscall for memory write - bypasses hooks".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        
        // Token manipulation
        map.insert("OpenProcessToken", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens process token - privilege escalation indicator".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Token monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("DuplicateTokenEx", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Duplicates token with impersonation - privilege escalation".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Token monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("SetThreadToken", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Sets thread token - impersonation technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Token monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        
        // Unhooking
        map.insert("NtProtectVirtualMemory", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Changes memory protection - unhooking technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Memory protection monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        // Note: NtWriteVirtualMemory already added above
        
        // Anti-debugging
        map.insert("IsDebuggerPresent", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Checks for debugger - anti-debugging technique".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("CheckRemoteDebuggerPresent", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Checks for remote debugger - anti-debugging".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("NtQueryInformationProcess", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Queries process information - anti-debugging".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Behavioral analysis".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        
        // Network operations
        map.insert("InternetOpenA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Opens internet connection - network activity".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("HttpOpenRequestA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Opens HTTP request - network activity".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("WinHttpConnect", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Connects via WinHTTP - network activity".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });

        // File operations
        map.insert("CreateFileA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Creates/opens file - file system access".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("WriteFile", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Writes to file - file system access".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });

        // Registry operations / persistence
        map.insert("RegOpenKeyExA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Opens registry key - registry access".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("RegSetValueExA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sets registry value - persistence indicator".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("RegCreateKeyExA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Creates registry key - potential persistence mechanism".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("RegSetValueExW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sets registry value (Unicode) - persistence indicator".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });

        // Service control manager / service persistence
        map.insert("OpenSCManagerA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens Service Control Manager - potential service-based persistence".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("CreateServiceA", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Creates a Windows service - strong persistence indicator".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("ChangeServiceConfigA", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Changes service configuration - persistence / defense evasion".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });

        // Alternate injection / thread manipulation
        map.insert("QueueUserAPC", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Queues an APC to a thread - APC-based code injection".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Thread monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("NtQueueApcThread", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Queues an APC via direct syscall - stealthy APC-based injection".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "Thread monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("SetThreadContext", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Manipulates thread context - code injection / hollowing primitive".to_string(),
            detection_vectors: vec!["Thread monitoring".to_string(), "Behavioral analysis".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("NtSetContextThread", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Direct syscall to change thread context - injection / hollowing primitive".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "Thread monitoring".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });

        // Additional anti-debug / evasion
        map.insert("OutputDebugStringA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sends string to debugger - often used in anti-debug logic".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        map.insert("NtSetInformationThread", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Can be used to hide threads from debuggers".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "Behavioral analysis".to_string()],
            locations: Vec::new(), // Will be populated during analysis
        });
        
        // ===== EXPANDED INJECTION APIs =====
        
        // Section mapping / manual mapping injection
        map.insert("NtCreateSection", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Creates a section object - used in section mapping injection".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string(), "Section monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtMapViewOfSection", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Maps a view of a section - section mapping injection technique".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string(), "Memory mapping monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtUnmapViewOfSection", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Unmaps a view of a section - used in process hollowing".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("MapViewOfFile", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Maps a view of a file mapping - section mapping injection".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Memory mapping monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("CreateFileMappingA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Creates a file mapping object - used in section mapping".to_string(),
            detection_vectors: vec!["ETW".to_string(), "File mapping monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("CreateFileMappingW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Creates a file mapping object (Unicode) - used in section mapping".to_string(),
            detection_vectors: vec!["ETW".to_string(), "File mapping monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // Process hollowing / early bird injection
        map.insert("NtResumeThread", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Resumes a suspended thread - used in process hollowing/early bird".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string(), "Thread monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("ResumeThread", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Resumes a suspended thread - used in process hollowing/early bird".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Thread monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtSuspendThread", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Suspends a thread - used in process hollowing".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("SuspendThread", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Suspends a thread - used in process hollowing".to_string(),
            detection_vectors: vec!["ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("GetThreadContext", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Gets thread context - used in process hollowing/injection".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Thread monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtGetContextThread", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Gets thread context via syscall - used in process hollowing/injection".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // DLL injection
        map.insert("LoadLibraryA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Loads a DLL - DLL injection technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "DLL loading monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("LoadLibraryW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Loads a DLL (Unicode) - DLL injection technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "DLL loading monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("LoadLibraryExA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Loads a DLL with extended options - DLL injection".to_string(),
            detection_vectors: vec!["ETW".to_string(), "DLL loading monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("LoadLibraryExW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Loads a DLL with extended options (Unicode) - DLL injection".to_string(),
            detection_vectors: vec!["ETW".to_string(), "DLL loading monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("LdrLoadDll", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Low-level DLL loader - used in advanced injection".to_string(),
            detection_vectors: vec!["ETW".to_string(), "DLL loading monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("LdrGetProcedureAddress", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Gets procedure address from DLL - used in manual mapping".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Behavioral analysis".to_string()],
            locations: Vec::new(),
        });
        
        // Additional injection primitives
        map.insert("NtAllocateVirtualMemory", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Allocates virtual memory via syscall - injection primitive".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtReadVirtualMemory", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Reads virtual memory via syscall - used in injection/reconnaissance".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("ReadProcessMemory", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Reads process memory - used in reconnaissance/injection".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtOpenProcess", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Opens a process via syscall - injection prerequisite".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtOpenThread", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Opens a thread via syscall - injection prerequisite".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== EXPANDED UNHOOKING APIs =====
        
        map.insert("VirtualProtect", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Changes memory protection - unhooking technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Memory protection monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("VirtualProtectEx", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Changes memory protection in remote process - unhooking".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Memory protection monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtProtectVirtualMemory", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Changes memory protection via syscall - unhooking technique".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("FlushInstructionCache", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Flushes instruction cache - used after unhooking".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Behavioral analysis".to_string()],
            locations: Vec::new(),
        });
        
        // ETW / AMSI bypass
        map.insert("EtwEventWrite", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "ETW event writing - can be used to disable ETW".to_string(),
            detection_vectors: vec!["ETW monitoring".to_string(), "Behavioral analysis".to_string()],
            locations: Vec::new(),
        });
        map.insert("EtwEventWriteFull", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "ETW full event writing - can be used to disable ETW".to_string(),
            detection_vectors: vec!["ETW monitoring".to_string(), "Behavioral analysis".to_string()],
            locations: Vec::new(),
        });
        map.insert("AmsiScanBuffer", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "AMSI buffer scanning - target for AMSI bypass".to_string(),
            detection_vectors: vec!["AMSI monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("AmsiInitialize", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "AMSI initialization - AMSI bypass target".to_string(),
            detection_vectors: vec!["AMSI monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== EXPANDED PERSISTENCE APIs =====
        
        // Scheduled tasks
        map.insert("ITaskScheduler", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Task Scheduler COM interface - scheduled task persistence".to_string(),
            detection_vectors: vec!["Task monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("SchRpcRegisterTask", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Registers a scheduled task - persistence mechanism".to_string(),
            detection_vectors: vec!["Task monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // WMI event subscriptions
        map.insert("IWbemServices", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "WMI services interface - WMI event subscription persistence".to_string(),
            detection_vectors: vec!["WMI monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("IWbemEventConsumerProvider", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "WMI event consumer - WMI persistence mechanism".to_string(),
            detection_vectors: vec!["WMI monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // Startup folder / COM hijacking
        map.insert("SHGetSpecialFolderPathA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets special folder path - used for startup folder persistence".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("SHGetSpecialFolderPathW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets special folder path (Unicode) - startup folder persistence".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("CoCreateInstance", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Creates COM instance - used in COM hijacking persistence".to_string(),
            detection_vectors: vec!["COM monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("CoGetClassObject", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets COM class object - used in COM hijacking".to_string(),
            detection_vectors: vec!["COM monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // Additional registry persistence
        map.insert("RegCreateKeyExW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Creates registry key (Unicode) - persistence mechanism".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegOpenKeyExW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Opens registry key (Unicode) - registry access".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegDeleteValueA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Deletes registry value - defense evasion / cleanup".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegDeleteValueW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Deletes registry value (Unicode) - defense evasion / cleanup".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // Additional service persistence
        map.insert("OpenSCManagerW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens Service Control Manager (Unicode) - service persistence".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("CreateServiceW", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Creates a Windows service (Unicode) - strong persistence".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("StartServiceA", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Starts a service - service-based execution".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("StartServiceW", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Starts a service (Unicode) - service-based execution".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("DeleteService", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Deletes a service - cleanup / defense evasion".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== EXPANDED ANTI-DEBUG / EVASION APIs =====
        
        // Timing checks
        map.insert("QueryPerformanceCounter", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "High-resolution performance counter - used in timing-based anti-debug".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
            locations: Vec::new(),
        });
        map.insert("GetTickCount", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets tick count - used in timing-based anti-debug".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
            locations: Vec::new(),
        });
        map.insert("GetTickCount64", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets tick count (64-bit) - used in timing-based anti-debug".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
            locations: Vec::new(),
        });
        
        // Hardware breakpoints / exception handling
        map.insert("SetUnhandledExceptionFilter", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sets unhandled exception filter - anti-debug / evasion".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
            locations: Vec::new(),
        });
        map.insert("AddVectoredExceptionHandler", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Adds vectored exception handler - anti-debug / evasion".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
            locations: Vec::new(),
        });
        map.insert("RaiseException", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Raises an exception - used in exception-based anti-debug".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
            locations: Vec::new(),
        });
        
        // Additional NtQueryInformation* APIs
        map.insert("NtQueryInformationThread", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Queries thread information - anti-debugging".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtQuerySystemInformation", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Queries system information - anti-debug / evasion".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtQueryObject", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Queries object information - anti-debug / evasion".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtQueryAttributesFile", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Queries file attributes - evasion / reconnaissance".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // Additional anti-debug checks
        map.insert("NtClose", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes a handle via syscall - common operation".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtDelayExecution", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Delays execution via syscall - timing-based evasion".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtWaitForSingleObject", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Waits for object via syscall - timing-based evasion".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== DISCOVERY APIs =====
        
        // Process enumeration
        map.insert("CreateToolhelp32Snapshot", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Creates process/thread snapshot - process enumeration".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("Process32First", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets first process in snapshot - process enumeration".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("Process32Next", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets next process in snapshot - process enumeration".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("EnumProcesses", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates processes - process discovery".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        // Note: NtQuerySystemInformation already added in anti-debug section above
        
        // Network enumeration
        map.insert("GetAdaptersInfo", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets network adapter information - network discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("GetAdaptersAddresses", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets network adapter addresses - network discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("GetIpNetTable", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets ARP table - network discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // Service enumeration
        map.insert("EnumServicesStatusA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates services - service discovery".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("EnumServicesStatusW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates services (Unicode) - service discovery".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // Registry enumeration
        map.insert("RegEnumKeyExA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Enumerates registry subkeys - registry discovery".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegEnumKeyExW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Enumerates registry subkeys (Unicode) - registry discovery".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegEnumValueA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Enumerates registry values - registry discovery".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegEnumValueW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Enumerates registry values (Unicode) - registry discovery".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // File system enumeration
        map.insert("FindFirstFileA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds first file matching pattern - file system discovery".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("FindFirstFileW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds first file matching pattern (Unicode) - file system discovery".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("FindNextFileA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds next file matching pattern - file system discovery".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("FindNextFileW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds next file matching pattern (Unicode) - file system discovery".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // Credential access
        map.insert("CredEnumerateA", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Enumerates stored credentials - credential access".to_string(),
            detection_vectors: vec!["Credential monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("CredEnumerateW", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Enumerates stored credentials (Unicode) - credential access".to_string(),
            detection_vectors: vec!["Credential monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("CredReadA", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Reads stored credential - credential access".to_string(),
            detection_vectors: vec!["Credential monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("CredReadW", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Reads stored credential (Unicode) - credential access".to_string(),
            detection_vectors: vec!["Credential monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("LsaRetrievePrivateData", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Retrieves LSA private data - credential access".to_string(),
            detection_vectors: vec!["LSA monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("SamEnumerateDomainsInSamServer", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Enumerates domains in SAM - credential access".to_string(),
            detection_vectors: vec!["SAM monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== STANDARD HEAP MANAGEMENT APIs =====
        
        map.insert("GetProcessHeap", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets handle to default process heap - standard memory management".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("HeapAlloc", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Allocates memory from heap - standard memory management".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("HeapFree", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees memory from heap - standard memory management".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== STANDARD C RUNTIME APIs =====
        
        map.insert("calloc", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Allocates and zero-initializes memory - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("free", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees allocated memory - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("vsnprintf", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats string with variable arguments - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("wcschr", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds first occurrence of character in wide string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("wcsncpy_s", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Copies wide string with bounds checking - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== STRING CONVERSION APIs =====
        
        map.insert("WideCharToMultiByte", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts wide character string to multibyte string - standard string conversion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== NETWORK/DOMAIN APIs =====
        
        map.insert("NetGetAadJoinInformation", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets Azure AD join information - domain/network information query".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetFreeAadJoinInformation", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees Azure AD join information buffer - standard cleanup function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== HANDLE AND ERROR MANAGEMENT APIs =====
        
        map.insert("CloseHandle", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes an open object handle - standard cleanup function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetLastError", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Retrieves the last error code - standard error handling".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetCurrentProcess", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Returns pseudo-handle to current process - standard process query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("LocalFree", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees local memory - standard memory management".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== TOKEN AND SECURITY APIs =====
        
        map.insert("GetTokenInformation", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Retrieves information about an access token - token enumeration".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Token monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("ConvertSidToStringSidA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts SID to string format - standard SID handling".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("LookupAccountSidA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Looks up account name for a SID - standard account lookup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("LookupPrivilegeNameA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Retrieves privilege name from LUID - standard privilege query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("LookupPrivilegeDisplayNameA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Retrieves display name for a privilege - standard privilege query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetUserNameExA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Retrieves extended user name - standard user information query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== ADDITIONAL C RUNTIME APIs =====
        
        map.insert("sprintf", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("memset", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Fills memory with a value - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("memcmp", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Compares memory blocks - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== LIBRARY LOADING APIs =====
        
        map.insert("GetProcAddress", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets address of exported function - standard dynamic linking".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("FreeLibrary", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees loaded DLL module - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== TIME CONVERSION APIs =====
        
        map.insert("FileTimeToSystemTime", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts file time to system time - standard time conversion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SECURITY DESCRIPTOR APIs =====
        
        map.insert("GetSecurityDescriptorOwner", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets owner from security descriptor - standard security query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetSecurityDescriptorDacl", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets DACL from security descriptor - standard security query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetAclInformation", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets information about an ACL - standard security query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetAce", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets an ACE from an ACL - standard security query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("LookupAccountSidW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Looks up account name for a SID (Unicode) - standard account lookup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ConvertSidToStringSidW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts SID to string format (Unicode) - standard SID handling".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== CRYPTO/CERTIFICATE APIs =====
        
        map.insert("CryptFindOIDInfo", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds OID information - standard crypto query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CertFreeCertificateContext", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees certificate context - standard crypto cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== COM/OLE APIs =====
        
        map.insert("StringFromGUID2", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts GUID to string - standard COM utility".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== ADDITIONAL C RUNTIME WIDE STRING APIs =====
        
        map.insert("wcscpy", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Copies wide string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("wcstok_s", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Tokenizes wide string (secure) - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("wcstoul", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts wide string to unsigned long - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== ADDITIONAL SECURITY DESCRIPTOR APIs =====
        
        map.insert("ConvertStringSecurityDescriptorToSecurityDescriptorW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts SDDL string to security descriptor - standard security conversion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SAFEARRAY APIs =====
        
        map.insert("SafeArrayAccessData", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Accesses SafeArray data - standard COM/OLE array access".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SafeArrayUnaccessData", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Releases SafeArray data access - standard COM/OLE cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SafeArrayGetElement", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets element from SafeArray - standard COM/OLE array access".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== FILE OPERATIONS =====
        
        map.insert("CreateFileW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Creates/opens file (Unicode) - file system access".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("ReadFile", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Reads from file - file system access".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("GetFileSize", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets file size - standard file query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("FindClose", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes find handle - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ExpandEnvironmentStringsW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Expands environment variables - standard string expansion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== HEAP MANAGEMENT =====
        
        map.insert("HeapReAlloc", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Reallocates heap memory - standard memory management".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== C RUNTIME STRING APIs =====
        
        map.insert("strlen", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets string length - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strcpy", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Copies string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strcmp", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Compares strings - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strstr", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds substring - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strtok_s", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Tokenizes string (secure) - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("wcscmp", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Compares wide strings - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("_snwprintf", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats wide string with size limit - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("wcsrchr", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds last occurrence of character in wide string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== KERNEL32 STRING APIs =====
        
        map.insert("lstrlenW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets wide string length - standard string function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("lstrcpynW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Copies wide string with length limit - standard string function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("lstrcatW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Concatenates wide strings - standard string function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== FILE/DIRECTORY QUERY APIs =====
        
        map.insert("GetFileAttributesW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets file attributes (Unicode) - standard file query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetFullPathNameW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets full path name (Unicode) - standard path query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetCurrentDirectoryW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets current directory (Unicode) - standard directory query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetFileSecurityW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets file security descriptor (Unicode) - standard security query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SECURITY APIs =====
        
        map.insert("MapGenericMask", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Maps generic access rights to specific rights - standard security function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== ERROR HANDLING =====
        
        map.insert("SetLastError", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Sets the last error code - standard error handling".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== USER32 CHARACTER APIs =====
        
        map.insert("CharPrevW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets pointer to previous character in wide string - standard character function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== TIME CONVERSION APIs =====
        
        map.insert("SystemTimeToTzSpecificLocalTime", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts UTC time to local time - standard time conversion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== ADDITIONAL C RUNTIME STRING APIs =====
        
        map.insert("_strnicmp", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Case-insensitive string comparison with length - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strcat", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Concatenates strings - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strncat", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Concatenates strings with length limit - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== FILE ENUMERATION APIs =====
        
        map.insert("FindFirstFileA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds first file matching pattern - file system discovery".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("FindNextFileA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds next file matching pattern - file system discovery".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== SERVICE CONTROL APIs =====
        
        map.insert("CloseServiceHandle", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes service handle - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("EnumServicesStatusExW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates services with extended info (Unicode) - service discovery".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== REGISTRY APIs =====
        
        map.insert("RegCloseKey", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes registry key handle - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("RegQueryValueExW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Queries registry value (Unicode) - standard registry read".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== CERTIFICATE/CRYPTO APIs =====
        
        map.insert("CertGetNameStringW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets certificate name string (Unicode) - standard certificate query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CryptVerifyMessageSignature", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Verifies message signature - standard crypto verification".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== IMAGE/PE APIs =====
        
        map.insert("ImageEnumerateCertificates", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Enumerates certificates in PE image - standard image query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ImageGetCertificateData", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets certificate data from PE image - standard image query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ImageGetCertificateHeader", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets certificate header from PE image - standard image query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== NT FILE APIs =====
        
        map.insert("NtCreateFile", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Creates/opens file via NT syscall - low-level file access".to_string(),
            detection_vectors: vec!["ETW".to_string(), "File system monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtClose", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes handle via NT syscall - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== ADDITIONAL C RUNTIME WIDE STRING APIs =====
        
        map.insert("_wcsicmp", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Case-insensitive wide string comparison - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("wcscat", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Concatenates wide strings - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("wcsncat", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Concatenates wide strings with length limit - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== ADDITIONAL REGISTRY APIs =====
        
        map.insert("RegConnectRegistryA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Connects to remote registry - remote registry access".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string(), "Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegQueryValueExA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Queries registry value - standard registry read".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== ADDITIONAL C RUNTIME APIs =====
        
        map.insert("strtoul", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts string to unsigned long - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== TERMINAL SERVICES APIs =====
        
        map.insert("WTSEnumerateSessionsA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates terminal sessions - session discovery".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Session monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("WTSQuerySessionInformationA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Queries terminal session information - session discovery".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Session monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("WTSFreeMemory", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees WTS memory - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== ENVIRONMENT APIs =====
        
        map.insert("GetEnvironmentStrings", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets environment strings block - standard environment query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("FreeEnvironmentStringsA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees environment strings block - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== KERNEL32 STRING APIs =====
        
        map.insert("lstrlenA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets string length - standard string function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== MODULE ENUMERATION APIs =====
        
        map.insert("Module32First", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets first module in snapshot - module enumeration".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("Module32Next", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets next module in snapshot - module enumeration".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("EnumProcessModulesEx", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates process modules - module discovery".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("GetModuleFileNameExA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets module file name - standard module query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SHLWAPI STRING APIs =====
        
        map.insert("StrStrIA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Case-insensitive substring search - standard string function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== BCRYPT APIs =====
        
        map.insert("BCryptOpenAlgorithmProvider", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Opens crypto algorithm provider - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("BCryptCloseAlgorithmProvider", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes crypto algorithm provider - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("BCryptCreateHash", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Creates hash object - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("BCryptHashData", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Hashes data - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("BCryptFinishHash", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finishes hash computation - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("BCryptDestroyHash", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Destroys hash object - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("BCryptSetProperty", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Sets crypto property - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("BCryptGenerateSymmetricKey", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Generates symmetric key - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("BCryptDecrypt", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Decrypts data - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("BCryptDestroyKey", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Destroys crypto key - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SECURITY DESCRIPTOR APIs =====
        
        map.insert("InitializeSecurityDescriptor", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Initializes security descriptor - standard security operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SetSecurityDescriptorDacl", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sets DACL on security descriptor - security modification".to_string(),
            detection_vectors: vec!["Security monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("SetEntriesInAclA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Creates ACL with specified entries - security modification".to_string(),
            detection_vectors: vec!["Security monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegGetKeySecurity", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets registry key security - standard security query".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegSetKeySecurity", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sets registry key security - security modification".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegQueryInfoKeyA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Queries registry key information - standard registry query".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== C RUNTIME MEMORY APIs =====
        
        map.insert("memcpy", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Copies memory - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("malloc", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Allocates memory - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("_ultoa", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts unsigned long to string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strtok", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Tokenizes string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("wcstombs", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts wide string to multibyte - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("_stricmp", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Case-insensitive string comparison - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== NETAPI32 APIs =====
        
        map.insert("NetApiBufferFree", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees NetAPI buffer - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("NetUserModalsGet", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets user modals information - user/domain discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetSessionEnum", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates network sessions - session discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetWkstaGetInfo", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets workstation information - network discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("DsGetDcNameA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets domain controller name - domain discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== LSA APIs =====
        
        map.insert("LsaGetLogonSessionData", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets logon session data - session information query".to_string(),
            detection_vectors: vec!["LSA monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("LsaFreeReturnBuffer", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees LSA return buffer - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== DNS APIs =====
        
        map.insert("DnsQuery_A", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Performs DNS query - standard DNS operation".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("DnsFree", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees DNS memory - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("DnsGetCacheDataTable", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets DNS cache data - DNS cache enumeration".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== MEMORY ALLOCATION APIs =====
        
        map.insert("LocalAlloc", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Allocates local memory - standard memory allocation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GlobalAlloc", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Allocates global memory - standard memory allocation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GlobalFree", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees global memory - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== NETWORK/IP HELPER APIs =====
        
        map.insert("GetNetworkParams", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets network parameters - standard network query".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== LDAP/BER APIs =====
        
        map.insert("ber_alloc_t", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Allocates BER element - LDAP encoding".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ber_free", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees BER element - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ber_printf", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats BER element - LDAP encoding".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ber_flatten", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Flattens BER element to berval - LDAP encoding".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ber_bvfree", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees berval structure - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== COM/OLE VARIANT APIs =====
        
        map.insert("CoInitializeEx", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Initializes COM library - standard COM initialization".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CoUninitialize", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Uninitializes COM library - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("VariantInit", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Initializes VARIANT - standard COM operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("VariantClear", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Clears VARIANT - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("VariantChangeType", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Changes VARIANT type - standard COM operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== PROCESS APIs =====
        
        map.insert("OpenProcess", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens process handle - process access".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("GetCurrentProcessId", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets current process ID - standard process query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== VERSION INFO APIs =====
        
        map.insert("GetFileVersionInfoSizeA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets file version info size - standard version query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetFileVersionInfoA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets file version info - standard version query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("VerQueryValueA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Queries version value - standard version query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== LOCALE/DATE APIs =====
        
        map.insert("GetSystemDefaultLocaleName", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets system default locale name - standard locale query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetLocaleInfoEx", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets locale information - standard locale query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("LocaleNameToLCID", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts locale name to LCID - standard locale conversion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetDateFormatEx", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats date string - standard date formatting".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== LEGACY CRYPT APIs =====
        
        map.insert("CryptAcquireContextA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Acquires crypto context - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CryptCreateHash", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Creates hash object - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CryptHashData", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Hashes data - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CryptGetHashParam", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets hash parameter - standard crypto operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CryptDestroyHash", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Destroys hash object - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CryptReleaseContext", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Releases crypto context - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== COMPUTER NAME APIs =====
        
        map.insert("GetComputerNameExW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets computer name (Unicode) - standard system query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== NETAPI32 USER/GROUP ENUMERATION APIs =====
        
        map.insert("NetGroupGetUsers", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets users in a group - user enumeration".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetQueryDisplayInformation", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Queries display information - user/group enumeration".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetLocalGroupEnum", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates local groups - group discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetLocalGroupGetMembers", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets local group members - group membership enumeration".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetWkstaUserEnum", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates workstation users - user discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetShareEnum", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates network shares - share discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== NETWORK TABLE APIs =====
        
        map.insert("GetExtendedTcpTable", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets TCP connection table - network connection enumeration".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("GetExtendedUdpTable", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets UDP endpoint table - network connection enumeration".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== PROCESS QUERY APIs =====
        
        map.insert("QueryFullProcessImageNameA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets full process image name - standard process query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== WINSOCK APIs =====
        
        map.insert("htonl", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts host to network long - standard network byte order".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("htons", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts host to network short - standard network byte order".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== TIME APIs =====
        
        map.insert("GetLocalTime", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets local time - standard time query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetSystemTimeAsFileTime", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets system time as file time - standard time query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("FileTimeToLocalFileTime", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts file time to local - standard time conversion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetDateFormatW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats date string (Unicode) - standard date formatting".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("gmtime", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts time to UTC struct - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strftime", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats time string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== NETAPI32 ADDITIONAL APIs =====
        
        map.insert("NetRemoteTOD", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets remote time of day - remote system query".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetStatisticsGet", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets network statistics - network information query".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetUserGetInfo", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets user information - user enumeration".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetUserGetGroups", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets user's global groups - group enumeration".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetUserGetLocalGroups", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets user's local groups - group enumeration".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetGetAnyDCName", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Gets any domain controller name - domain discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetUserEnum", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates users - user discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetServerEnum", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates servers - network discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== MESSAGE/ERROR APIs =====
        
        map.insert("FormatMessageA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats message string - standard message formatting".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== WNET (MPR) APIs =====
        
        map.insert("WNetAddConnection2W", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Adds network connection - network resource access".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("WNetCancelConnection2W", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Cancels network connection - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("WNetOpenEnumW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens network resource enumeration - network discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("WNetEnumResourceW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates network resources - network discovery".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("WNetGetResourceInformationW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets network resource information - network query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("WNetGetUserW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets network user name - standard user query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("WNetCloseEnum", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes network enumeration - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== LDAP APIs =====
        
        map.insert("ldap_init", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Initializes LDAP connection - LDAP access".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("ldap_bind_s", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Binds to LDAP server - LDAP authentication".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("ldap_unbind", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Unbinds from LDAP server - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_search_s", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Performs LDAP search - LDAP query".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("ldap_count_entries", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Counts LDAP entries - standard LDAP operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_first_entry", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets first LDAP entry - standard LDAP operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_next_entry", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets next LDAP entry - standard LDAP operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_first_attribute", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets first LDAP attribute - standard LDAP operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_next_attribute", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets next LDAP attribute - standard LDAP operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_get_values", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets LDAP attribute values - standard LDAP operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_get_values_lenA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets LDAP attribute values with length - standard LDAP operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_value_free", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees LDAP values - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_value_free_len", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees LDAP values with length - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_memfree", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees LDAP memory - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ldap_msgfree", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees LDAP message - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== USER32 WINDOW APIs =====
        
        map.insert("EnumChildWindows", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Enumerates child windows - window enumeration".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("EnumDesktopWindows", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Enumerates desktop windows - window enumeration".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("FindWindowExA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds child window - window query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetClassNameA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets window class name - window query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetWindowTextA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets window text - window query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("IsWindowVisible", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Checks if window is visible - window query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SendMessageA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Sends message to window - window messaging".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== WINSOCK APIs =====
        
        map.insert("socket", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Creates socket - network socket creation".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("connect", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Connects socket - network connection".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("closesocket", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes socket - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("select", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Monitors socket status - standard socket operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("ioctlsocket", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Controls socket I/O mode - standard socket operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("getaddrinfo", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets address info - DNS resolution".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("freeaddrinfo", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees address info - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("__WSAFDIsSet", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Checks if socket is in FD set - standard socket operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("inet_ntoa", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts IP to string - standard network utility".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SYSTEM INFO APIs =====
        
        map.insert("GetDiskFreeSpaceExA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets disk free space - system information query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GlobalMemoryStatusEx", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets memory status - system information query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetIpForwardTable", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets IP routing table - network information query".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== SERVICE APIs =====
        
        map.insert("EnumServicesStatusExA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates services with extended info - service discovery".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("OpenServiceA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens service handle - service access".to_string(),
            detection_vectors: vec!["Service monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("QueryServiceConfigA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Queries service configuration - service query".to_string(),
            detection_vectors: vec!["Service monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("QueryServiceConfig2A", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Queries service optional configuration - service query".to_string(),
            detection_vectors: vec!["Service monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("QueryServiceStatus", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Queries service status - service query".to_string(),
            detection_vectors: vec!["Service monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== RPC APIs =====
        
        map.insert("UuidToStringA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts UUID to string - standard RPC utility".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("RpcStringFreeA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees RPC string - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== C RUNTIME STRING APIs =====
        
        map.insert("wcslen", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets wide string length - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("wcstok", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Tokenizes wide string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== OLEAUT32 BSTR/VARIANT APIs =====
        
        map.insert("SysAllocString", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Allocates BSTR string - standard COM string operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SysFreeString", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees BSTR string - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("VarFormatDateTime", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats variant date/time - standard COM operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== COM SECURITY APIs =====
        
        map.insert("CoInitializeSecurity", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Initializes COM security - standard COM security setup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CoSetProxyBlanket", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Sets proxy authentication - standard COM security".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SAFEARRAY ADDITIONAL APIs =====
        
        map.insert("SafeArrayDestroy", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Destroys SafeArray - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SafeArrayGetLBound", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets SafeArray lower bound - standard array operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SafeArrayGetUBound", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets SafeArray upper bound - standard array operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== TIME CONVERSION APIs =====
        
        map.insert("SystemTimeToFileTime", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts system time to file time - standard time conversion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== USER INPUT APIs =====
        
        map.insert("GetLastInputInfo", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets last input time - user activity query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== NT FILE CONTROL APIs =====
        
        map.insert("NtFsControlFile", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sends control code to file system - low-level file system control".to_string(),
            detection_vectors: vec!["ETW".to_string(), "File system monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== STRING CONVERSION APIs =====
        
        map.insert("MultiByteToWideChar", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts multibyte string to wide string - standard string conversion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== CRYPTO ENCODING APIs =====
        
        map.insert("CryptBinaryToStringW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts binary to string (Unicode) - standard crypto encoding".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CryptBinaryToStringA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts binary to string - standard crypto encoding".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CryptEncodeObjectEx", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Encodes crypto object - standard crypto encoding".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CryptUnprotectData", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Decrypts DPAPI protected data - credential access".to_string(),
            detection_vectors: vec!["DPAPI monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== USER/COMPUTER NAME APIs =====
        
        map.insert("GetComputerObjectNameW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets computer object name (Unicode) - standard system query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetUserNameExW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets extended user name (Unicode) - standard user query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SLEEP/TIMING APIs =====
        
        map.insert("Sleep", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Suspends execution - standard timing function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== OLEAUT32 STRING APIs =====
        
        map.insert("SysStringLen", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets BSTR length - standard COM string operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SysAllocStringByteLen", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Allocates BSTR with byte length - standard COM string operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SysStringByteLen", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets BSTR byte length - standard COM string operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== C RUNTIME FORMATTING APIs =====
        
        map.insert("_swprintf", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats wide string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== CERTIFICATE STORE APIs =====
        
        map.insert("CertOpenStore", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens certificate store - certificate access".to_string(),
            detection_vectors: vec!["Certificate monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("CertCloseStore", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes certificate store - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CertEnumCertificatesInStore", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Enumerates certificates in store - certificate enumeration".to_string(),
            detection_vectors: vec!["Certificate monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("CertFindCertificateInStore", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds certificate in store - certificate query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CertCreateCertificateContext", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Creates certificate context - standard certificate operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("CertAddCertificateContextToStore", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Adds certificate to store - certificate modification".to_string(),
            detection_vectors: vec!["Certificate monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("CertDeleteCertificateFromStore", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Deletes certificate from store - certificate modification".to_string(),
            detection_vectors: vec!["Certificate monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("PFXImportCertStore", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Imports PFX certificate store - certificate import".to_string(),
            detection_vectors: vec!["Certificate monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== C RUNTIME RANDOM/TIME APIs =====
        
        map.insert("_time32", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets current time - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("rand", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Generates random number - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("srand", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Seeds random generator - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strnlen", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets string length with limit - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== NETAPI32 USER MANAGEMENT APIs =====
        
        map.insert("NetUserAdd", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Adds user account - user creation".to_string(),
            detection_vectors: vec!["Security monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetGroupAddUser", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Adds user to group - group membership modification".to_string(),
            detection_vectors: vec!["Security monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("NetLocalGroupAddMembers", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Adds members to local group - group membership modification".to_string(),
            detection_vectors: vec!["Security monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== PATH APIs =====
        
        map.insert("PathCombineW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Combines path components - standard path operation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("PathFileExistsW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Checks if path exists - standard file query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("StrStrA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds substring - standard string function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== NETAPI32 USER MODIFICATION APIs =====
        
        map.insert("NetUserSetInfo", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Modifies user account - user modification".to_string(),
            detection_vectors: vec!["Security monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== EVENT/SYNCHRONIZATION APIs =====
        
        map.insert("CreateEventA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Creates event object - standard synchronization".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SetEvent", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Sets event to signaled - standard synchronization".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("WaitForSingleObject", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Waits for object - standard synchronization".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== WINDOW MESSAGING APIs =====
        
        map.insert("SendMessageTimeoutW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Sends message with timeout - window messaging".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SHELL EXECUTION APIs =====
        
        map.insert("ShellExecuteA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Executes shell operation - process execution".to_string(),
            detection_vectors: vec!["Process monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== RANDOM APIs =====
        
        map.insert("SystemFunction036", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "RtlGenRandom - cryptographic random generation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== THREAD APIs =====
        
        map.insert("TerminateThread", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Terminates thread - thread manipulation".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Thread monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("_beginthreadex", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Creates thread - standard C runtime thread creation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetCurrentThread", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets current thread handle - standard thread query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== WINSOCK STARTUP/CLEANUP APIs =====
        
        map.insert("WSAStartup", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Initializes Winsock - standard network initialization".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("WSACleanup", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Cleans up Winsock - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== WINHTTP APIs =====
        
        map.insert("WinHttpOpen", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Opens WinHTTP session - network initialization".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("WinHttpOpenRequest", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Opens HTTP request - network activity".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("WinHttpAddRequestHeaders", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Adds HTTP headers - network activity".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("WinHttpSendRequest", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sends HTTP request - network activity".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("WinHttpReceiveResponse", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Receives HTTP response - network activity".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("WinHttpReadData", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Reads HTTP data - network activity".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("WinHttpCloseHandle", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Closes WinHTTP handle - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== C RUNTIME STRING APIs =====
        
        map.insert("_snprintf", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Formats string with size limit - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strchr", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds character in string - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("strncmp", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Compares strings with length - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("_strlwr", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts string to lowercase - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("_strupr", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts string to uppercase - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("isspace", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Checks if whitespace - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== WINSOCK SERVER APIs =====
        
        map.insert("bind", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Binds socket to address - network server".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("listen", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Listens on socket - network server".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("accept", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Accepts connection - network server".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("recv", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Receives data from socket - network communication".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("send", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Sends data to socket - network communication".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("inet_addr", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts IP string to address - standard network utility".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== TOKEN PRIVILEGE APIs =====
        
        map.insert("AdjustTokenPrivileges", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Adjusts token privileges - privilege escalation".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Token monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("LookupPrivilegeValueA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Looks up privilege LUID - standard privilege query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("OpenThreadToken", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens thread token - token access".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Token monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== COMPUTER/ACCOUNT APIs =====
        
        map.insert("GetComputerNameA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets computer name - standard system query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("LookupAccountNameA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Looks up account SID by name - standard account query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== MEMORY QUERY APIs =====
        
        map.insert("VirtualQueryEx", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Queries virtual memory in process - memory reconnaissance".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== CERTIFICATE PROPERTY APIs =====
        
        map.insert("CertGetCertificateContextProperty", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets certificate property - standard certificate query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== CREDENTIAL APIs =====
        
        map.insert("CredMarshalCredentialW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Marshals credential - credential handling".to_string(),
            detection_vectors: vec!["Credential monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("LogonUserW", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Logs on user - authentication/impersonation".to_string(),
            detection_vectors: vec!["Security monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== FILE DELETION APIs =====
        
        map.insert("DeleteFileW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Deletes file (Unicode) - file system modification".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== DEBUG/DUMP APIs =====
        
        map.insert("MiniDumpWriteDump", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Writes process minidump - credential dumping technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string(), "LSASS protection".to_string()],
            locations: Vec::new(),
        });
        
        // ===== MODULE APIs =====
        
        map.insert("GetModuleHandleA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets module handle - standard module query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== REGISTRY MODIFICATION APIs =====
        
        map.insert("RegDeleteKeyExA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Deletes registry key - registry modification".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegDeleteKeyValueA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Deletes registry key value - registry modification".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("RegSaveKeyExA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Saves registry key to file - registry backup/exfiltration".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== SERVICE CONTROL APIs =====
        
        map.insert("ChangeServiceConfig2A", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Changes service optional configuration - service modification".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("QueryServiceStatusEx", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Queries service status extended - service query".to_string(),
            detection_vectors: vec!["Service monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("ControlService", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sends control code to service - service control".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        map.insert("EnumDependentServicesA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Enumerates dependent services - service query".to_string(),
            detection_vectors: vec!["Service monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== SECURITY DESCRIPTOR CONVERSION APIs =====
        
        map.insert("ConvertSecurityDescriptorToStringSecurityDescriptorW", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Converts security descriptor to SDDL - standard security conversion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== PROCESS CREATION APIs =====
        
        map.insert("CreateProcessWithLogonW", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Creates process with different credentials - credential use".to_string(),
            detection_vectors: vec!["Process monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== C RUNTIME WIDE STRING APIs =====
        
        map.insert("wcsstr", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds wide substring - standard C runtime function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SYSTEM SHUTDOWN APIs =====
        
        map.insert("InitiateSystemShutdownExA", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Initiates system shutdown - system control".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Security monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== NT PROCESS CONTROL APIs =====
        
        map.insert("NtSuspendProcess", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Suspends entire process via syscall - process manipulation".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("NtResumeProcess", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Resumes entire process via syscall - process manipulation".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== MEMORY MAPPING APIs =====
        
        map.insert("UnmapViewOfFile", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Unmaps file view - standard memory cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("VirtualAlloc", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Allocates virtual memory - memory allocation".to_string(),
            detection_vectors: vec!["ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== ENVIRONMENT APIs =====
        
        map.insert("ExpandEnvironmentStringsA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Expands environment variables - standard string expansion".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== THREAD/PROCESS ID APIs =====
        
        map.insert("GetProcessIdOfThread", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets process ID from thread - standard query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetWindowThreadProcessId", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets thread/process ID from window - standard query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("OpenThread", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens thread handle - thread access".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Thread monitoring".to_string()],
            locations: Vec::new(),
        });
        
        // ===== WINDOW PROPERTY APIs =====
        
        map.insert("PostMessageA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Posts message to window - window messaging".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SetPropA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Sets window property - window property manipulation".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== STRING COMPARISON APIs =====
        
        map.insert("lstrcmpA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Compares strings - standard string function".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== WINDOW LONG/PROPERTY APIs =====
        
        map.insert("GetWindowLongPtrA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets window long pointer value - window query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("SetWindowLongPtrA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sets window long pointer value - window modification".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("FindWindowA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Finds window by class/title - window query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("GetPropA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets window property - window query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== DDE APIs =====
        
        map.insert("DdeInitializeA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Initializes DDE - DDE communication".to_string(),
            detection_vectors: vec!["DDE monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("DdeUninitialize", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Uninitializes DDE - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        map.insert("DdeConnectList", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Connects to DDE servers - DDE communication".to_string(),
            detection_vectors: vec!["DDE monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("DdeDisconnectList", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Disconnects DDE connections - standard cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== MEMORY FREE APIs =====
        
        map.insert("VirtualFree", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Frees virtual memory - standard memory cleanup".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        // ===== SERVICE UNICODE APIs =====
        
        map.insert("OpenServiceW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens service handle (Unicode) - service access".to_string(),
            detection_vectors: vec!["Service monitoring".to_string()],
            locations: Vec::new(),
        });
        map.insert("OpenSCManagerW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens Service Control Manager (Unicode) - service access".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
            locations: Vec::new(),
        });
        
        // ===== SYSTEM INFO APIs =====
        
        map.insert("GetSystemInfo", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Gets system information - standard system query".to_string(),
            detection_vectors: vec![],
            locations: Vec::new(),
        });
        
        map
    };
    
    /// Risky API combinations
    static ref RISKY_COMBINATIONS: Vec<RiskyCombination> = vec![
        RiskyCombination {
            apis: vec!["VirtualAllocEx".to_string(), "WriteProcessMemory".to_string(), "CreateRemoteThread".to_string()],
            risk_level: OpsecCategory::CriticalRisk,
            description: "Classic process injection pattern".to_string(),
            recommendation: "Consider using alternative techniques or ensure proper OpSec measures".to_string(),
            locations: Vec::new(), // Will be populated during analysis
        },
        RiskyCombination {
            apis: vec!["OpenProcessToken".to_string(), "DuplicateTokenEx".to_string(), "SetThreadToken".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Token manipulation for privilege escalation".to_string(),
            recommendation: "Monitor token operations and consider logging".to_string(),
            locations: Vec::new(), // Will be populated during analysis
        },
        RiskyCombination {
            apis: vec!["NtProtectVirtualMemory".to_string(), "NtWriteVirtualMemory".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Unhooking pattern - modifies memory protection and writes".to_string(),
            recommendation: "Direct syscalls bypass hooks but are more detectable".to_string(),
            locations: Vec::new(), // Will be populated during analysis
        },
        RiskyCombination {
            apis: vec!["IsDebuggerPresent".to_string(), "CheckRemoteDebuggerPresent".to_string()],
            risk_level: OpsecCategory::MediumRisk,
            description: "Multiple anti-debugging checks".to_string(),
            recommendation: "Consider using less detectable anti-debugging techniques".to_string(),
            locations: Vec::new(), // Will be populated during analysis
        },
        RiskyCombination {
            apis: vec!["QueueUserAPC".to_string(), "VirtualAllocEx".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "APC-based injection pattern (queue APC into remote thread)".to_string(),
            recommendation: "APC-based injection is noisy on modern EDR; consider less obvious patterns.".to_string(),
            locations: Vec::new(), // Will be populated during analysis
        },
        RiskyCombination {
            apis: vec!["NtQueueApcThread".to_string(), "NtWriteVirtualMemory".to_string()],
            risk_level: OpsecCategory::CriticalRisk,
            description: "Direct-syscall APC injection with memory write".to_string(),
            recommendation: "Direct-syscall APC injection is powerful but highly profileable; ensure this is really necessary.".to_string(),
            locations: Vec::new(), // Will be populated during analysis
        },
        RiskyCombination {
            apis: vec!["OpenSCManagerA".to_string(), "CreateServiceA".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Service-based persistence via Service Control Manager".to_string(),
            recommendation: "Service-based persistence is durable but noisy; consider short-lived or fileless alternatives.".to_string(),
            locations: Vec::new(), // Will be populated during analysis
        },
        RiskyCombination {
            apis: vec!["RegCreateKeyExA".to_string(), "RegSetValueExA".to_string()],
            risk_level: OpsecCategory::MediumRisk,
            description: "Registry-based persistence pattern (create key and set value)".to_string(),
            recommendation: "Registries are heavily monitored; consider in-memory or transient techniques when possible.".to_string(),
            locations: Vec::new(), // Will be populated during analysis
        },
        
        // ===== EXPANDED INJECTION COMBINATIONS =====
        
        // Section mapping injection
        RiskyCombination {
            apis: vec!["NtCreateSection".to_string(), "NtMapViewOfSection".to_string()],
            risk_level: OpsecCategory::CriticalRisk,
            description: "Section mapping injection pattern - maps section into target process".to_string(),
            recommendation: "Section mapping is stealthier than classic injection but still detectable via ETW and memory mapping monitoring.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["CreateFileMappingA".to_string(), "MapViewOfFile".to_string(), "CreateRemoteThread".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "File mapping-based injection pattern".to_string(),
            recommendation: "File mapping injection is less common but still detectable; consider alternative techniques.".to_string(),
            locations: Vec::new(),
        },
        
        // Process hollowing
        RiskyCombination {
            apis: vec!["CreateProcessA".to_string(), "NtUnmapViewOfSection".to_string(), "NtMapViewOfSection".to_string(), "SetThreadContext".to_string(), "ResumeThread".to_string()],
            risk_level: OpsecCategory::CriticalRisk,
            description: "Process hollowing pattern - unmaps original image and maps malicious code".to_string(),
            recommendation: "Process hollowing is a sophisticated technique but highly detectable via ETW and behavioral analysis.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["CreateProcessA".to_string(), "GetThreadContext".to_string(), "SetThreadContext".to_string(), "ResumeThread".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Early bird injection pattern - hijacks thread before main execution".to_string(),
            recommendation: "Early bird injection is stealthy but detectable via thread monitoring.".to_string(),
            locations: Vec::new(),
        },
        
        // Manual mapping / DLL injection
        RiskyCombination {
            apis: vec!["VirtualAllocEx".to_string(), "WriteProcessMemory".to_string(), "LdrLoadDll".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Manual DLL mapping pattern - loads DLL without standard LoadLibrary".to_string(),
            recommendation: "Manual mapping bypasses some detection but is still detectable via ETW and behavioral analysis.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["NtAllocateVirtualMemory".to_string(), "NtWriteVirtualMemory".to_string(), "LdrGetProcedureAddress".to_string()],
            risk_level: OpsecCategory::CriticalRisk,
            description: "Direct-syscall manual mapping pattern - bypasses hooks".to_string(),
            recommendation: "Direct-syscall manual mapping is powerful but highly profileable; ensure this is necessary.".to_string(),
            locations: Vec::new(),
        },
        
        // ===== EXPANDED UNHOOKING COMBINATIONS =====
        
        RiskyCombination {
            apis: vec!["VirtualProtect".to_string(), "WriteProcessMemory".to_string(), "FlushInstructionCache".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Unhooking pattern - changes protection, writes, and flushes cache".to_string(),
            recommendation: "Unhooking is detectable via memory protection monitoring and ETW.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["NtProtectVirtualMemory".to_string(), "NtWriteVirtualMemory".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Direct-syscall unhooking pattern - bypasses hooks".to_string(),
            recommendation: "Direct-syscall unhooking bypasses hooks but is more detectable via ETW.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["EtwEventWrite".to_string(), "NtProtectVirtualMemory".to_string(), "NtWriteVirtualMemory".to_string()],
            risk_level: OpsecCategory::CriticalRisk,
            description: "ETW patching pattern - disables ETW before unhooking".to_string(),
            recommendation: "ETW patching is a strong evasion technique but highly detectable if ETW is already monitoring.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["AmsiScanBuffer".to_string(), "VirtualProtect".to_string(), "WriteProcessMemory".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "AMSI bypass pattern - unhooks AMSI before scanning".to_string(),
            recommendation: "AMSI bypass is effective but detectable via AMSI monitoring and ETW.".to_string(),
            locations: Vec::new(),
        },
        
        // ===== EXPANDED PERSISTENCE COMBINATIONS =====
        
        // Scheduled tasks
        RiskyCombination {
            apis: vec!["ITaskScheduler".to_string(), "SchRpcRegisterTask".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Scheduled task persistence pattern".to_string(),
            recommendation: "Scheduled tasks are durable but noisy; consider fileless alternatives.".to_string(),
            locations: Vec::new(),
        },
        
        // WMI event subscriptions
        RiskyCombination {
            apis: vec!["IWbemServices".to_string(), "IWbemEventConsumerProvider".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "WMI event subscription persistence pattern".to_string(),
            recommendation: "WMI persistence is stealthy but detectable via WMI monitoring and ETW.".to_string(),
            locations: Vec::new(),
        },
        
        // COM hijacking
        RiskyCombination {
            apis: vec!["CoGetClassObject".to_string(), "RegSetValueExA".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "COM hijacking persistence pattern - modifies COM registration".to_string(),
            recommendation: "COM hijacking is sophisticated but detectable via registry and COM monitoring.".to_string(),
            locations: Vec::new(),
        },
        
        // Startup folder
        RiskyCombination {
            apis: vec!["SHGetSpecialFolderPathA".to_string(), "CreateFileA".to_string(), "WriteFile".to_string()],
            risk_level: OpsecCategory::MediumRisk,
            description: "Startup folder persistence pattern".to_string(),
            recommendation: "Startup folder persistence is simple but easily detected; consider more sophisticated methods.".to_string(),
            locations: Vec::new(),
        },
        
        // Service modification
        RiskyCombination {
            apis: vec!["OpenSCManagerA".to_string(), "ChangeServiceConfigA".to_string(), "StartServiceA".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Service modification and execution pattern".to_string(),
            recommendation: "Service modification is durable but noisy; consider short-lived alternatives.".to_string(),
            locations: Vec::new(),
        },
        
        // ===== EXPANDED ANTI-DEBUG COMBINATIONS =====
        
        RiskyCombination {
            apis: vec!["IsDebuggerPresent".to_string(), "CheckRemoteDebuggerPresent".to_string(), "NtQueryInformationProcess".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Multiple anti-debugging checks - comprehensive debugger detection".to_string(),
            recommendation: "Multiple anti-debug checks are more effective but also more detectable.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["QueryPerformanceCounter".to_string(), "GetTickCount".to_string()],
            risk_level: OpsecCategory::MediumRisk,
            description: "Timing-based anti-debug pattern - detects debugger slowdown".to_string(),
            recommendation: "Timing checks are subtle but detectable via behavioral analysis.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["SetUnhandledExceptionFilter".to_string(), "RaiseException".to_string()],
            risk_level: OpsecCategory::MediumRisk,
            description: "Exception-based anti-debug pattern - detects debugger via exceptions".to_string(),
            recommendation: "Exception-based anti-debug is effective but detectable via behavioral analysis.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["NtSetInformationThread".to_string(), "NtQueryInformationThread".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Thread information manipulation - hides threads from debuggers".to_string(),
            recommendation: "Thread hiding is stealthy but detectable via direct syscall monitoring.".to_string(),
            locations: Vec::new(),
        },
        
        // ===== DISCOVERY COMBINATIONS =====
        
        RiskyCombination {
            apis: vec!["CreateToolhelp32Snapshot".to_string(), "Process32First".to_string(), "Process32Next".to_string()],
            risk_level: OpsecCategory::MediumRisk,
            description: "Process enumeration pattern - reconnaissance activity".to_string(),
            recommendation: "Process enumeration is common but detectable; consider limiting scope.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["EnumServicesStatusA".to_string(), "OpenServiceA".to_string()],
            risk_level: OpsecCategory::MediumRisk,
            description: "Service enumeration pattern - reconnaissance activity".to_string(),
            recommendation: "Service enumeration is detectable via service monitoring.".to_string(),
            locations: Vec::new(),
        },
        RiskyCombination {
            apis: vec!["CredEnumerateA".to_string(), "CredReadA".to_string()],
            risk_level: OpsecCategory::CriticalRisk,
            description: "Credential enumeration and access pattern - credential theft".to_string(),
            recommendation: "Credential access is highly detectable and should be used with extreme caution.".to_string(),
            locations: Vec::new(),
        },
    ];
}

use crate::core::analyzer::opsec_config::{ScoringProfile, ScoringProfiles};

/// Analyze OpSec implications of APIs used in a BOF
/// 
/// This is a convenience wrapper around `analyze_api_opsec_with_bof` for backward compatibility.
/// For enhanced analysis with location information, use `analyze_api_opsec_with_bof` instead.
#[allow(dead_code)] // Kept for backward compatibility
pub fn analyze_api_opsec(imports: &[Import]) -> EnhancedOpsecAnalysis {
    analyze_api_opsec_with_bof(imports, None, None)
}

/// Analyze OpSec implications of APIs used in a BOF (with full BOF context)
/// 
/// # Arguments
/// * `imports` - List of imports from the BOF
/// * `bof` - Optional full BOF context for location information
/// * `profile` - Optional scoring profile (uses default if None)
pub fn analyze_api_opsec_with_bof(
    imports: &[Import], 
    bof: Option<&BofFile>,
    profile: Option<&ScoringProfile>
) -> EnhancedOpsecAnalysis {
    // Use provided profile or default (need to store default in a static or use a different approach)
    // Since we can't return a reference to a temporary, we'll use a lazy static or pass None
    let default_profile = ScoringProfiles::default();
    let profile = profile.unwrap_or(&default_profile);
    let mut api_classifications = Vec::new();
    let mut detected_apis = HashSet::new();
    let mut risky_combinations = Vec::new();
    let mut suspicious_patterns = Vec::new();
    let mut function_findings = Vec::new();
    let mut recommendations = Vec::new();
    
    // Build import map for location lookup
    let mut import_map: HashMap<String, &Import> = HashMap::new();
    for import in imports {
        import_map.insert(import.function.clone(), import);
    }
    
    // Build symbol map if BOF is available - map symbol names to their info
    // (Reserved for future use in disassembly-based analysis)
    let _symbol_map: HashMap<String, (&Symbol, Option<String>)> = if let Some(bof) = bof {
        bof.symbols.iter()
            .filter_map(|sym| {
                let section_name = sym.section.and_then(|idx| {
                    bof.sections.get(idx).map(|s| s.name.clone())
                });
                Some((sym.name.clone(), (sym, section_name)))
            })
            .collect()
    } else {
        HashMap::new()
    };
    
    // Build import symbol to address map (for finding import addresses)
    let import_symbol_to_address: HashMap<String, u64> = if let Some(bof) = bof {
        bof.symbols.iter()
            .filter_map(|sym| {
                // Import symbols typically have names like "__imp_LIBRARY$Function"
                if sym.name.starts_with("__imp_") {
                    Some((sym.name.clone(), sym.value))
                } else {
                    None
                }
            })
            .collect()
    } else {
        HashMap::new()
    };
    
    // Helper function to build locations from API names with enhanced details
    let build_locations_from_apis = |api_names: &[&str]| -> (Vec<String>, Vec<FindingLocation>) {
        let mut location_str = Vec::new();
        let mut locations = Vec::new();
        for api_name in api_names {
            location_str.push(api_name.to_string());
            if let Some(import) = import_map.get(*api_name) {
                let import_address = import_symbol_to_address.get(&import.symbol_name).copied();
                let section_name = if let Some(bof) = bof {
                    bof.symbols.iter()
                        .find(|s| s.name == import.symbol_name)
                        .and_then(|s| s.section)
                        .and_then(|idx| bof.sections.get(idx).map(|s| s.name.clone()))
                } else {
                    None
                };
                
                locations.push(FindingLocation {
                    symbol: Some(import.symbol_name.clone()),
                    offset: None,
                    address: import_address,
                    section: section_name,
                    import_info: Some(ImportLocation {
                        library: import.library.clone(),
                        function: import.function.clone(),
                        symbol_name: import.symbol_name.clone(),
                    }),
                });
            }
        }
        (location_str, locations)
    };
    
    // Classify all APIs with location information (skip whitelisted ones)
    for import in imports {
        if import.library == "Beacon" {
            continue; // Beacon APIs are generally safe
        }
        
        let api_name = &import.function;
        
        // Skip whitelisted APIs (but still track them for combination detection)
        if profile.is_api_whitelisted(api_name) {
            detected_apis.insert(api_name.clone());
            continue;
        }
        
        detected_apis.insert(api_name.clone());
        
        // Build location information with enhanced details
        let import_address = import_symbol_to_address.get(&import.symbol_name).copied();
        let section_name = if let Some(bof) = bof {
            // Try to find the section for this import symbol
            bof.symbols.iter()
                .find(|s| s.name == import.symbol_name)
                .and_then(|s| s.section)
                .and_then(|idx| bof.sections.get(idx).map(|s| s.name.clone()))
        } else {
            None
        };
        
        let locations = vec![FindingLocation {
            symbol: Some(import.symbol_name.clone()), // Import symbol name
            offset: None, // Offset within symbol not available from imports alone
            address: import_address, // Address of the import symbol
            section: section_name,
            import_info: Some(ImportLocation {
                library: import.library.clone(),
                function: import.function.clone(),
                symbol_name: import.symbol_name.clone(),
            }),
        }];
        
        // Strip @N suffix for 32-bit stdcall decorated names (e.g., "CloseHandle@4" -> "CloseHandle")
        let base_api_name = if let Some(at_pos) = api_name.rfind('@') {
            if api_name[at_pos + 1..].chars().all(|c| c.is_ascii_digit()) {
                &api_name[..at_pos]
            } else {
                api_name.as_str()
            }
        } else {
            api_name.as_str()
        };
        
        if let Some(mut info) = API_OPSEC_DB.get(base_api_name).cloned() {
            info.locations = locations;
            api_classifications.push((api_name.clone(), info));
        } else {
            // Unknown API - assume medium risk
            api_classifications.push((api_name.clone(), ApiOpsecInfo {
                category: OpsecCategory::MediumRisk,
                description: format!("Unknown API: {}", api_name),
                detection_vectors: vec!["Unknown detection vectors".to_string()],
                locations,
            }));
        }
    }
    
    // Build function-based groupings if BOF is available
    if let Some(bof) = bof {
        for symbol in &bof.symbols {
            use crate::core::models::bof::SymbolType;
            if symbol.symbol_type == SymbolType::Function {
                let function_name = symbol.name.clone();
                let function_address = Some(symbol.value);
                let section_name = symbol.section.and_then(|idx| {
                    bof.sections.get(idx).map(|s| s.name.clone())
                });
                
                // Collect risky APIs that might be used by this function
                // (Note: this is a heuristic - we don't actually know which APIs a function uses
                //  from imports alone, but we can associate imports with functions based on patterns)
                let mut func_risky_apis = Vec::new();
                for (api_name, api_info) in &api_classifications {
                    if matches!(api_info.category, OpsecCategory::MediumRisk | OpsecCategory::HighRisk | OpsecCategory::CriticalRisk) {
                        func_risky_apis.push((
                            api_name.clone(),
                            ApiOpsecInfo {
                                category: api_info.category,
                                description: api_info.description.clone(),
                                detection_vectors: api_info.detection_vectors.clone(),
                                locations: vec![FindingLocation {
                                    symbol: Some(function_name.clone()),
                                    offset: None,
                                    address: function_address,
                                    section: section_name.clone(),
                                    import_info: api_info.locations.first().and_then(|loc| loc.import_info.clone()),
                                }],
                            }
                        ));
                    }
                }
                
                if !func_risky_apis.is_empty() {
                    function_findings.push(FunctionOpsecInfo {
                        function_name,
                        function_address,
                        risky_apis: func_risky_apis,
                        risky_combinations: Vec::new(), // Will be populated below
                        suspicious_patterns: Vec::new(), // Will be populated below
                    });
                }
            }
        }
    }
    
    // Check for risky combinations (skip whitelisted ones)
    for combination_template in RISKY_COMBINATIONS.iter() {
        let all_present = combination_template.apis.iter()
            .all(|api| detected_apis.contains(api));
        
        if all_present {
            // Skip if this combination is whitelisted
            if profile.is_combination_whitelisted(&combination_template.apis) {
                continue;
            }
            
            // Build location information for the combination with enhanced details
            let locations: Vec<FindingLocation> = combination_template.apis.iter()
                .filter_map(|api_name| {
                    import_map.get(api_name).map(|import| {
                        let import_address = import_symbol_to_address.get(&import.symbol_name).copied();
                        let section_name = if let Some(bof) = bof {
                            bof.symbols.iter()
                                .find(|s| s.name == import.symbol_name)
                                .and_then(|s| s.section)
                                .and_then(|idx| bof.sections.get(idx).map(|s| s.name.clone()))
                        } else {
                            None
                        };
                        
                        FindingLocation {
                            symbol: Some(import.symbol_name.clone()),
                            offset: None,
                            address: import_address,
                            section: section_name,
                            import_info: Some(ImportLocation {
                                library: import.library.clone(),
                                function: import.function.clone(),
                                symbol_name: import.symbol_name.clone(),
                            }),
                        }
                    })
                })
                .collect();
            
            let mut combination = combination_template.clone();
            combination.locations = locations;
            risky_combinations.push(combination);
            recommendations.push(combination_template.recommendation.clone());
        }
    }
    
    // Detect suspicious patterns
    if detected_apis.contains("NtCreateThreadEx") || detected_apis.contains("NtWriteVirtualMemory") {
        let mut apis = Vec::new();
        if detected_apis.contains("NtCreateThreadEx") {
            apis.push("NtCreateThreadEx");
        }
        if detected_apis.contains("NtWriteVirtualMemory") {
            apis.push("NtWriteVirtualMemory");
        }
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::DirectSyscall,
            description: "Direct syscalls detected - bypasses API hooks but more detectable".to_string(),
            severity: OpsecCategory::HighRisk,
            location: if location_str.is_empty() {
                None
            } else {
                Some(format!("Win32 imports: {}", location_str.join(", ")))
            },
            locations,
        });
        recommendations.push("Direct syscalls are detectable via ETW. Consider using indirect syscalls or API unhooking instead.".to_string());
    }
    
    if detected_apis.contains("CreateRemoteThread") && detected_apis.contains("WriteProcessMemory") {
        let (location_str, locations) = build_locations_from_apis(&["CreateRemoteThread", "WriteProcessMemory"]);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "Process injection pattern detected".to_string(),
            severity: OpsecCategory::CriticalRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
        recommendations.push("Process injection is highly detectable. Consider alternative techniques or ensure proper OpSec measures.".to_string());
    }
    
    if detected_apis.contains("OpenProcessToken") && detected_apis.contains("DuplicateTokenEx") {
        let (location_str, locations) = build_locations_from_apis(&["OpenProcessToken", "DuplicateTokenEx"]);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::TokenManipulation,
            description: "Token manipulation pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    if detected_apis.contains("NtProtectVirtualMemory") && detected_apis.contains("NtWriteVirtualMemory") {
        let (location_str, locations) = build_locations_from_apis(&["NtProtectVirtualMemory", "NtWriteVirtualMemory"]);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Unhooking,
            description: "Unhooking pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }

    if detected_apis.contains("QueueUserAPC") || detected_apis.contains("NtQueueApcThread") {
        let apis: Vec<&str> = if detected_apis.contains("NtQueueApcThread") {
            vec!["NtQueueApcThread"]
        } else {
            vec!["QueueUserAPC"]
        };
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "APC-based injection pattern detected (QueueUserAPC / NtQueueApcThread)".to_string(),
            severity: if detected_apis.contains("NtQueueApcThread") {
                OpsecCategory::CriticalRisk
            } else {
                OpsecCategory::HighRisk
            },
            location: Some(format!("Win32 imports: {}", location_str.join(" / "))),
            locations,
        });
    }

    if detected_apis.contains("SetThreadContext") || detected_apis.contains("NtSetContextThread") {
        let apis: Vec<&str> = if detected_apis.contains("NtSetContextThread") {
            vec!["NtSetContextThread"]
        } else {
            vec!["SetThreadContext"]
        };
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "Thread context manipulation detected (potential hollowing or injection)".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(" / "))),
            locations,
        });
    }

    if detected_apis.contains("OpenSCManagerA") && detected_apis.contains("CreateServiceA") {
        let (location_str, locations) = build_locations_from_apis(&["OpenSCManagerA", "CreateServiceA"]);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Persistence,
            description: "Service-based persistence pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }

    if detected_apis.contains("RegCreateKeyExA") && (detected_apis.contains("RegSetValueExA") || detected_apis.contains("RegSetValueExW")) {
        let mut apis = vec!["RegCreateKeyExA"];
        if detected_apis.contains("RegSetValueExA") {
            apis.push("RegSetValueExA");
        } else {
            apis.push("RegSetValueExW");
        }
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Persistence,
            description: "Registry-based persistence pattern detected".to_string(),
            severity: OpsecCategory::MediumRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    // ===== EXPANDED PATTERN DETECTION =====
    
    // Section mapping injection
    if detected_apis.contains("NtCreateSection") && detected_apis.contains("NtMapViewOfSection") {
        let (location_str, locations) = build_locations_from_apis(&["NtCreateSection", "NtMapViewOfSection"]);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "Section mapping injection pattern detected - maps section into target process".to_string(),
            severity: OpsecCategory::CriticalRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
        recommendations.push("Section mapping is stealthier than classic injection but still detectable via ETW.".to_string());
    }
    
    // Process hollowing
    if detected_apis.contains("NtUnmapViewOfSection") && (detected_apis.contains("NtMapViewOfSection") || detected_apis.contains("MapViewOfFile")) {
        let mut apis = vec!["NtUnmapViewOfSection"];
        if detected_apis.contains("NtMapViewOfSection") {
            apis.push("NtMapViewOfSection");
        } else {
            apis.push("MapViewOfFile");
        }
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "Process hollowing pattern detected - unmaps original image and maps malicious code".to_string(),
            severity: OpsecCategory::CriticalRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
        recommendations.push("Process hollowing is sophisticated but highly detectable via ETW and behavioral analysis.".to_string());
    }
    
    // Early bird injection
    if detected_apis.contains("GetThreadContext") && detected_apis.contains("SetThreadContext") && detected_apis.contains("ResumeThread") {
        let (location_str, locations) = build_locations_from_apis(&["GetThreadContext", "SetThreadContext", "ResumeThread"]);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "Early bird injection pattern detected - hijacks thread before main execution".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    // Manual mapping / DLL injection
    if detected_apis.contains("LdrLoadDll") || detected_apis.contains("LdrGetProcedureAddress") {
        let apis: Vec<&str> = if detected_apis.contains("LdrGetProcedureAddress") {
            vec!["LdrGetProcedureAddress"]
        } else {
            vec!["LdrLoadDll"]
        };
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "Manual DLL mapping pattern detected - loads DLL without standard LoadLibrary".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    // Enhanced unhooking patterns
    if detected_apis.contains("VirtualProtect") && detected_apis.contains("WriteProcessMemory") && detected_apis.contains("FlushInstructionCache") {
        let (location_str, locations) = build_locations_from_apis(&["VirtualProtect", "WriteProcessMemory", "FlushInstructionCache"]);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Unhooking,
            description: "Enhanced unhooking pattern detected - changes protection, writes, and flushes cache".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    // ETW patching
    if detected_apis.contains("EtwEventWrite") || detected_apis.contains("EtwEventWriteFull") {
        let apis: Vec<&str> = if detected_apis.contains("EtwEventWriteFull") {
            vec!["EtwEventWriteFull"]
        } else {
            vec!["EtwEventWrite"]
        };
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::AntiDebugging,
            description: "ETW patching pattern detected - attempts to disable ETW".to_string(),
            severity: OpsecCategory::CriticalRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
        recommendations.push("ETW patching is a strong evasion technique but highly detectable if ETW is already monitoring.".to_string());
    }
    
    // AMSI bypass
    if detected_apis.contains("AmsiScanBuffer") || detected_apis.contains("AmsiInitialize") {
        let apis: Vec<&str> = if detected_apis.contains("AmsiInitialize") {
            vec!["AmsiInitialize"]
        } else {
            vec!["AmsiScanBuffer"]
        };
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::AntiDebugging,
            description: "AMSI bypass pattern detected - targets AMSI for unhooking".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    // Timing-based anti-debug
    if detected_apis.contains("QueryPerformanceCounter") && (detected_apis.contains("GetTickCount") || detected_apis.contains("GetTickCount64")) {
        let mut apis = vec!["QueryPerformanceCounter"];
        if detected_apis.contains("GetTickCount64") {
            apis.push("GetTickCount64");
        } else {
            apis.push("GetTickCount");
        }
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::AntiDebugging,
            description: "Timing-based anti-debug pattern detected - detects debugger slowdown".to_string(),
            severity: OpsecCategory::MediumRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    // Exception-based anti-debug
    if detected_apis.contains("SetUnhandledExceptionFilter") || detected_apis.contains("AddVectoredExceptionHandler") {
        let apis: Vec<&str> = if detected_apis.contains("AddVectoredExceptionHandler") {
            vec!["AddVectoredExceptionHandler"]
        } else {
            vec!["SetUnhandledExceptionFilter"]
        };
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::AntiDebugging,
            description: "Exception-based anti-debug pattern detected - detects debugger via exceptions".to_string(),
            severity: OpsecCategory::MediumRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    // Additional persistence patterns
    if detected_apis.contains("ITaskScheduler") || detected_apis.contains("SchRpcRegisterTask") {
        let apis: Vec<&str> = if detected_apis.contains("SchRpcRegisterTask") {
            vec!["SchRpcRegisterTask"]
        } else {
            vec!["ITaskScheduler"]
        };
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Persistence,
            description: "Scheduled task persistence pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    if detected_apis.contains("IWbemServices") || detected_apis.contains("IWbemEventConsumerProvider") {
        let apis: Vec<&str> = if detected_apis.contains("IWbemEventConsumerProvider") {
            vec!["IWbemEventConsumerProvider"]
        } else {
            vec!["IWbemServices"]
        };
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Persistence,
            description: "WMI event subscription persistence pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    if detected_apis.contains("CoGetClassObject") || detected_apis.contains("CoCreateInstance") {
        let apis: Vec<&str> = if detected_apis.contains("CoCreateInstance") {
            vec!["CoCreateInstance"]
        } else {
            vec!["CoGetClassObject"]
        };
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Persistence,
            description: "COM hijacking persistence pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    if detected_apis.contains("SHGetSpecialFolderPathA") || detected_apis.contains("SHGetSpecialFolderPathW") {
        let apis: Vec<&str> = if detected_apis.contains("SHGetSpecialFolderPathW") {
            vec!["SHGetSpecialFolderPathW"]
        } else {
            vec!["SHGetSpecialFolderPathA"]
        };
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Persistence,
            description: "Startup folder persistence pattern detected".to_string(),
            severity: OpsecCategory::MediumRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    // Discovery patterns
    if detected_apis.contains("CreateToolhelp32Snapshot") && (detected_apis.contains("Process32First") || detected_apis.contains("Process32Next")) {
        let mut apis = vec!["CreateToolhelp32Snapshot"];
        if detected_apis.contains("Process32Next") {
            apis.push("Process32Next");
        } else {
            apis.push("Process32First");
        }
        let (location_str, locations) = build_locations_from_apis(&apis);
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::FileSystemAccess,
            description: "Process enumeration pattern detected - reconnaissance activity".to_string(),
            severity: OpsecCategory::MediumRisk,
            location: Some(format!("Win32 imports: {}", location_str.join(", "))),
            locations,
        });
    }
    
    if detected_apis.contains("CredEnumerateA") || detected_apis.contains("CredEnumerateW") || detected_apis.contains("CredReadA") || detected_apis.contains("CredReadW") {
        let mut apis = Vec::new();
        if detected_apis.contains("CredEnumerateW") {
            apis.push("CredEnumerateW");
        } else if detected_apis.contains("CredEnumerateA") {
            apis.push("CredEnumerateA");
        }
        if detected_apis.contains("CredReadW") {
            apis.push("CredReadW");
        } else if detected_apis.contains("CredReadA") {
            apis.push("CredReadA");
        }
        if !apis.is_empty() {
            let (location_str, locations) = build_locations_from_apis(&apis);
            suspicious_patterns.push(SuspiciousPattern {
                pattern_type: PatternType::FileSystemAccess,
                description: "Credential access pattern detected - credential enumeration/access".to_string(),
                severity: OpsecCategory::CriticalRisk,
                location: Some(format!("Win32 imports: {}", location_str.join(", "))),
                locations,
            });
            recommendations.push("Credential access is highly detectable and should be used with extreme caution.".to_string());
        }
    }
    
    // Calculate OpSec scores (0-100) using profile weights
    let mut score: i32 = 100;
    let mut injection_penalty: i32 = 0;
    let mut anti_debug_penalty: i32 = 0;
    let mut persistence_penalty: i32 = 0;
    
    // Deduct points based on API categories using profile weights
    for (_, info) in &api_classifications {
        let weight = profile.get_category_weight(info.category);
        score -= weight;
    }
    
    // Deduct additional points for risky combinations using profile weights
    for combination in &risky_combinations {
        let base = profile.get_combination_weight(combination.risk_level);
        score -= base;

        // Heuristically map combinations into dimensions
        let apis = &combination.apis;
        if apis.iter().any(|a| a.contains("VirtualAlloc") || a.contains("WriteProcessMemory") || a.contains("Thread") || a.contains("Apc")) {
            injection_penalty += base;
        }
        if apis.iter().any(|a| a.contains("Reg") || a.contains("Service") || a.contains("CreateService") || a.contains("OpenSCManager")) {
            persistence_penalty += base;
        }
        if apis.iter().any(|a| a.contains("Debugger") || a.contains("QueryInformationProcess") || a.contains("SetInformationThread")) {
            anti_debug_penalty += base;
        }
    }
    
    // Deduct points for suspicious patterns using profile weights (skip whitelisted patterns)
    for pattern in &suspicious_patterns {
        // Skip whitelisted patterns
        if profile.is_pattern_whitelisted(&pattern.pattern_type) {
            continue;
        }
        
        let base = profile.get_pattern_weight(&pattern.pattern_type);
        score -= base;

        match pattern.pattern_type {
            PatternType::DirectSyscall | PatternType::ProcessInjection | PatternType::Unhooking => {
                injection_penalty += base;
            }
            PatternType::AntiDebugging => {
                anti_debug_penalty += base;
            }
            PatternType::Persistence => {
                persistence_penalty += base;
            }
            _ => {}
        }
    }
    
    // Ensure scores are within bounds
    let opsec_score = score.max(0).min(100) as u8;

    // Overall stealth is derived from global OpSec score (higher is stealthier)
    let overall_stealth_score = opsec_score;

    // Dimension scores: map penalties roughly into 0-100
    let clamp_score = |penalty: i32| -> u8 {
        let raw = 20 + penalty; // minimum baseline
        raw.min(100).max(0) as u8
    };
    let injection_noise_score = clamp_score(injection_penalty);
    let anti_debug_evasion_score = clamp_score(anti_debug_penalty);
    let persistence_profile_score = clamp_score(persistence_penalty);
    
    // Add general recommendations if score is low
    if opsec_score < 50 {
        recommendations.push("Consider reviewing API usage and reducing high-risk operations".to_string());
        recommendations.push("Use alternative techniques with better OpSec characteristics".to_string());
    }
    
    EnhancedOpsecAnalysis {
        api_classifications,
        risky_combinations,
        suspicious_patterns,
        function_findings,
        opsec_score,
        overall_stealth_score,
        injection_noise_score,
        anti_debug_evasion_score,
        persistence_profile_score,
        recommendations,
    }
}

/// Get OpSec category for a specific API
#[allow(dead_code)] // Public API for future use
pub fn get_api_opsec_category(api_name: &str) -> OpsecCategory {
    API_OPSEC_DB.get(api_name)
        .map(|info| info.category)
        .unwrap_or(OpsecCategory::MediumRisk)
}

/// Check if an API combination is risky
#[allow(dead_code)] // Public API for future use
pub fn is_risky_combination(apis: &[String]) -> Option<&RiskyCombination> {
    RISKY_COMBINATIONS.iter()
        .find(|combo| {
            // Check if all APIs in combination are present
            combo.apis.iter().all(|api| apis.contains(api))
        })
}

