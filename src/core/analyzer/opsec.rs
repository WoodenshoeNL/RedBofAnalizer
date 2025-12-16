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
        
        if let Some(mut info) = API_OPSEC_DB.get(api_name.as_str()).cloned() {
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

