//! OpSec (Operational Security) analysis module
//!
//! This module provides advanced OpSec analysis including:
//! - API categorization by OpSec implications
//! - Risky API combination detection
//! - Suspicious pattern detection
//! - Enhanced OpSec scoring

use crate::core::models::bof::Import;
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

/// API OpSec classification
#[derive(Debug, Clone)]
pub struct ApiOpsecInfo {
    pub category: OpsecCategory,
    pub description: String,
    #[allow(dead_code)] // Reserved for future use in detailed reporting
    pub detection_vectors: Vec<String>,
}

/// Risky API combination
#[derive(Debug, Clone)]
pub struct RiskyCombination {
    pub apis: Vec<String>,
    pub risk_level: OpsecCategory,
    pub description: String,
    pub recommendation: String,
}

/// OpSec analysis result
#[derive(Debug, Clone)]
pub struct EnhancedOpsecAnalysis {
    pub api_classifications: Vec<(String, ApiOpsecInfo)>,
    pub risky_combinations: Vec<RiskyCombination>,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
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
    pub location: Option<String>,
}

/// Type of suspicious pattern
#[derive(Debug, Clone, PartialEq, Eq)]
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
        });
        map.insert("WriteProcessMemory", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Writes to another process memory - injection technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
        });
        map.insert("VirtualAllocEx", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Allocates memory in another process - injection technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Process monitoring".to_string()],
        });
        map.insert("NtCreateThreadEx", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Direct syscall for thread creation - bypasses hooks".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
        });
        map.insert("NtWriteVirtualMemory", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Direct syscall for memory write - bypasses hooks".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "ETW".to_string()],
        });
        
        // Token manipulation
        map.insert("OpenProcessToken", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens process token - privilege escalation indicator".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Token monitoring".to_string()],
        });
        map.insert("DuplicateTokenEx", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Duplicates token with impersonation - privilege escalation".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Token monitoring".to_string()],
        });
        map.insert("SetThreadToken", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Sets thread token - impersonation technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Token monitoring".to_string()],
        });
        
        // Unhooking
        map.insert("NtProtectVirtualMemory", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Changes memory protection - unhooking technique".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Memory protection monitoring".to_string()],
        });
        // Note: NtWriteVirtualMemory already added above
        
        // Anti-debugging
        map.insert("IsDebuggerPresent", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Checks for debugger - anti-debugging technique".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
        });
        map.insert("CheckRemoteDebuggerPresent", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Checks for remote debugger - anti-debugging".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
        });
        map.insert("NtQueryInformationProcess", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Queries process information - anti-debugging".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Behavioral analysis".to_string()],
        });
        
        // Network operations
        map.insert("InternetOpenA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Opens internet connection - network activity".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
        });
        map.insert("HttpOpenRequestA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Opens HTTP request - network activity".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
        });
        map.insert("WinHttpConnect", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Connects via WinHTTP - network activity".to_string(),
            detection_vectors: vec!["Network monitoring".to_string()],
        });

        // File operations
        map.insert("CreateFileA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Creates/opens file - file system access".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
        });
        map.insert("WriteFile", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Writes to file - file system access".to_string(),
            detection_vectors: vec!["File system monitoring".to_string()],
        });

        // Registry operations / persistence
        map.insert("RegOpenKeyExA", ApiOpsecInfo {
            category: OpsecCategory::LowRisk,
            description: "Opens registry key - registry access".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
        });
        map.insert("RegSetValueExA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sets registry value - persistence indicator".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
        });
        map.insert("RegCreateKeyExA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Creates registry key - potential persistence mechanism".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
        });
        map.insert("RegSetValueExW", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sets registry value (Unicode) - persistence indicator".to_string(),
            detection_vectors: vec!["Registry monitoring".to_string()],
        });

        // Service control manager / service persistence
        map.insert("OpenSCManagerA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Opens Service Control Manager - potential service-based persistence".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
        });
        map.insert("CreateServiceA", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Creates a Windows service - strong persistence indicator".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
        });
        map.insert("ChangeServiceConfigA", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Changes service configuration - persistence / defense evasion".to_string(),
            detection_vectors: vec!["Service monitoring".to_string(), "ETW".to_string()],
        });

        // Alternate injection / thread manipulation
        map.insert("QueueUserAPC", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Queues an APC to a thread - APC-based code injection".to_string(),
            detection_vectors: vec!["ETW".to_string(), "Thread monitoring".to_string()],
        });
        map.insert("NtQueueApcThread", ApiOpsecInfo {
            category: OpsecCategory::CriticalRisk,
            description: "Queues an APC via direct syscall - stealthy APC-based injection".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "Thread monitoring".to_string()],
        });
        map.insert("SetThreadContext", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Manipulates thread context - code injection / hollowing primitive".to_string(),
            detection_vectors: vec!["Thread monitoring".to_string(), "Behavioral analysis".to_string()],
        });
        map.insert("NtSetContextThread", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Direct syscall to change thread context - injection / hollowing primitive".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "Thread monitoring".to_string()],
        });

        // Additional anti-debug / evasion
        map.insert("OutputDebugStringA", ApiOpsecInfo {
            category: OpsecCategory::MediumRisk,
            description: "Sends string to debugger - often used in anti-debug logic".to_string(),
            detection_vectors: vec!["Behavioral analysis".to_string()],
        });
        map.insert("NtSetInformationThread", ApiOpsecInfo {
            category: OpsecCategory::HighRisk,
            description: "Can be used to hide threads from debuggers".to_string(),
            detection_vectors: vec!["Direct syscall detection".to_string(), "Behavioral analysis".to_string()],
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
        },
        RiskyCombination {
            apis: vec!["OpenProcessToken".to_string(), "DuplicateTokenEx".to_string(), "SetThreadToken".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Token manipulation for privilege escalation".to_string(),
            recommendation: "Monitor token operations and consider logging".to_string(),
        },
        RiskyCombination {
            apis: vec!["NtProtectVirtualMemory".to_string(), "NtWriteVirtualMemory".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Unhooking pattern - modifies memory protection and writes".to_string(),
            recommendation: "Direct syscalls bypass hooks but are more detectable".to_string(),
        },
        RiskyCombination {
            apis: vec!["IsDebuggerPresent".to_string(), "CheckRemoteDebuggerPresent".to_string()],
            risk_level: OpsecCategory::MediumRisk,
            description: "Multiple anti-debugging checks".to_string(),
            recommendation: "Consider using less detectable anti-debugging techniques".to_string(),
        },
        RiskyCombination {
            apis: vec!["QueueUserAPC".to_string(), "VirtualAllocEx".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "APC-based injection pattern (queue APC into remote thread)".to_string(),
            recommendation: "APC-based injection is noisy on modern EDR; consider less obvious patterns.".to_string(),
        },
        RiskyCombination {
            apis: vec!["NtQueueApcThread".to_string(), "NtWriteVirtualMemory".to_string()],
            risk_level: OpsecCategory::CriticalRisk,
            description: "Direct-syscall APC injection with memory write".to_string(),
            recommendation: "Direct-syscall APC injection is powerful but highly profileable; ensure this is really necessary.".to_string(),
        },
        RiskyCombination {
            apis: vec!["OpenSCManagerA".to_string(), "CreateServiceA".to_string()],
            risk_level: OpsecCategory::HighRisk,
            description: "Service-based persistence via Service Control Manager".to_string(),
            recommendation: "Service-based persistence is durable but noisy; consider short-lived or fileless alternatives.".to_string(),
        },
        RiskyCombination {
            apis: vec!["RegCreateKeyExA".to_string(), "RegSetValueExA".to_string()],
            risk_level: OpsecCategory::MediumRisk,
            description: "Registry-based persistence pattern (create key and set value)".to_string(),
            recommendation: "Registries are heavily monitored; consider in-memory or transient techniques when possible.".to_string(),
        },
    ];
}

/// Analyze OpSec implications of APIs used in a BOF
pub fn analyze_api_opsec(imports: &[Import]) -> EnhancedOpsecAnalysis {
    let mut api_classifications = Vec::new();
    let mut detected_apis = HashSet::new();
    let mut risky_combinations = Vec::new();
    let mut suspicious_patterns = Vec::new();
    let mut recommendations = Vec::new();
    
    // Classify all APIs
    for import in imports {
        if import.library == "Beacon" {
            continue; // Beacon APIs are generally safe
        }
        
        let api_name = &import.function;
        detected_apis.insert(api_name.clone());
        
        if let Some(info) = API_OPSEC_DB.get(api_name.as_str()) {
            api_classifications.push((api_name.clone(), info.clone()));
        } else {
            // Unknown API - assume medium risk
            api_classifications.push((api_name.clone(), ApiOpsecInfo {
                category: OpsecCategory::MediumRisk,
                description: format!("Unknown API: {}", api_name),
                detection_vectors: vec!["Unknown detection vectors".to_string()],
            }));
        }
    }
    
    // Check for risky combinations
    for combination in RISKY_COMBINATIONS.iter() {
        let all_present = combination.apis.iter()
            .all(|api| detected_apis.contains(api));
        
        if all_present {
            risky_combinations.push(combination.clone());
            recommendations.push(combination.recommendation.clone());
        }
    }
    
    // Detect suspicious patterns
    if detected_apis.contains("NtCreateThreadEx") || detected_apis.contains("NtWriteVirtualMemory") {
        let mut location = Vec::new();
        if detected_apis.contains("NtCreateThreadEx") {
            location.push("NtCreateThreadEx");
        }
        if detected_apis.contains("NtWriteVirtualMemory") {
            location.push("NtWriteVirtualMemory");
        }
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::DirectSyscall,
            description: "Direct syscalls detected - bypasses API hooks but more detectable".to_string(),
            severity: OpsecCategory::HighRisk,
            location: if location.is_empty() {
                None
            } else {
                Some(format!("Win32 imports: {}", location.join(", ")))
            },
        });
        recommendations.push("Direct syscalls are detectable via ETW. Consider using indirect syscalls or API unhooking instead.".to_string());
    }
    
    if detected_apis.contains("CreateRemoteThread") && detected_apis.contains("WriteProcessMemory") {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "Process injection pattern detected".to_string(),
            severity: OpsecCategory::CriticalRisk,
            location: Some("Win32 imports: CreateRemoteThread, WriteProcessMemory".to_string()),
        });
        recommendations.push("Process injection is highly detectable. Consider alternative techniques or ensure proper OpSec measures.".to_string());
    }
    
    if detected_apis.contains("OpenProcessToken") && detected_apis.contains("DuplicateTokenEx") {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::TokenManipulation,
            description: "Token manipulation pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some("Win32 imports: OpenProcessToken, DuplicateTokenEx".to_string()),
        });
    }
    
    if detected_apis.contains("NtProtectVirtualMemory") && detected_apis.contains("NtWriteVirtualMemory") {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Unhooking,
            description: "Unhooking pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some("Win32 imports: NtProtectVirtualMemory, NtWriteVirtualMemory".to_string()),
        });
    }

    if detected_apis.contains("QueueUserAPC") || detected_apis.contains("NtQueueApcThread") {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "APC-based injection pattern detected (QueueUserAPC / NtQueueApcThread)".to_string(),
            severity: if detected_apis.contains("NtQueueApcThread") {
                OpsecCategory::CriticalRisk
            } else {
                OpsecCategory::HighRisk
            },
            location: Some("Win32 imports: QueueUserAPC / NtQueueApcThread".to_string()),
        });
    }

    if detected_apis.contains("SetThreadContext") || detected_apis.contains("NtSetContextThread") {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "Thread context manipulation detected (potential hollowing or injection)".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some("Win32 imports: SetThreadContext / NtSetContextThread".to_string()),
        });
    }

    if detected_apis.contains("OpenSCManagerA") && detected_apis.contains("CreateServiceA") {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Persistence,
            description: "Service-based persistence pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: Some("Win32 imports: OpenSCManagerA, CreateServiceA".to_string()),
        });
    }

    if detected_apis.contains("RegCreateKeyExA") && (detected_apis.contains("RegSetValueExA") || detected_apis.contains("RegSetValueExW")) {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Persistence,
            description: "Registry-based persistence pattern detected".to_string(),
            severity: OpsecCategory::MediumRisk,
            location: Some("Win32 imports: RegCreateKeyExA, RegSetValueEx*".to_string()),
        });
    }
    
    // Calculate OpSec scores (0-100)
    let mut score: i32 = 100;
    let mut injection_penalty: i32 = 0;
    let mut anti_debug_penalty: i32 = 0;
    let mut persistence_penalty: i32 = 0;
    
    // Deduct points based on API categories (global score)
    for (_, info) in &api_classifications {
        match info.category {
            OpsecCategory::LowRisk => score -= 1,
            OpsecCategory::MediumRisk => score -= 5,
            OpsecCategory::HighRisk => score -= 10,
            OpsecCategory::CriticalRisk => score -= 20,
        }
    }
    
    // Deduct additional points for risky combinations (global + dimension-specific)
    for combination in &risky_combinations {
        let base = match combination.risk_level {
            OpsecCategory::LowRisk => 5,
            OpsecCategory::MediumRisk => 10,
            OpsecCategory::HighRisk => 15,
            OpsecCategory::CriticalRisk => 25,
        };
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
    
    // Deduct points for suspicious patterns (global + dimension-specific)
    for pattern in &suspicious_patterns {
        let base = match pattern.severity {
            OpsecCategory::LowRisk => 3,
            OpsecCategory::MediumRisk => 7,
            OpsecCategory::HighRisk => 12,
            OpsecCategory::CriticalRisk => 20,
        };
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

