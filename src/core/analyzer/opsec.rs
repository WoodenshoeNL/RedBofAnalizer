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
    pub opsec_score: u8,
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
pub enum PatternType {
    DirectSyscall,
    ProcessInjection,
    TokenManipulation,
    Unhooking,
    #[allow(dead_code)] // Reserved for future use
    AntiDebugging,
    #[allow(dead_code)] // Reserved for future use
    StringObfuscation,
    #[allow(dead_code)] // Reserved for future use
    HighEntropy,
    #[allow(dead_code)] // Reserved for future use
    SuspiciousDll,
    #[allow(dead_code)] // Reserved for future use
    NetworkActivity,
    #[allow(dead_code)] // Reserved for future use
    FileSystemAccess,
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
        
        // Registry operations
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
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::DirectSyscall,
            description: "Direct syscalls detected - bypasses API hooks but more detectable".to_string(),
            severity: OpsecCategory::HighRisk,
            location: None,
        });
        recommendations.push("Direct syscalls are detectable via ETW. Consider using indirect syscalls or API unhooking instead.".to_string());
    }
    
    if detected_apis.contains("CreateRemoteThread") && detected_apis.contains("WriteProcessMemory") {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::ProcessInjection,
            description: "Process injection pattern detected".to_string(),
            severity: OpsecCategory::CriticalRisk,
            location: None,
        });
        recommendations.push("Process injection is highly detectable. Consider alternative techniques or ensure proper OpSec measures.".to_string());
    }
    
    if detected_apis.contains("OpenProcessToken") && detected_apis.contains("DuplicateTokenEx") {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::TokenManipulation,
            description: "Token manipulation pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: None,
        });
    }
    
    if detected_apis.contains("NtProtectVirtualMemory") && detected_apis.contains("NtWriteVirtualMemory") {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::Unhooking,
            description: "Unhooking pattern detected".to_string(),
            severity: OpsecCategory::HighRisk,
            location: None,
        });
    }
    
    // Calculate OpSec score (0-100, higher is better)
    let mut score: i32 = 100;
    
    // Deduct points based on API categories
    for (_, info) in &api_classifications {
        match info.category {
            OpsecCategory::LowRisk => score -= 1,
            OpsecCategory::MediumRisk => score -= 5,
            OpsecCategory::HighRisk => score -= 10,
            OpsecCategory::CriticalRisk => score -= 20,
        }
    }
    
    // Deduct additional points for risky combinations
    for combination in &risky_combinations {
        match combination.risk_level {
            OpsecCategory::LowRisk => score -= 5,
            OpsecCategory::MediumRisk => score -= 10,
            OpsecCategory::HighRisk => score -= 15,
            OpsecCategory::CriticalRisk => score -= 25,
        }
    }
    
    // Deduct points for suspicious patterns
    for pattern in &suspicious_patterns {
        match pattern.severity {
            OpsecCategory::LowRisk => score -= 3,
            OpsecCategory::MediumRisk => score -= 7,
            OpsecCategory::HighRisk => score -= 12,
            OpsecCategory::CriticalRisk => score -= 20,
        }
    }
    
    // Ensure score is within bounds
    let opsec_score = score.max(0).min(100) as u8;
    
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

