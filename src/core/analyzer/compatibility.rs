//! Compatibility analysis module
//!
//! Analyzes BOF compatibility with different Cobalt Strike versions
//! and detects version-specific features.

use crate::core::models::bof::BofFile;
use std::collections::HashSet;

/// Cobalt Strike version compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsVersion {
    /// Cobalt Strike 4.0
    CS40,
    /// Cobalt Strike 4.1
    CS41,
    /// Cobalt Strike 4.2
    CS42,
    /// Cobalt Strike 4.3+
    CS43Plus,
    /// Unknown/unsupported
    #[allow(dead_code)] // Reserved for future use
    Unknown,
}

/// Compatibility issue
#[derive(Debug, Clone)]
pub struct CompatibilityIssue {
    pub severity: CompatibilitySeverity,
    pub message: String,
    pub affected_versions: Vec<CsVersion>,
    pub recommendation: String,
}

/// Compatibility issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilitySeverity {
    /// Information only
    #[allow(dead_code)] // Reserved for future use
    Info,
    /// Warning - may cause issues
    Warning,
    /// Error - will not work
    Error,
}

/// Compatibility analysis result
#[derive(Debug, Clone)]
pub struct CompatibilityAnalysis {
    pub compatible_versions: Vec<CsVersion>,
    pub issues: Vec<CompatibilityIssue>,
    pub version_specific_features: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Analyze BOF compatibility with Cobalt Strike versions
pub fn analyze_compatibility(bof: &BofFile) -> CompatibilityAnalysis {
    let mut compatible_versions = vec![CsVersion::CS40, CsVersion::CS41, CsVersion::CS42, CsVersion::CS43Plus];
    let mut issues = Vec::new();
    let mut version_specific_features = Vec::new();
    let mut recommendations = Vec::new();
    
    // Check for version-specific Beacon APIs
    let beacon_apis: HashSet<String> = bof.imports.iter()
        .filter(|imp| imp.library == "Beacon")
        .map(|imp| imp.function.clone())
        .collect();
    
    // CS 4.3+ features
    if beacon_apis.contains("BeaconGetSyscallInformation") {
        version_specific_features.push("BeaconGetSyscallInformation (CS 4.3+)".to_string());
        compatible_versions.retain(|&v| matches!(v, CsVersion::CS43Plus));
        issues.push(CompatibilityIssue {
            severity: CompatibilitySeverity::Warning,
            message: "Uses BeaconGetSyscallInformation - requires CS 4.3+".to_string(),
            affected_versions: vec![CsVersion::CS40, CsVersion::CS41, CsVersion::CS42],
            recommendation: "Upgrade to CS 4.3+ or remove this API call".to_string(),
        });
    }
    
    // Check for newer format APIs (available in CS 4.1+)
    if beacon_apis.contains("BeaconFormatAlloc") || 
       beacon_apis.contains("BeaconFormatPrintf") ||
       beacon_apis.contains("BeaconFormatToString") {
        version_specific_features.push("Format APIs (CS 4.1+)".to_string());
        compatible_versions.retain(|&v| !matches!(v, CsVersion::CS40));
        if !compatible_versions.contains(&CsVersion::CS40) {
            issues.push(CompatibilityIssue {
                severity: CompatibilitySeverity::Warning,
                message: "Uses Format APIs - requires CS 4.1+".to_string(),
                affected_versions: vec![CsVersion::CS40],
                recommendation: "Upgrade to CS 4.1+ or use BeaconPrintf instead".to_string(),
            });
        }
    }
    
    // Check for newer memory APIs (available in CS 4.2+)
    if beacon_apis.contains("BeaconVirtualAllocEx") ||
       beacon_apis.contains("BeaconVirtualProtectEx") {
        version_specific_features.push("Extended Memory APIs (CS 4.2+)".to_string());
        compatible_versions.retain(|&v| !matches!(v, CsVersion::CS40 | CsVersion::CS41));
        if !compatible_versions.contains(&CsVersion::CS40) || !compatible_versions.contains(&CsVersion::CS41) {
            issues.push(CompatibilityIssue {
                severity: CompatibilitySeverity::Warning,
                message: "Uses extended memory APIs - requires CS 4.2+".to_string(),
                affected_versions: vec![CsVersion::CS40, CsVersion::CS41],
                recommendation: "Upgrade to CS 4.2+ or use standard memory APIs".to_string(),
            });
        }
    }
    
    // Check for architecture compatibility
    match bof.header.machine {
        crate::core::models::bof::MachineType::X64 => {
            // x64 is supported in all versions
        }
        crate::core::models::bof::MachineType::X86 => {
            issues.push(CompatibilityIssue {
                severity: CompatibilitySeverity::Warning,
                message: "x86 architecture - CS 4.0+ supports x64 only".to_string(),
                affected_versions: vec![CsVersion::CS40, CsVersion::CS41, CsVersion::CS42, CsVersion::CS43Plus],
                recommendation: "Recompile for x64 architecture".to_string(),
            });
        }
        _ => {
            issues.push(CompatibilityIssue {
                severity: CompatibilitySeverity::Error,
                message: format!("Unsupported architecture: {:?}", bof.header.machine),
                affected_versions: vec![CsVersion::CS40, CsVersion::CS41, CsVersion::CS42, CsVersion::CS43Plus],
                recommendation: "Use x64 architecture".to_string(),
            });
        }
    }
    
    // Check for entry point
    if bof.entry_point.is_none() {
        issues.push(CompatibilityIssue {
            severity: CompatibilitySeverity::Error,
            message: "No entry point (go function) found".to_string(),
            affected_versions: vec![CsVersion::CS40, CsVersion::CS41, CsVersion::CS42, CsVersion::CS43Plus],
            recommendation: "Ensure BOF has a 'go' function as entry point".to_string(),
        });
    }
    
    // Check for suspicious section flags
    for section in &bof.sections {
        // Check for unusual section characteristics
        if section.characteristics & 0xE0000000 == 0xE0000000 {
            // All three high bits set (EXECUTE | READ | WRITE) - unusual
            issues.push(CompatibilityIssue {
                severity: CompatibilitySeverity::Warning,
                message: format!("Section '{}' has unusual flags (EXECUTE|READ|WRITE)", section.name),
                affected_versions: vec![],
                recommendation: "Review section characteristics".to_string(),
            });
        }
    }
    
    // Generate recommendations
    if !issues.is_empty() {
        recommendations.push("Review compatibility issues before deployment".to_string());
    }
    
    if compatible_versions.is_empty() {
        recommendations.push("BOF may not be compatible with any CS version - review issues".to_string());
    } else if compatible_versions.len() < 4 {
        recommendations.push(format!("BOF is compatible with CS {} and later", 
            match compatible_versions[0] {
                CsVersion::CS40 => "4.0",
                CsVersion::CS41 => "4.1",
                CsVersion::CS42 => "4.2",
                CsVersion::CS43Plus => "4.3",
                CsVersion::Unknown => "unknown",
            }));
    }
    
    CompatibilityAnalysis {
        compatible_versions,
        issues,
        version_specific_features,
        recommendations,
    }
}

/// Get minimum required CS version
#[allow(dead_code)] // Public API for future use
pub fn get_minimum_version(analysis: &CompatibilityAnalysis) -> Option<CsVersion> {
    analysis.compatible_versions.first().copied()
}

/// Check if BOF is compatible with a specific version
#[allow(dead_code)] // Public API for future use
pub fn is_compatible_with(analysis: &CompatibilityAnalysis, version: CsVersion) -> bool {
    analysis.compatible_versions.contains(&version)
}

impl std::fmt::Display for CsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CsVersion::CS40 => write!(f, "CS 4.0"),
            CsVersion::CS41 => write!(f, "CS 4.1"),
            CsVersion::CS42 => write!(f, "CS 4.2"),
            CsVersion::CS43Plus => write!(f, "CS 4.3+"),
            CsVersion::Unknown => write!(f, "Unknown"),
        }
    }
}

