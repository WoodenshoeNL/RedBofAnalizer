//! Calling convention analysis module
//!
//! Analyzes calling conventions used in BOF code to detect mismatches
//! and verify proper function signatures.

use crate::core::models::bof::BofFile;

/// Calling convention type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// Microsoft x64 calling convention (default on Windows x64)
    MicrosoftX64,
    /// System V AMD64 calling convention (Linux)
    #[allow(dead_code)] // Reserved for future cross-platform support
    SystemVAMD64,
    /// cdecl (x86)
    Cdecl,
    /// stdcall (x86)
    Stdcall,
    /// fastcall (x86)
    #[allow(dead_code)] // Reserved for future use
    Fastcall,
    /// Unknown/undetermined
    Unknown,
}

/// Calling convention issue
#[derive(Debug, Clone)]
pub struct CallingConventionIssue {
    pub severity: IssueSeverity,
    pub location: String,
    pub expected: CallingConvention,
    pub detected: Option<CallingConvention>,
    pub message: String,
}

/// Issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSeverity {
    Info,
    Warning,
    #[allow(dead_code)] // Reserved for future use
    Error,
}

/// Calling convention analysis result
#[derive(Debug, Clone)]
pub struct CallingConventionAnalysis {
    pub detected_convention: CallingConvention,
    pub issues: Vec<CallingConventionIssue>,
    pub recommendations: Vec<String>,
}

/// Analyze calling conventions in BOF
pub fn analyze_calling_conventions(bof: &BofFile) -> CallingConventionAnalysis {
    let mut issues = Vec::new();
    let mut recommendations = Vec::new();
    
    // For x64 BOFs, Microsoft x64 calling convention is standard
    let expected_convention = match bof.header.machine {
        crate::core::models::bof::MachineType::X64 => CallingConvention::MicrosoftX64,
        crate::core::models::bof::MachineType::X86 => CallingConvention::Stdcall, // Common for x86 Windows
        _ => CallingConvention::Unknown,
    };
    
    // Check entry point signature
    if let Some(entry) = &bof.entry_point {
        // BOF entry point should be: void go(char* args, int len)
        // On x64 Microsoft calling convention:
        // - First arg (args) in RCX
        // - Second arg (len) in RDX
        // - Caller cleans stack
        
        // Verify entry point exists
        if entry.name != "go" {
            issues.push(CallingConventionIssue {
                severity: IssueSeverity::Warning,
                location: format!("Entry point: {}", entry.name),
                expected: expected_convention,
                detected: None,
                message: format!("Entry point '{}' should be 'go' for standard BOF", entry.name),
            });
        }
    }
    
    // Check for potential calling convention mismatches
    // This is a simplified check - full analysis would require disassembly
    for symbol in &bof.symbols {
        if symbol.is_external {
            // External symbols (imports) should use standard calling conventions
            // Check for unusual naming that might indicate different conventions
            if symbol.name.contains("_cdecl") || symbol.name.contains("__cdecl") {
                issues.push(CallingConventionIssue {
                    severity: IssueSeverity::Info,
                    location: format!("Symbol: {}", symbol.name),
                    expected: expected_convention,
                    detected: Some(CallingConvention::Cdecl),
                    message: "cdecl calling convention detected - may cause issues on x64".to_string(),
                });
            }
        }
    }
    
    // Generate recommendations
    if !issues.is_empty() {
        recommendations.push("Verify calling conventions match expected behavior".to_string());
    }
    
    if expected_convention == CallingConvention::Unknown {
        recommendations.push("Unable to determine expected calling convention - verify architecture".to_string());
    }
    
    CallingConventionAnalysis {
        detected_convention: expected_convention,
        issues,
        recommendations,
    }
}

impl std::fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallingConvention::MicrosoftX64 => write!(f, "Microsoft x64"),
            CallingConvention::SystemVAMD64 => write!(f, "System V AMD64"),
            CallingConvention::Cdecl => write!(f, "cdecl"),
            CallingConvention::Stdcall => write!(f, "stdcall"),
            CallingConvention::Fastcall => write!(f, "fastcall"),
            CallingConvention::Unknown => write!(f, "Unknown"),
        }
    }
}

