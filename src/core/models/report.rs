//! Analysis report data structures

use crate::core::models::bof::BofFile;
use crate::core::models::lint::LintFinding;
use crate::core::utils::disasm::DisassemblyResult;
use crate::core::parser::relocations::{RelocationInfo, RelocationStats};
use std::path::PathBuf;
use std::time::Duration;

/// Complete analysis report
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisReport {
    pub bof: BofFile,
    pub overview: Overview,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub apis: ApiUsage,
    pub security: SecurityAssessment,
    pub lints: Vec<LintFinding>,
    pub dependencies: Dependencies,
    /// Disassembly results (if --disasm was specified)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub disassembly: Vec<DisassemblyResult>,
    /// Extended relocation information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relocations: Option<RelocationReport>,
}

/// Relocation report
#[derive(Debug, Clone, serde::Serialize)]
pub struct RelocationReport {
    /// Statistics
    pub stats: RelocationStats,
    /// Detailed relocation entries
    pub entries: Vec<RelocationInfo>,
}

/// Overview information
#[derive(Debug, Clone, serde::Serialize)]
pub struct Overview {
    pub file_size: u64,
    pub entry_point_found: bool,
    pub architecture: String,
}

/// Section information for report
#[derive(Debug, Clone, serde::Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub size: u32,
    pub entropy: f64,
    pub flags: String,
}

/// Symbol information for report
#[derive(Debug, Clone, serde::Serialize)]
pub struct SymbolInfo {
    pub name: String,
    pub r#type: String,
    pub section: Option<String>,
    pub address: u64,
}

/// API usage information
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiUsage {
    pub beacon_apis: Vec<String>,
    pub win32_apis: Vec<Win32Api>,
}

/// Win32 API information
#[derive(Debug, Clone, serde::Serialize)]
pub struct Win32Api {
    pub dll: String,
    pub function: String,
}

/// Security assessment
#[derive(Debug, Clone, serde::Serialize)]
pub struct SecurityAssessment {
    pub risk_level: RiskLevel,
    pub capabilities: Vec<Capability>,
    pub opsec_score: u8,
    pub opsec_analysis: OpsecAnalysis,
}

/// Risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Capability
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Capability {
    ProcessOperations,
    TokenManipulation,
    MemoryOperations,
    NetworkOperations,
    FileOperations,
    RegistryOperations,
}

/// OpSec analysis
#[derive(Debug, Clone, serde::Serialize)]
pub struct OpsecAnalysis {
    pub risky_apis: Vec<String>,
    pub suspicious_patterns: Vec<String>,
    pub direct_syscalls: bool,
}

/// Dependencies
#[derive(Debug, Clone, serde::Serialize)]
pub struct Dependencies {
    pub dlls: Vec<String>,
    pub functions: Vec<FunctionDependency>,
}

/// Function dependency
#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionDependency {
    pub dll: String,
    pub function: String,
}

/// Test result
#[derive(Debug, Clone, serde::Serialize)]
pub struct TestResult {
    pub file: PathBuf,
    pub success: bool,
    pub duration: Duration,
    pub error: Option<String>,
    pub output: Vec<OutputMessage>,
}

/// Output message
#[derive(Debug, Clone, serde::Serialize)]
pub struct OutputMessage {
    pub timestamp: String,
    pub message_type: OutputType,
    pub content: String,
}

/// Output type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum OutputType {
    Output,
    Error,
    Custom,
}

impl std::fmt::Display for OutputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputType::Output => write!(f, "OUTPUT"),
            OutputType::Error => write!(f, "ERROR"),
            OutputType::Custom => write!(f, "CUSTOM"),
        }
    }
}

/// Validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
}

/// Execution result
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub success: bool,
    pub output: Vec<OutputMessage>,
    pub execution_time: Duration,
    pub error: Option<String>,
    pub api_calls: Vec<ApiCall>,
}

/// API call record
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiCall {
    pub name: String,
    pub timestamp: String,
    pub arguments: Vec<String>,
}

