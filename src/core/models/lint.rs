//! Lint finding data structures

use serde::Serialize;

/// Lint finding
#[derive(Debug, Clone, Serialize)]
pub struct LintFinding {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    pub location: Location,
    pub explanation: String,
    pub suggestion: Option<String>,
}

/// Severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Error => write!(f, "ERROR"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Location information
#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub symbol: Option<String>,
    pub section: Option<String>,
    pub address: Option<u64>,
    pub line: Option<u32>,
}

