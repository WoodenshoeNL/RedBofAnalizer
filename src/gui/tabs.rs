//! Tab management for the GUI

#![allow(dead_code)]

/// Available tabs in the application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Overview,
    Sections,
    Symbols,
    Imports,
    Lints,
    OpSec,
    Disassembly,
    StackAnalysis,
    Yara,
    Execute,
}

impl Default for ActiveTab {
    fn default() -> Self {
        Self::Overview
    }
}

impl ActiveTab {
    /// Get tab title
    pub fn title(&self) -> &str {
        match self {
            Self::Overview => "Overview",
            Self::Sections => "Sections",
            Self::Symbols => "Symbols",
            Self::Imports => "Imports",
            Self::Lints => "Lints",
            Self::OpSec => "OpSec",
            Self::Disassembly => "Disassembly",
            Self::StackAnalysis => "Stack",
            Self::Yara => "YARA",
            Self::Execute => "Execute",
        }
    }
    
    /// Get tab icon
    pub fn icon(&self) -> &str {
        match self {
            Self::Overview => "📊",
            Self::Sections => "📁",
            Self::Symbols => "🔣",
            Self::Imports => "📥",
            Self::Lints => "⚠️",
            Self::OpSec => "🔒",
            Self::Disassembly => "💻",
            Self::StackAnalysis => "📊",
            Self::Yara => "🔍",
            Self::Execute => "▶️",
        }
    }
}

