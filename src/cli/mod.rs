//! CLI interface module

pub mod commands;
pub mod output;
pub mod args;

use clap::ValueEnum;

/// Output format for reports
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text format
    Text,
    /// JSON format (machine-readable)
    Json,
    /// Markdown format
    Markdown,
}

