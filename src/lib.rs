//! RedBofAnalizer - Core Library
//! 
//! This library provides the core functionality for analyzing and executing
//! Beacon Object Files (BOFs).

pub mod core;
pub mod cli;
pub mod gui;

// Re-export commonly used types
pub use core::models::bof::BofFile;
pub use core::models::report::AnalysisReport;

