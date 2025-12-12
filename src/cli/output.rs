//! Output formatting for CLI

use crate::core::models::report::{AnalysisReport, TestResult};
use crate::cli::OutputFormat;
use anyhow::Result;
use serde_json;

/// Format report as text
pub fn format_text(report: &AnalysisReport) -> String {
    let mut output = String::new();
    
    output.push_str("=== BOF Analysis Report ===\n\n");
    output.push_str(&format!("File: {}\n", report.bof.path.display()));
    output.push_str(&format!("Size: {} bytes\n", report.overview.file_size));
    output.push_str(&format!("Architecture: {}\n", report.overview.architecture));
    output.push_str(&format!("Sections: {}\n", report.sections.len()));
    output.push_str(&format!("Symbols: {}\n", report.symbols.len()));
    
    if report.overview.entry_point_found {
        if let Some(entry) = &report.bof.entry_point {
            output.push_str(&format!("Entry Point: {} (found)\n", entry.name));
        } else {
            output.push_str("Entry Point: found\n");
        }
    } else {
        output.push_str("Entry Point: NOT FOUND\n");
    }
    
    // Sections
    if !report.sections.is_empty() {
        output.push_str("\n=== Sections ===\n");
        output.push_str(&format!("{:<12} {:>10} {:>8} {}\n", "Name", "Size", "Entropy", "Flags"));
        output.push_str(&format!("{:-<12} {:-<10} {:-<8} {}\n", "", "", "", ""));
        for section in &report.sections {
            output.push_str(&format!("{:<12} {:>10} {:>8.2} {}\n", 
                section.name, section.size, section.entropy, section.flags));
        }
    }
    
    // APIs
    if !report.apis.beacon_apis.is_empty() || !report.apis.win32_apis.is_empty() {
        output.push_str("\n=== API Usage ===\n");
        if !report.apis.beacon_apis.is_empty() {
            output.push_str("Beacon APIs:\n");
            for api in &report.apis.beacon_apis {
                output.push_str(&format!("  - {}\n", api));
            }
        }
        if !report.apis.win32_apis.is_empty() {
            output.push_str("Win32 APIs:\n");
            for api in &report.apis.win32_apis {
                output.push_str(&format!("  - {}::{}\n", api.dll, api.function));
            }
        }
    }
    
    // Dependencies
    if !report.dependencies.dlls.is_empty() {
        output.push_str("\n=== Dependencies ===\n");
        output.push_str("Required DLLs:\n");
        for dll in &report.dependencies.dlls {
            output.push_str(&format!("  - {}\n", dll));
        }
    }
    
    // Security Assessment
    output.push_str("\n=== Security Assessment ===\n");
    output.push_str(&format!("Risk Level: {:?}\n", report.security.risk_level));
    output.push_str(&format!("OpSec Score: {}/100\n", report.security.opsec_score));
    
    if !report.lints.is_empty() {
        output.push_str("\n=== Lint Findings ===\n");
        for lint in &report.lints {
            output.push_str(&format!("[{}] {}: {}\n", 
                lint.severity, lint.code, lint.message));
        }
    }
    
    output
}

/// Format report as JSON
pub fn format_json(report: &AnalysisReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// Format report as Markdown
pub fn format_markdown(report: &AnalysisReport) -> String {
    let mut output = String::new();
    
    output.push_str("# BOF Analysis Report\n\n");
    output.push_str(&format!("**File:** `{}`\n\n", report.bof.path.display()));
    
    output.push_str("## Overview\n\n");
    output.push_str(&format!("- **Size:** {} bytes\n", report.overview.file_size));
    output.push_str(&format!("- **Architecture:** {}\n", report.overview.architecture));
    output.push_str(&format!("- **Sections:** {}\n", report.sections.len()));
    output.push_str(&format!("- **Symbols:** {}\n", report.symbols.len()));
    
    if report.overview.entry_point_found {
        if let Some(entry) = &report.bof.entry_point {
            output.push_str(&format!("- **Entry Point:** `{}` ✓\n", entry.name));
        } else {
            output.push_str("- **Entry Point:** ✓\n");
        }
    } else {
        output.push_str("- **Entry Point:** ✗ NOT FOUND\n");
    }
    
    // Sections
    if !report.sections.is_empty() {
        output.push_str("\n## Sections\n\n");
        output.push_str("| Name | Size | Entropy | Flags |\n");
        output.push_str("|------|------|---------|-------|\n");
        for section in &report.sections {
            output.push_str(&format!("| {} | {} | {:.2} | {} |\n", 
                section.name, section.size, section.entropy, section.flags));
        }
    }
    
    // APIs
    if !report.apis.beacon_apis.is_empty() || !report.apis.win32_apis.is_empty() {
        output.push_str("\n## API Usage\n\n");
        if !report.apis.beacon_apis.is_empty() {
            output.push_str("### Beacon APIs\n\n");
            for api in &report.apis.beacon_apis {
                output.push_str(&format!("- `{}`\n", api));
            }
            output.push_str("\n");
        }
        if !report.apis.win32_apis.is_empty() {
            output.push_str("### Win32 APIs\n\n");
            output.push_str("| DLL | Function |\n");
            output.push_str("|-----|----------|\n");
            for api in &report.apis.win32_apis {
                output.push_str(&format!("| {} | {} |\n", api.dll, api.function));
            }
        }
    }
    
    // Dependencies
    if !report.dependencies.dlls.is_empty() {
        output.push_str("\n## Dependencies\n\n");
        output.push_str("### Required DLLs\n\n");
        for dll in &report.dependencies.dlls {
            output.push_str(&format!("- `{}`\n", dll));
        }
    }
    
    output.push_str("\n## Security Assessment\n\n");
    output.push_str(&format!("- **Risk Level:** `{:?}`\n", report.security.risk_level));
    output.push_str(&format!("- **OpSec Score:** {}/100\n", report.security.opsec_score));
    
    if !report.lints.is_empty() {
        output.push_str("\n## Lint Findings\n\n");
        output.push_str("| Severity | Code | Message |\n");
        output.push_str("|----------|------|----------|\n");
        for lint in &report.lints {
            output.push_str(&format!("| {} | {} | {} |\n", 
                lint.severity, lint.code, lint.message));
        }
    }
    
    output
}

/// Format test report
pub fn format_test_report(results: &[TestResult], format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Text => {
            let mut output = String::new();
            output.push_str("=== Test Results ===\n\n");
            
            // Summary
            let total = results.len();
            let passed = results.iter().filter(|r| r.success).count();
            let failed = total - passed;
            output.push_str(&format!("Total: {} | Passed: {} | Failed: {}\n\n", total, passed, failed));
            
            // Detailed results
            output.push_str(&format!("{:<50} {:<10} {:<12} {}\n", "File", "Status", "Duration", "Notes"));
            output.push_str(&format!("{:-<50} {:-<10} {:-<12} {}\n", "", "", "", ""));
            
            for result in results {
                let status = if result.success { "PASS" } else { "FAIL" };
                let duration_ms = result.duration.as_millis();
                let notes = result.error.as_deref().unwrap_or("");
                let file_name = result.file.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?");
                output.push_str(&format!("{:<50} {:<10} {:<12} {}\n", 
                    file_name, status, format!("{}ms", duration_ms), notes));
            }
            
            Ok(output)
        }
        OutputFormat::Json => {
            Ok(serde_json::to_string_pretty(results)?)
        }
        OutputFormat::Markdown => {
            let mut output = String::new();
            output.push_str("# Test Results\n\n");
            
            // Summary
            let total = results.len();
            let passed = results.iter().filter(|r| r.success).count();
            let failed = total - passed;
            output.push_str(&format!("**Total:** {} | **Passed:** {} | **Failed:** {}\n\n", total, passed, failed));
            
            // Table
            output.push_str("| File | Status | Duration | Error |\n");
            output.push_str("|------|--------|----------|-------|\n");
            for result in results {
                let status = if result.success { "✓ PASS" } else { "✗ FAIL" };
                let duration_ms = result.duration.as_millis();
                let error = result.error.as_deref().unwrap_or("");
                let file_name = result.file.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?");
                output.push_str(&format!("| {} | {} | {}ms | {} |\n", 
                    file_name, status, duration_ms, error));
            }
            
            Ok(output)
        }
    }
}

