//! Output formatting for CLI

use crate::core::models::report::{AnalysisReport, TestResult};
use crate::core::models::lint::{LintFinding, Severity};
use crate::core::models::bof::MachineType;
use crate::core::analyzer::get_lint_summary;
use crate::core::utils::disasm::{format_disassembly_text, format_disassembly_markdown};
use crate::core::parser::relocations::{format_relocations_text, format_relocations_markdown};
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
    
    // Capabilities
    if !report.security.capabilities.is_empty() {
        output.push_str("\nCapabilities:\n");
        for cap in &report.security.capabilities {
            output.push_str(&format!("  - {:?}\n", cap));
        }
    }
    
    // OpSec Analysis details
    if report.security.opsec_analysis.direct_syscalls {
        output.push_str("\n[!] Direct syscalls detected\n");
    }
    if !report.security.opsec_analysis.risky_apis.is_empty() {
        output.push_str("\nRisky APIs:\n");
        for api in &report.security.opsec_analysis.risky_apis {
            output.push_str(&format!("  - {}\n", api));
        }
    }
    
    // Lint Findings
    if !report.lints.is_empty() {
        output.push_str(&format_lint_findings_text(&report.lints));
    }
    
    // Relocations
    if let Some(ref reloc_report) = report.relocations {
        let is_x64 = matches!(report.bof.header.machine, MachineType::X64);
        output.push_str("\n");
        output.push_str(&format_relocations_text(&reloc_report.entries, is_x64));
    }
    
    // Disassembly
    if !report.disassembly.is_empty() {
        output.push_str("\n");
        for disasm in &report.disassembly {
            // Limit to 100 instructions per section in text output
            output.push_str(&format_disassembly_text(disasm, Some(100)));
            output.push_str("\n");
        }
    }
    
    output
}

/// Format lint findings for text output
fn format_lint_findings_text(findings: &[LintFinding]) -> String {
    let mut output = String::new();
    let summary = get_lint_summary(findings);
    
    output.push_str("\n=== Lint Findings ===\n");
    output.push_str(&format!("Summary: {}\n\n", summary));
    
    for (i, lint) in findings.iter().enumerate() {
        let severity_marker = match lint.severity {
            Severity::Error => "❌",
            Severity::Warning => "⚠️",
            Severity::Info => "ℹ️",
        };
        
        output.push_str(&format!("{}. {} [{}] {}\n", i + 1, severity_marker, lint.code, lint.message));
        
        // Location info
        if let Some(ref symbol) = lint.location.symbol {
            output.push_str(&format!("   Symbol: {}\n", symbol));
        }
        if let Some(ref section) = lint.location.section {
            output.push_str(&format!("   Section: {}\n", section));
        }
        if let Some(addr) = lint.location.address {
            output.push_str(&format!("   Address: 0x{:X}\n", addr));
        }
        
        // Explanation (truncated for text output)
        let explanation = if lint.explanation.len() > 200 {
            format!("{}...", &lint.explanation[..200])
        } else {
            lint.explanation.clone()
        };
        output.push_str(&format!("   Explanation: {}\n", explanation));
        
        // Suggestion
        if let Some(ref suggestion) = lint.suggestion {
            output.push_str(&format!("   Suggestion: {}\n", suggestion));
        }
        
        output.push_str("\n");
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
    
    // Capabilities
    if !report.security.capabilities.is_empty() {
        output.push_str("\n### Capabilities\n\n");
        for cap in &report.security.capabilities {
            output.push_str(&format!("- {:?}\n", cap));
        }
    }
    
    // OpSec Analysis
    if report.security.opsec_analysis.direct_syscalls || 
       !report.security.opsec_analysis.risky_apis.is_empty() {
        output.push_str("\n### OpSec Analysis\n\n");
        
        if report.security.opsec_analysis.direct_syscalls {
            output.push_str("⚠️ **Direct syscalls detected**\n\n");
        }
        
        if !report.security.opsec_analysis.risky_apis.is_empty() {
            output.push_str("**Risky APIs:**\n");
            for api in &report.security.opsec_analysis.risky_apis {
                output.push_str(&format!("- `{}`\n", api));
            }
        }
    }
    
    // Lint Findings
    if !report.lints.is_empty() {
        output.push_str(&format_lint_findings_markdown(&report.lints));
    }
    
    // Relocations
    if let Some(ref reloc_report) = report.relocations {
        let is_x64 = matches!(report.bof.header.machine, MachineType::X64);
        output.push_str("\n---\n\n");
        output.push_str(&format_relocations_markdown(&reloc_report.entries, is_x64));
    }
    
    // Disassembly
    if !report.disassembly.is_empty() {
        output.push_str("\n---\n\n");
        for disasm in &report.disassembly {
            // Limit to 100 instructions per section in markdown output
            output.push_str(&format_disassembly_markdown(disasm, Some(100)));
            output.push_str("\n");
        }
    }
    
    output
}

/// Format lint findings for markdown output
fn format_lint_findings_markdown(findings: &[LintFinding]) -> String {
    let mut output = String::new();
    let summary = get_lint_summary(findings);
    
    output.push_str("\n## Lint Findings\n\n");
    output.push_str(&format!("**Summary:** {} total ({} errors, {} warnings, {} info)\n\n",
        summary.total, summary.errors, summary.warnings, summary.infos));
    
    // Group by severity
    let errors: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Error).collect();
    let warnings: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Warning).collect();
    let infos: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Info).collect();
    
    if !errors.is_empty() {
        output.push_str("### ❌ Errors\n\n");
        for lint in errors {
            output.push_str(&format_single_lint_markdown(lint));
        }
    }
    
    if !warnings.is_empty() {
        output.push_str("### ⚠️ Warnings\n\n");
        for lint in warnings {
            output.push_str(&format_single_lint_markdown(lint));
        }
    }
    
    if !infos.is_empty() {
        output.push_str("### ℹ️ Info\n\n");
        for lint in infos {
            output.push_str(&format_single_lint_markdown(lint));
        }
    }
    
    output
}

/// Format a single lint finding for markdown
fn format_single_lint_markdown(lint: &LintFinding) -> String {
    let mut output = String::new();
    
    output.push_str(&format!("#### `{}` - {}\n\n", lint.code, lint.message));
    
    // Location info
    let mut location_parts = Vec::new();
    if let Some(ref symbol) = lint.location.symbol {
        location_parts.push(format!("Symbol: `{}`", symbol));
    }
    if let Some(ref section) = lint.location.section {
        location_parts.push(format!("Section: `{}`", section));
    }
    if let Some(addr) = lint.location.address {
        location_parts.push(format!("Address: `0x{:X}`", addr));
    }
    
    if !location_parts.is_empty() {
        output.push_str(&format!("**Location:** {}\n\n", location_parts.join(" | ")));
    }
    
    output.push_str(&format!("**Explanation:**\n{}\n\n", lint.explanation));
    
    if let Some(ref suggestion) = lint.suggestion {
        output.push_str(&format!("> 💡 **Suggestion:** {}\n\n", suggestion));
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

