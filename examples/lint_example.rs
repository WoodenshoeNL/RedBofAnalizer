//! Example: Using the new lint rules (BOF009-BOF012)
//!
//! This example demonstrates how to use the new lint rules that mirror boflint.py validation.
//!
//! Run with: cargo run --example lint_example -- <path-to-bof.o>

use redbofanalyzer::core;
use redbofanalyzer::core::models::lint::Severity;
use std::env;

fn main() -> anyhow::Result<()> {
    // Get BOF file path from command line
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <bof-file>", args[0]);
        std::process::exit(1);
    }
    
    let bof_path = &args[1];
    println!("Analyzing BOF: {}\n", bof_path);
    
    // Load and parse BOF
    let bof = core::parser::load_bof(bof_path)?;
    
    // Run all lints
    let lint_findings = core::analyzer::linter::run_lints(&bof);
    
    // Get summary
    let summary = core::analyzer::linter::get_lint_summary(&lint_findings);
    println!("=== Lint Summary ===");
    println!("Total: {} | Errors: {} | Warnings: {} | Info: {}\n", 
        summary.total, summary.errors, summary.warnings, summary.infos);
    
    // Filter and display new rules (BOF009-BOF012)
    let new_rules = lint_findings.iter()
        .filter(|f| f.code.starts_with("BOF009") || 
                    f.code.starts_with("BOF010") || 
                    f.code.starts_with("BOF011") || 
                    f.code.starts_with("BOF012"))
        .collect::<Vec<_>>();
    
    if !new_rules.is_empty() {
        println!("=== New Lint Rules (BOF009-BOF012) ===\n");
        
        // Group by code
        let mut by_code: std::collections::HashMap<&str, Vec<_>> = std::collections::HashMap::new();
        for finding in &new_rules {
            by_code.entry(&finding.code).or_insert_with(Vec::new).push(finding);
        }
        
        // Display each rule type
        for code in ["BOF009", "BOF010", "BOF011", "BOF012"] {
            if let Some(findings) = by_code.get(code) {
                println!("[{}] Found {} issue(s):", code, findings.len());
                for finding in findings {
                    let severity_icon = match finding.severity {
                        Severity::Error => "❌",
                        Severity::Warning => "⚠️ ",
                        Severity::Info => "ℹ️ ",
                    };
                    println!("  {} {}", severity_icon, finding.message);
                    
                    if let Some(ref sym) = finding.location.symbol {
                        println!("      Symbol: {}", sym);
                    }
                    if let Some(ref sec) = finding.location.section {
                        println!("      Section: {}", sec);
                    }
                    if let Some(addr) = finding.location.address {
                        println!("      Address: 0x{:X}", addr);
                    }
                    
                    if let Some(ref suggestion) = finding.suggestion {
                        println!("      → {}", suggestion);
                    }
                    println!();
                }
            }
        }
    } else {
        println!("✓ No issues found with new lint rules (BOF009-BOF012)");
    }
    
    // Display all other findings
    let other_findings = lint_findings.iter()
        .filter(|f| !f.code.starts_with("BOF009") && 
                    !f.code.starts_with("BOF010") && 
                    !f.code.starts_with("BOF011") && 
                    !f.code.starts_with("BOF012"))
        .collect::<Vec<_>>();
    
    if !other_findings.is_empty() {
        println!("=== Other Lint Findings (BOF001-BOF008) ===\n");
        for finding in other_findings {
            let severity_icon = match finding.severity {
                Severity::Error => "❌",
                Severity::Warning => "⚠️ ",
                Severity::Info => "ℹ️ ",
            };
            println!("  {} [{}] {}", severity_icon, finding.code, finding.message);
        }
    }
    
    // Example: Check for specific issues
    println!("\n=== Specific Checks ===");
    
    // Check for undefined symbols
    let undefined_count = lint_findings.iter()
        .filter(|f| f.code == "BOF009" && f.severity == Severity::Error)
        .count();
    if undefined_count > 0 {
        println!("⚠️  Found {} undefined symbol(s) - linker may fail", undefined_count);
    } else {
        println!("✓ No undefined symbols detected");
    }
    
    // Check for invalid Beacon imports
    let invalid_beacon_imports = lint_findings.iter()
        .filter(|f| f.code == "BOF012")
        .count();
    if invalid_beacon_imports > 0 {
        println!("❌ Found {} invalid Beacon import(s) - may cause runtime errors", invalid_beacon_imports);
    } else {
        println!("✓ All Beacon imports are valid");
    }
    
    // Check for loader-unfriendly sections
    let unfriendly_sections = lint_findings.iter()
        .filter(|f| f.code == "BOF011")
        .count();
    if unfriendly_sections > 0 {
        println!("⚠️  Found {} loader-unfriendly section(s) - may not work with all loaders", unfriendly_sections);
    } else {
        println!("✓ No loader-unfriendly sections detected");
    }
    
    // Check for unexpected relocations
    let unexpected_relocs = lint_findings.iter()
        .filter(|f| f.code == "BOF010")
        .count();
    if unexpected_relocs > 0 {
        println!("⚠️  Found unexpected relocation type(s) - may not work with all loaders");
    } else {
        println!("✓ All relocations use standard types");
    }
    
    Ok(())
}

