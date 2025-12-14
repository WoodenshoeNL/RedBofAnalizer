//! CLI command implementations

use crate::core;
use crate::cli::output;
use crate::cli::OutputFormat;
use std::path::PathBuf;
use anyhow::{Result, Context};
use log::info;

/// Analyze a BOF file
pub fn analyze(
    file: PathBuf,
    security: bool,
    disasm: bool,
    apis: bool,
    dependencies: bool,
    lints: bool,
    relocs: bool,
    enhanced: bool,
    output_file: Option<PathBuf>,
    format: OutputFormat,
    yara_rules: &[core::analyzer::YaraRuleSource],
) -> Result<()> {
    info!("Analyzing BOF file: {:?}", file);

    // Check if file exists
    if !file.exists() {
        anyhow::bail!("BOF file not found: {:?}", file);
    }

    // Load and parse BOF
    let bof = core::parser::load_bof(&file)?;
    
    // Perform analysis
    // Use default rules if no custom rules provided, otherwise don't use defaults (CLI behavior)
    let use_default_rules = yara_rules.is_empty();
    let report = core::analyzer::analyze(&bof, security, disasm, apis, dependencies, lints, relocs, yara_rules, use_default_rules)?;
    
    // Perform enhanced analysis if requested
    if enhanced {
        let enhanced_opsec = core::analyzer::analyze_api_opsec(&bof.imports);
        let compatibility = core::analyzer::analyze_compatibility(&bof);
        let calling_conv = core::analyzer::analyze_calling_conventions(&bof);
        
        // Display enhanced analysis results
        if matches!(format, OutputFormat::Text) {
            println!("\n=== Enhanced OpSec Analysis ===");
            println!("OpSec Score: {}/100", enhanced_opsec.opsec_score);
            
            if !enhanced_opsec.risky_combinations.is_empty() {
                println!("\nRisky API Combinations:");
                for combo in &enhanced_opsec.risky_combinations {
                    println!("  [!] {}: {}", 
                        match combo.risk_level {
                            core::analyzer::opsec::OpsecCategory::LowRisk => "LOW",
                            core::analyzer::opsec::OpsecCategory::MediumRisk => "MEDIUM",
                            core::analyzer::opsec::OpsecCategory::HighRisk => "HIGH",
                            core::analyzer::opsec::OpsecCategory::CriticalRisk => "CRITICAL",
                        },
                        combo.description);
                    println!("      APIs: {}", combo.apis.join(", "));
                    println!("      Recommendation: {}", combo.recommendation);
                }
            }
            
            if !enhanced_opsec.suspicious_patterns.is_empty() {
                println!("\nSuspicious Patterns:");
                for pattern in &enhanced_opsec.suspicious_patterns {
                    println!("  [!] {}: {}", 
                        match pattern.severity {
                            core::analyzer::opsec::OpsecCategory::LowRisk => "LOW",
                            core::analyzer::opsec::OpsecCategory::MediumRisk => "MEDIUM",
                            core::analyzer::opsec::OpsecCategory::HighRisk => "HIGH",
                            core::analyzer::opsec::OpsecCategory::CriticalRisk => "CRITICAL",
                        },
                        pattern.description);
                }
            }
            
            if !enhanced_opsec.recommendations.is_empty() {
                println!("\nRecommendations:");
                for rec in &enhanced_opsec.recommendations {
                    println!("  - {}", rec);
                }
            }
            
            println!("\n=== Compatibility Analysis ===");
            println!("Compatible with: {}", 
                compatibility.compatible_versions.iter()
                    .map(|v| format!("{}", v))
                    .collect::<Vec<_>>()
                    .join(", "));
            
            if !compatibility.version_specific_features.is_empty() {
                println!("\nVersion-Specific Features:");
                for feature in &compatibility.version_specific_features {
                    println!("  - {}", feature);
                }
            }
            
            if !compatibility.issues.is_empty() {
                println!("\nCompatibility Issues:");
                for issue in &compatibility.issues {
                    println!("  [{}] {} (affects: {})", 
                        match issue.severity {
                            core::analyzer::compatibility::CompatibilitySeverity::Info => "INFO",
                            core::analyzer::compatibility::CompatibilitySeverity::Warning => "WARN",
                            core::analyzer::compatibility::CompatibilitySeverity::Error => "ERROR",
                        },
                        issue.message,
                        issue.affected_versions.iter()
                            .map(|v| format!("{}", v))
                            .collect::<Vec<_>>()
                            .join(", "));
                    println!("      Recommendation: {}", issue.recommendation);
                }
            }
            
            println!("\n=== Calling Convention Analysis ===");
            println!("Detected Convention: {}", calling_conv.detected_convention);
            
            if !calling_conv.issues.is_empty() {
                println!("\nIssues:");
                for issue in &calling_conv.issues {
                    println!("  [{}] {}: {}", 
                        match issue.severity {
                            core::analyzer::calling_convention::IssueSeverity::Info => "INFO",
                            core::analyzer::calling_convention::IssueSeverity::Warning => "WARN",
                            core::analyzer::calling_convention::IssueSeverity::Error => "ERROR",
                        },
                        issue.location,
                        issue.message);
                }
            }
        }
    }

    // Format and output report
    let formatted = match format {
        OutputFormat::Text => output::format_text(&report),
        OutputFormat::Json => output::format_json(&report)?,
        OutputFormat::Markdown => output::format_markdown(&report),
    };

    // Write to file or stdout
    if let Some(output_path) = output_file {
        std::fs::write(&output_path, formatted)?;
        info!("Report written to: {:?}", output_path);
    } else {
        println!("{}", formatted);
    }

    Ok(())
}

/// Execute a BOF file
pub fn execute(
    file: PathBuf,
    args: Option<String>,
    sandbox: bool,
    trace: bool,
    timeout: u64,
) -> Result<()> {
    info!("Executing BOF file: {:?}", file);

    // Load and parse BOF
    let bof = core::parser::load_bof(&file)?;
    
    // Parse arguments if provided
    let packed_args = if let Some(arg_str) = args {
        core::executor::arguments::parse_arguments(&arg_str)
            .context(format!("Failed to parse arguments: {}", arg_str))?
    } else {
        Vec::new()
    };

    // Execute BOF
    let result = core::executor::execute(
        &bof,
        &packed_args,
        sandbox,
        trace,
        std::time::Duration::from_secs(timeout),
    )?;

    // Display results
    println!("\n=== Execution Results ===");
    println!("Status: {}", if result.success { "SUCCESS" } else { "FAILED" });
    println!("Execution Time: {:.2}s", result.execution_time.as_secs_f64());
    
    if !result.success {
        if let Some(err) = &result.error {
            eprintln!("\nError: {}", err);
        }
    }
    
    // Display output
    if !result.output.is_empty() {
        println!("\n--- BOF Output ---");
        for msg in &result.output {
            println!("[{}] {}", msg.message_type, msg.content);
        }
    }
    
    // Display API calls if tracing was enabled
    if !result.api_calls.is_empty() {
        println!("\n--- API Calls ({} total) ---", result.api_calls.len());
        for call in &result.api_calls {
            if call.arguments.is_empty() {
                println!("  {} @ {}", call.name, call.timestamp);
            } else {
                println!("  {} @ {}", call.name, call.timestamp);
                for arg in &call.arguments {
                    println!("    - {}", arg);
                }
            }
        }
    }

    Ok(())
}

/// Test all BOFs in a directory
pub fn test(
    directory: PathBuf,
    report_format: OutputFormat,
    filter: Option<String>,
    output_file: Option<PathBuf>,
    continue_on_error: bool,
) -> Result<()> {
    info!("Testing BOFs in directory: {:?}", directory);

    // Find all BOF files
    let bof_files = core::utils::find_bof_files(&directory, filter.as_deref())?;
    
    info!("Found {} BOF files", bof_files.len());

    let mut results = Vec::new();
    for bof_file in bof_files {
        info!("Testing: {:?}", bof_file);
        
        let start = std::time::Instant::now();
        let result = match core::executor::test_bof(&bof_file, continue_on_error) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error testing {:?}: {}", bof_file, e);
                if !continue_on_error {
                    return Err(e);
                }
                continue;
            }
        };
        let duration = start.elapsed();

        results.push(core::models::report::TestResult {
            file: bof_file,
            success: result.success,
            duration,
            error: result.error,
            output: result.output,
        });
    }

    // Generate report
    let report = output::format_test_report(&results, report_format)?;
    
    if let Some(output_path) = output_file {
        std::fs::write(&output_path, report)?;
        info!("Test report written to: {:?}", output_path);
    } else {
        println!("{}", report);
    }

    Ok(())
}

/// Validate a BOF file
pub fn validate(file: PathBuf) -> Result<()> {
    info!("Validating BOF file: {:?}", file);

    // Load and parse BOF
    let bof = core::parser::load_bof(&file)?;
    
    // Validate
    let validation = core::analyzer::validate(&bof)?;
    
    if validation.is_valid {
        println!("✓ BOF file is valid");
        Ok(())
    } else {
        eprintln!("✗ BOF file validation failed:");
        for error in &validation.errors {
            eprintln!("  - {}", error);
        }
        anyhow::bail!("Validation failed");
    }
}

