//! CLI command implementations

use crate::cli::output;
use crate::cli::OutputFormat;
use crate::core;
use anyhow::{Context, Result};
use log::info;
use std::path::PathBuf;

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
    let report = core::analyzer::analyze(
        &bof,
        security,
        disasm,
        apis,
        dependencies,
        lints,
        relocs,
        yara_rules,
        use_default_rules,
    )?;

    // Perform enhanced analysis if requested
    if enhanced {
        use core::analyzer::opsec::analyze_api_opsec_with_bof;
        let enhanced_opsec = analyze_api_opsec_with_bof(&bof.imports, Some(&bof), None);
        let compatibility = core::analyzer::analyze_compatibility(&bof);
        let calling_conv = core::analyzer::analyze_calling_conventions(&bof);

        // Display enhanced analysis results
        if matches!(format, OutputFormat::Text) {
            println!("\n=== Enhanced OpSec Analysis ===");
            println!("OpSec Score: {}/100", enhanced_opsec.opsec_score);

            if !enhanced_opsec.risky_combinations.is_empty() {
                println!("\nRisky API Combinations:");
                for combo in &enhanced_opsec.risky_combinations {
                    println!(
                        "  [!] {}: {}",
                        match combo.risk_level {
                            core::analyzer::opsec::OpsecCategory::LowRisk => "LOW",
                            core::analyzer::opsec::OpsecCategory::MediumRisk => "MEDIUM",
                            core::analyzer::opsec::OpsecCategory::HighRisk => "HIGH",
                            core::analyzer::opsec::OpsecCategory::CriticalRisk => "CRITICAL",
                        },
                        combo.description
                    );
                    println!("      APIs: {}", combo.apis.join(", "));
                    println!("      Recommendation: {}", combo.recommendation);
                }
            }

            if !enhanced_opsec.suspicious_patterns.is_empty() {
                println!("\nSuspicious Patterns:");
                for pattern in &enhanced_opsec.suspicious_patterns {
                    println!(
                        "  [!] {}: {}",
                        match pattern.severity {
                            core::analyzer::opsec::OpsecCategory::LowRisk => "LOW",
                            core::analyzer::opsec::OpsecCategory::MediumRisk => "MEDIUM",
                            core::analyzer::opsec::OpsecCategory::HighRisk => "HIGH",
                            core::analyzer::opsec::OpsecCategory::CriticalRisk => "CRITICAL",
                        },
                        pattern.description
                    );
                }
            }

            if !enhanced_opsec.recommendations.is_empty() {
                println!("\nRecommendations:");
                for rec in &enhanced_opsec.recommendations {
                    println!("  - {}", rec);
                }
            }

            println!("\n=== Compatibility Analysis ===");
            println!(
                "Compatible with: {}",
                compatibility
                    .compatible_versions
                    .iter()
                    .map(|v| format!("{}", v))
                    .collect::<Vec<_>>()
                    .join(", ")
            );

            if !compatibility.version_specific_features.is_empty() {
                println!("\nVersion-Specific Features:");
                for feature in &compatibility.version_specific_features {
                    println!("  - {}", feature);
                }
            }

            if !compatibility.issues.is_empty() {
                println!("\nCompatibility Issues:");
                for issue in &compatibility.issues {
                    println!(
                        "  [{}] {} (affects: {})",
                        match issue.severity {
                            core::analyzer::compatibility::CompatibilitySeverity::Info => "INFO",
                            core::analyzer::compatibility::CompatibilitySeverity::Warning => "WARN",
                            core::analyzer::compatibility::CompatibilitySeverity::Error => "ERROR",
                        },
                        issue.message,
                        issue
                            .affected_versions
                            .iter()
                            .map(|v| format!("{}", v))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    println!("      Recommendation: {}", issue.recommendation);
                }
            }

            println!("\n=== Calling Convention Analysis ===");
            println!("Detected Convention: {}", calling_conv.detected_convention);

            if !calling_conv.issues.is_empty() {
                println!("\nIssues:");
                for issue in &calling_conv.issues {
                    println!(
                        "  [{}] {}: {}",
                        match issue.severity {
                            core::analyzer::calling_convention::IssueSeverity::Info => "INFO",
                            core::analyzer::calling_convention::IssueSeverity::Warning => "WARN",
                            core::analyzer::calling_convention::IssueSeverity::Error => "ERROR",
                        },
                        issue.location,
                        issue.message
                    );
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
/// Live output callback shared by the execute and s1 commands: labels each
/// entry by callback type and flushes so async output streams promptly.
fn print_live_entry(entry: &core::executor::capture::OutputEntry) {
    let kind = match entry.callback_type {
        0x00 => "output",
        0x0d => "error",
        _ => "custom",
    };
    print!("[{}] {}", kind, String::from_utf8_lossy(&entry.data));
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

pub fn execute(
    file: PathBuf,
    args: Option<String>,
    sandbox: bool,
    trace: bool,
    timeout: u64,
    is_async: bool,
    async_timeout: Option<u64>,
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
    let result = if is_async {
        println!("\n--- Live Output (async) ---");
        core::executor::execute_async(
            &bof,
            &packed_args,
            sandbox,
            trace,
            std::time::Duration::from_secs(timeout),
            false, // CLI: use zeroed BeaconInformation by default
            async_timeout.map(std::time::Duration::from_secs),
            Some(&mut print_live_entry),
        )?
    } else {
        core::executor::execute(
            &bof,
            &packed_args,
            sandbox,
            trace,
            std::time::Duration::from_secs(timeout),
            false, // CLI: use zeroed BeaconInformation by default
        )?
    };

    // Display results
    println!("\n=== Execution Results ===");
    println!(
        "Status: {}",
        if result.success { "SUCCESS" } else { "FAILED" }
    );
    println!(
        "Execution Time: {:.2}s",
        result.execution_time.as_secs_f64()
    );

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

/// Run a BOF through an OC2 Stage1 (.s1.py) wrapper (ported from RedLoader):
/// extract the typed argument spec, pack argv exactly like OC2, resolve the
/// BOF next to the script (PE or COFF, auto-detected), execute.
#[allow(clippy::too_many_arguments)]
pub fn s1(
    script: PathBuf,
    list: bool,
    files: Vec<String>,
    x86: bool,
    sandbox: bool,
    trace: bool,
    timeout: u64,
    is_async: bool,
    async_timeout: Option<u64>,
    pack_only: bool,
    args: Vec<String>,
) -> Result<()> {
    use crate::core::s1::{self, S1ArgKind, S1Error, S1Literal};

    if !script.exists() {
        anyhow::bail!("wrapper script not found: {}", script.display());
    }
    let spec = s1::parse_wrapper(&script).map_err(|e| match e {
        S1Error::UnsupportedExpression(msg) => {
            anyhow::anyhow!("unsupported s1.py construct: {}", msg)
        }
        other => anyhow::anyhow!("failed to parse {}: {}", script.display(), other),
    })?;

    if list {
        println!("Command:          {}", spec.command);
        println!(
            "BOF binary:       {}.{}",
            spec.base_binary_name,
            if x86 { "x86.o" } else { "x64.o" }
        );
        if let Some(sub) = &spec.base_binary_path {
            println!("BOF subdirectory: {}", sub);
        }
        println!("Format string:    {}", spec.format_string());
        if !spec.file_elements.is_empty() {
            println!("File uploads:     {}", spec.file_elements.join(", "));
        }
        println!("Arguments:");
        for a in &spec.args {
            let kind = match a.kind {
                S1ArgKind::Int => "int",
                S1ArgKind::Bool => "flag",
                S1ArgKind::Str => "str",
            };
            let name = if a.flags.is_empty() {
                format!("<{}>", a.name)
            } else {
                a.flags.join("/")
            };
            let default = a
                .default
                .as_ref()
                .map(|d| match d {
                    S1Literal::Str(s) => format!("default {:?}", s),
                    S1Literal::Int(n) => format!("default {}", n),
                    S1Literal::Bool(b) => format!("default {}", b),
                })
                .unwrap_or_default();
            println!("  {:<28} {:<6} {}", name, kind, default);
        }
        return Ok(());
    }

    let script_dir = script.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let bof_path = spec.resolve_bof(&script_dir, x86);
    if !bof_path.exists() {
        anyhow::bail!(
            "BOF not found next to wrapper: {} (checked via base_binary_name)",
            bof_path.display()
        );
    }

    let mut file_map = std::collections::HashMap::new();
    for binding in &files {
        match binding.split_once('=') {
            Some((name, path)) => {
                // Typo'd element names must fail upfront with the valid
                // names listed, not deep in packing as a confusing
                // MissingFile.
                if !spec.file_elements.iter().any(|el| el == name) {
                    anyhow::bail!(
                        "unknown upload element '{}' (wrapper declares: {})",
                        name,
                        if spec.file_elements.is_empty() {
                            "<none>".to_string()
                        } else {
                            spec.file_elements.join(", ")
                        }
                    );
                }
                let bytes = std::fs::read(path)
                    .with_context(|| format!("cannot read upload '{}' at {}", name, path))?;
                file_map.insert(name.to_string(), bytes);
            }
            None => anyhow::bail!("--file expects NAME=PATH, got '{}'", binding),
        }
    }

    let arg_data = spec.pack_arguments(&args, &file_map).map_err(|e| {
        if let S1Error::MissingFile(el) = &e {
            anyhow::anyhow!("this command needs an uploaded file: --file {}=<path>", el)
        } else {
            anyhow::anyhow!("{}", e)
        }
    })?;

    println!("=== s1.py Wrapper Execution ===");
    println!("Wrapper:      {}", script.display());
    println!("Command:      {}", spec.command);
    println!("BOF:          {}", bof_path.display());
    println!("Format:       {}", spec.format_string());
    println!("s1 argv:      {:?}", args);
    println!("Argument buffer: {} bytes", arg_data.len());
    if !arg_data.is_empty() {
        println!(
            "Buffer hex:   {}",
            arg_data
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
    }
    println!();

    if pack_only {
        return Ok(());
    }

    // Load the BOF (PE or COFF, dispatched on magic) — also validates it
    // parses before we try to execute.
    let bof = core::parser::load_bof(&bof_path)?;
    println!(
        "Loaded:       {} sections, {} symbols, entry: {}",
        bof.sections.len(),
        bof.symbols.len(),
        bof.entry_point
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "<none>".to_string())
    );
    println!();

    // Execute (Windows) or stop here (other platforms).
    let result = if is_async {
        println!("--- Live Output (async) ---");
        core::executor::execute_async(
            &bof,
            &arg_data,
            sandbox,
            trace,
            std::time::Duration::from_secs(timeout),
            false,
            async_timeout.map(std::time::Duration::from_secs),
            Some(&mut print_live_entry),
        )?
    } else {
        core::executor::execute(
            &bof,
            &arg_data,
            sandbox,
            trace,
            std::time::Duration::from_secs(timeout),
            false,
        )?
    };

    println!("\n=== Execution Results ===");
    println!(
        "Status: {}",
        if result.success { "SUCCESS" } else { "FAILED" }
    );
    println!(
        "Execution Time: {:.2}s",
        result.execution_time.as_secs_f64()
    );
    if !result.success {
        if let Some(err) = &result.error {
            eprintln!("\nError: {}", err);
        }
    }
    if !result.output.is_empty() {
        println!("\n--- BOF Output ---");
        for msg in &result.output {
            println!("[{}] {}", msg.message_type, msg.content);
        }
    }
    Ok(())
}
