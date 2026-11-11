//! RedBofAnalizer - Main entry point
//!
//! Supports both CLI and GUI modes with a shared core library.

use clap::{Parser, Subcommand};
use log::info;
use std::path::PathBuf;

mod cli;
mod core;
#[cfg(windows)]
mod gui;

/// RedBofAnalizer - BOF Analyzer and Execution Tool
#[derive(Parser)]
#[command(name = "redbofanalyzer")]
#[command(about = "A comprehensive Beacon Object File (BOF) analyzer and execution tool", long_about = None)]
struct Args {
    /// Run in CLI mode (default: GUI mode)
    #[arg(long, global = true)]
    cli: bool,

    /// Launch GUI mode (deprecated: GUI is now the default)
    #[arg(long, global = true, hide = true)]
    gui: bool,

    /// Verbose output
    #[arg(long, short, global = true)]
    verbose: bool,

    /// Quiet mode (errors only)
    #[arg(long, short, global = true)]
    quiet: bool,

    /// Debug mode - show detailed executor output
    #[arg(long, global = true)]
    debug: bool,

    /// Output format
    #[arg(long, global = true, value_enum, default_value = "text")]
    format: cli::OutputFormat,

    /// Command to execute
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a BOF file
    Analyze {
        /// BOF file to analyze
        file: PathBuf,
        /// Security assessment only
        #[arg(long)]
        security: bool,
        /// Include disassembly
        #[arg(long)]
        disasm: bool,
        /// Show API usage
        #[arg(long)]
        apis: bool,
        /// Show dependencies
        #[arg(long)]
        dependencies: bool,
        /// Show lint findings
        #[arg(long)]
        lints: bool,
        /// Show relocation information
        #[arg(long)]
        relocs: bool,
        /// Enhanced OpSec analysis (API categorization, risky combinations)
        #[arg(long)]
        opsec: bool,
        /// Compatibility analysis (CS version requirements)
        #[arg(long)]
        compatibility: bool,
        /// Calling convention analysis
        #[arg(long)]
        calling_convention: bool,
        /// YARA rule files or directories to load (can be specified multiple times)
        #[arg(long)]
        yara_rules: Vec<PathBuf>,
        /// Write report to file
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Execute a BOF file
    Execute {
        /// BOF file to execute
        file: PathBuf,
        /// Arguments (e.g., "z:string i:123")
        #[arg(long)]
        args: Option<String>,
        /// Run in sandbox mode
        #[arg(long)]
        sandbox: bool,
        /// Verbose API logging
        #[arg(long)]
        trace: bool,
        /// Execution timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,
        /// Run asynchronously: worker thread with a private output sink and
        /// an OC2 stop-event contract (BeaconGetStopJobEvent/BeaconWakeup)
        #[arg(long, name = "async")]
        is_async: bool,
        /// With --async: signal the stop event after N seconds (a
        /// well-behaved BOF observes it and returns promptly)
        #[arg(long, requires = "async")]
        async_timeout: Option<u64>,
    },
    /// Run a BOF through an OC2 Stage1 (.s1.py) wrapper: extracts the typed
    /// argument spec, packs argv exactly like OC2, finds the BOF next to
    /// the script (PE or COFF) and executes it
    S1 {
        /// The .s1.py wrapper script
        script: PathBuf,
        /// Show the extracted spec (command, format string, args) and exit
        #[arg(long)]
        list: bool,
        /// Provide an uploaded file for a get_file_by_name element (NAME=PATH)
        #[arg(long = "file", value_name = "NAME=PATH")]
        files: Vec<String>,
        /// Use the x86 variant of the BOF
        #[arg(long)]
        x86: bool,
        /// Run in sandbox mode
        #[arg(long)]
        sandbox: bool,
        /// Verbose API logging
        #[arg(long)]
        trace: bool,
        /// Execution timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,
        /// Run asynchronously (per-task output sink, OC2 stop-event contract)
        #[arg(long, name = "async")]
        is_async: bool,
        /// With --async: signal the stop event after N seconds
        #[arg(long, requires = "async")]
        async_timeout: Option<u64>,
        /// Parse and pack only: print the packed argument buffer and exit
        /// (also the automatic behavior on non-Windows builds)
        #[arg(long)]
        pack_only: bool,
        /// Arguments for the s1.py argument parser
        args: Vec<String>,
    },
    /// Test all BOFs in directory
    Test {
        /// Directory containing BOF files
        directory: PathBuf,
        /// Report format
        #[arg(long, value_enum, default_value = "text")]
        report: cli::OutputFormat,
        /// Filter BOFs (glob pattern)
        #[arg(long)]
        filter: Option<String>,
        /// Write report to file
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Continue on errors
        #[arg(long)]
        continue_on_error: bool,
    },
    /// Validate BOF without execution
    Validate {
        /// BOF file to validate
        file: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    // Respect RUST_LOG if set, otherwise use command-line flags
    if args.quiet {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Error)
            .init();
    } else if args.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        // Use RUST_LOG if set, otherwise default to Info
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    info!("RedBofAnalizer v{}", env!("CARGO_PKG_VERSION"));

    // Determine mode: CLI if --cli flag is set or a command is provided, otherwise GUI (default)
    let use_cli = args.cli || args.command.is_some();

    if !use_cli {
        // GUI mode (default)
        info!("Launching GUI mode");
        // Set debug mode globally for executor
        core::executor::set_debug_mode(args.debug);
        #[cfg(windows)]
        {
            gui::run()?;
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("GUI mode is only supported on Windows. Use --cli with a command (analyze, validate, etc.).");
        }
    }

    // CLI mode: require a command if --cli is explicitly set
    if args.cli && args.command.is_none() {
        eprintln!("Error: --cli flag requires a command to execute");
        eprintln!();
        eprintln!("Usage: redbofanalyzer --cli <COMMAND>");
        eprintln!();
        eprintln!("Available commands:");
        eprintln!("  analyze    Analyze a BOF file");
        eprintln!("  execute    Execute a BOF file");
        eprintln!("  test       Test all BOFs in directory");
        eprintln!("  validate   Validate BOF without execution");
        eprintln!();
        eprintln!("For more information, try 'redbofanalyzer --cli --help'");
        std::process::exit(1);
    }

    // Set debug mode for CLI commands
    core::executor::set_debug_mode(args.debug);

    // Execute CLI command
    match args.command.unwrap() {
        Command::Analyze {
            file,
            security,
            disasm,
            apis,
            dependencies,
            lints,
            relocs,
            opsec,
            compatibility,
            calling_convention,
            yara_rules,
            output,
        } => {
            // Enhanced OpSec and compatibility analysis are always performed when security is enabled
            // or when explicitly requested
            let enhanced_analysis = security || opsec || compatibility || calling_convention;

            // Convert YARA rule paths to YaraRuleSource and validate they exist
            use crate::core::analyzer::YaraRuleSource;
            let yara_rules_count = yara_rules.len();
            let mut yara_rule_sources = Vec::new();
            for path in &yara_rules {
                if !path.exists() {
                    eprintln!("Warning: YARA rule path does not exist: {:?}", path);
                    continue;
                }
                if path.is_dir() {
                    log::info!("Loading YARA rules from directory: {:?}", path);
                    yara_rule_sources.push(YaraRuleSource::Directory(path.clone()));
                } else if path.is_file() {
                    log::info!("Loading YARA rule file: {:?}", path);
                    yara_rule_sources.push(YaraRuleSource::File(path.clone()));
                } else {
                    eprintln!(
                        "Warning: YARA rule path is neither a file nor directory: {:?}",
                        path
                    );
                }
            }

            if yara_rule_sources.is_empty() && yara_rules_count > 0 {
                eprintln!("Warning: No valid YARA rule paths found. Using default rules only.");
            }

            cli::commands::analyze(
                file,
                security,
                disasm,
                apis,
                dependencies,
                lints,
                relocs,
                enhanced_analysis,
                output,
                args.format,
                &yara_rule_sources,
            )?;
        }
        Command::Execute {
            file,
            args: exec_args,
            sandbox,
            trace,
            timeout,
            is_async,
            async_timeout,
        } => {
            cli::commands::execute(
                file,
                exec_args,
                sandbox,
                trace,
                timeout,
                is_async,
                async_timeout,
            )?;
        }
        Command::S1 {
            script,
            list,
            files,
            x86,
            sandbox,
            trace,
            timeout,
            is_async,
            async_timeout,
            pack_only,
            args,
        } => {
            cli::commands::s1(
                script,
                list,
                files,
                x86,
                sandbox,
                trace,
                timeout,
                is_async,
                async_timeout,
                pack_only,
                args,
            )?;
        }
        Command::Test {
            directory,
            report,
            filter,
            output,
            continue_on_error,
        } => {
            cli::commands::test(directory, report, filter, output, continue_on_error)?;
        }
        Command::Validate { file } => {
            cli::commands::validate(file)?;
        }
    }

    Ok(())
}
