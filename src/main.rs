//! RedBofAnalizer - Main entry point
//! 
//! Supports both CLI and GUI modes with a shared core library.

use clap::{Parser, Subcommand};
use log::info;
use std::path::PathBuf;

mod cli;
mod gui;
mod core;

/// RedBofAnalizer - BOF Analyzer and Execution Tool
#[derive(Parser)]
#[command(name = "redbofanalyzer")]
#[command(about = "A comprehensive Beacon Object File (BOF) analyzer and execution tool", long_about = None)]
struct Args {
    /// Launch GUI mode
    #[arg(long, global = true)]
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
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info")
        ).init();
    }

    info!("RedBofAnalizer v{}", env!("CARGO_PKG_VERSION"));

    // Check if GUI mode is requested or no command provided
    if args.gui || args.command.is_none() {
        info!("Launching GUI mode");
        // Set debug mode globally for executor
        core::executor::set_debug_mode(args.debug);
        gui::run()?;
        return Ok(());
    }
    
    // Set debug mode for CLI commands too
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
            output,
        } => {
            cli::commands::analyze(file, security, disasm, apis, dependencies, lints, relocs, output, args.format)?;
        }
        Command::Execute {
            file,
            args: exec_args,
            sandbox,
            trace,
            timeout,
        } => {
            cli::commands::execute(file, exec_args, sandbox, trace, timeout)?;
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

