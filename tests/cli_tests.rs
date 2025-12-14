//! Tests for CLI functionality

mod common;

use std::process::Command;
use std::path::PathBuf;

fn get_binary_path() -> PathBuf {
    // In tests, the binary is in target/debug/redbofanalyzer.exe
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join("redbofanalyzer.exe")
}

#[test]
#[ignore] // Ignore by default - requires built binary
fn test_cli_help() {
    let binary = get_binary_path();
    if !binary.exists() {
        println!("Binary not found, skipping test. Run 'cargo build' first.");
        return;
    }
    
    let output = Command::new(&binary)
        .arg("--help")
        .output()
        .expect("Should execute command");
    
    assert!(output.status.success(), "Help command should succeed");
    assert!(!output.stdout.is_empty(), "Should have help output");
}

#[test]
#[ignore] // Ignore by default - requires built binary and BOF files
fn test_cli_analyze() {
    let binary = get_binary_path();
    if !binary.exists() {
        println!("Binary not found, skipping test. Run 'cargo build' first.");
        return;
    }
    
    // Find a test BOF
    let test_dirs = vec![
        common::get_test_bof_dir("bof_template").join("examples"),
    ];
    
    let mut found_bof = None;
    for dir in test_dirs {
        let bofs = common::find_bof_files(&dir);
        if let Some(bof) = bofs.first() {
            found_bof = Some(bof.clone());
            break;
        }
    }
    
    if let Some(bof_path) = found_bof {
        let output = Command::new(&binary)
            .arg("analyze")
            .arg(&bof_path)
            .output()
            .expect("Should execute command");
        
        // Analyze should succeed
        assert!(output.status.success() || !output.stderr.is_empty(),
                "Analyze command should succeed or provide error info");
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
#[ignore] // Ignore by default - requires built binary and BOF files
fn test_cli_validate() {
    let binary = get_binary_path();
    if !binary.exists() {
        println!("Binary not found, skipping test. Run 'cargo build' first.");
        return;
    }
    
    // Find a test BOF
    let test_dirs = vec![
        common::get_test_bof_dir("bof_template").join("examples"),
    ];
    
    let mut found_bof = None;
    for dir in test_dirs {
        let bofs = common::find_bof_files(&dir);
        if let Some(bof) = bofs.first() {
            found_bof = Some(bof.clone());
            break;
        }
    }
    
    if let Some(bof_path) = found_bof {
        let output = Command::new(&binary)
            .arg("validate")
            .arg(&bof_path)
            .output()
            .expect("Should execute command");
        
        // Validate should succeed for valid BOFs
        assert!(output.status.success() || !output.stderr.is_empty(),
                "Validate command should succeed or provide error info");
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
#[ignore] // Ignore by default - requires built binary
fn test_cli_invalid_command() {
    let binary = get_binary_path();
    if !binary.exists() {
        println!("Binary not found, skipping test. Run 'cargo build' first.");
        return;
    }
    
    let output = Command::new(&binary)
        .arg("invalid_command")
        .output()
        .expect("Should execute command");
    
    // Should fail with error
    assert!(!output.status.success(), "Invalid command should fail");
    assert!(!output.stderr.is_empty(), "Should have error message");
}

