//! Batch testing of multiple BOFs

mod common;

use redbofanalyzer::core::parser;
use redbofanalyzer::core::executor;
use redbofanalyzer::core::analyzer;
use std::time::Duration;

#[test]
#[ignore] // Long-running test
fn test_batch_parse_all_bofs() {
    let test_dirs = vec![
        common::get_test_bof_dir("bof_template").join("examples"),
        common::get_test_bof_dir("CS-Situational-Awareness-BOF").join("SA"),
    ];
    
    let mut total = 0;
    let mut parsed = 0;
    let mut failed = Vec::new();
    
    for dir in test_dirs {
        let bofs = common::find_bof_files(&dir);
        total += bofs.len();
        
        for bof_path in bofs {
            match parser::load_bof(&bof_path) {
                Ok(bof) => {
                    assert!(!bof.sections.is_empty());
                    parsed += 1;
                }
                Err(e) => {
                    eprintln!("Failed to parse {:?}: {}", bof_path, e);
                    failed.push((bof_path, format!("{}", e)));
                }
            }
        }
    }
    
    println!("Batch parse results: {}/{} parsed successfully", parsed, total);
    
    if !failed.is_empty() {
        println!("Failed to parse {} BOFs:", failed.len());
        for (path, error) in &failed {
            println!("  {:?}: {}", path, error);
        }
    }
    
    // Should parse at least some BOFs
    if total > 0 {
        assert!(parsed > 0, "Should parse at least one BOF");
    } else {
        println!("No BOFs found for batch testing");
    }
}

#[test]
#[ignore] // Long-running test
fn test_batch_analyze_all_bofs() {
    let test_dirs = vec![
        common::get_test_bof_dir("bof_template").join("examples"),
    ];
    
    let mut total = 0;
    let mut analyzed = 0;
    let mut failed = Vec::new();
    
    for dir in test_dirs {
        let bofs = common::find_bof_files(&dir);
        total += bofs.len();
        
        for bof_path in bofs {
            match parser::load_bof(&bof_path) {
                Ok(bof) => {
                    let _report = analyzer::analyze(&bof, false, false, true, true, true, false, &[], true)
                        .expect("Should analyze BOF");
                    // Report is valid if we got here
                    analyzed += 1;
                }
                Err(e) => {
                    eprintln!("Failed to parse {:?}: {}", bof_path, e);
                    failed.push((bof_path, format!("{}", e)));
                }
            }
        }
    }
    
    println!("Batch analyze results: {}/{} analyzed successfully", analyzed, total);
    
    if !failed.is_empty() {
        println!("Failed to analyze {} BOFs:", failed.len());
        for (path, error) in &failed {
            println!("  {:?}: {}", path, error);
        }
    }
    
    if total > 0 {
        assert!(analyzed > 0, "Should analyze at least one BOF");
    } else {
        println!("No BOFs found for batch testing");
    }
}

#[test]
#[ignore] // Long-running and potentially unstable test
fn test_batch_execute_simple_bofs() {
    let test_dirs = vec![
        common::get_test_bof_dir("bof_template").join("examples"),
    ];
    
    let mut total = 0;
    let mut executed = 0;
    let mut succeeded = 0;
    let mut failed = Vec::new();
    
    for dir in test_dirs {
        let bofs = common::find_bof_files(&dir);
        total += bofs.len();
        
        for bof_path in bofs {
            match parser::load_bof(&bof_path) {
                Ok(bof) => {
                    total += 1;
                    match executor::execute(
                        &bof,
                        &[],
                        false, // sandbox
                        false, // trace
                        Duration::from_secs(5), // Short timeout for batch testing
                    ) {
                        Ok(exec_result) => {
                            executed += 1;
                            if exec_result.success {
                                succeeded += 1;
                            } else {
                                failed.push((bof_path, exec_result.error.unwrap_or_default()));
                            }
                        }
                        Err(e) => {
                            failed.push((bof_path, format!("{}", e)));
                        }
                    }
                }
                Err(e) => {
                    failed.push((bof_path, format!("Parse error: {}", e)));
                }
            }
        }
    }
    
    println!("Batch execute results: {}/{} executed, {}/{} succeeded", 
             executed, total, succeeded, executed);
    
    if !failed.is_empty() {
        println!("Failed to execute {} BOFs:", failed.len());
        for (path, error) in failed.iter().take(10) {
            println!("  {:?}: {}", path, error);
        }
        if failed.len() > 10 {
            println!("  ... and {} more", failed.len() - 10);
        }
    }
    
    // Don't assert - execution failures are expected for some BOFs
    // Just report the results
}

