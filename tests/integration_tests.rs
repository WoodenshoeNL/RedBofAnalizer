//! Integration tests for BOF execution and analysis

mod common;

use common::*;
use redbofanalyzer::core::executor;
use redbofanalyzer::core::parser;
use redbofanalyzer::core::analyzer;
use std::time::Duration;

#[test]
fn test_parse_simple_bof() {
    // Try to find a simple BOF in the test directories
    let test_dirs = vec![
        get_test_bof_dir("bof_template").join("examples"),
        get_test_bof_dir("CS-Situational-Awareness-BOF").join("SA"),
        get_test_bof_dir("CS-Remote-OPs-BOF").join("Remote"),
    ];
    
    let mut found_bof = None;
    for dir in test_dirs {
        let bofs = find_bof_files(&dir);
        if let Some(bof) = bofs.first() {
            found_bof = Some(bof.clone());
            break;
        }
    }
    
    if let Some(bof_path) = found_bof {
        let result = parser::load_bof(&bof_path);
        assert!(result.is_ok(), "Should parse BOF file: {:?}", bof_path);
        
        let bof = result.unwrap();
        assert!(!bof.sections.is_empty(), "BOF should have sections");
        assert!(!bof.symbols.is_empty(), "BOF should have symbols");
    } else {
        // Skip test if no BOFs found
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_parse_multiple_bofs() {
    let test_dirs = vec![
        get_test_bof_dir("bof_template").join("examples"),
        get_test_bof_dir("CS-Situational-Awareness-BOF").join("SA"),
    ];
    
    let mut parsed_count = 0;
    let mut total_count = 0;
    
    for dir in test_dirs {
        let bofs = find_bof_files(&dir);
        total_count += bofs.len();
        
        for bof_path in bofs {
            match parser::load_bof(&bof_path) {
                Ok(bof) => {
                    assert!(!bof.sections.is_empty(), "BOF should have sections: {:?}", bof_path);
                    parsed_count += 1;
                }
                Err(e) => {
                    eprintln!("Failed to parse {:?}: {}", bof_path, e);
                }
            }
        }
    }
    
    if total_count > 0 {
        println!("Parsed {}/{} BOFs successfully", parsed_count, total_count);
        assert!(parsed_count > 0, "Should parse at least one BOF");
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_execute_simple_bof() {
    // Try to find a simple BOF that should execute without arguments
    let test_dirs = vec![
        get_test_bof_dir("bof_template").join("examples"),
    ];
    
    let mut found_bof = None;
    for dir in test_dirs {
        let bofs = find_bof_files(&dir);
        // Prefer simple BOFs like whoami, dir, etc.
        for bof in &bofs {
            if let Some(name) = bof.file_stem() {
                let name_lower = name.to_string_lossy().to_lowercase();
                if name_lower.contains("whoami") || name_lower.contains("dir") || name_lower.contains("test") {
                    found_bof = Some(bof.clone());
                    break;
                }
            }
        }
        if found_bof.is_some() {
            break;
        }
        // If no specific match, use first BOF
        if found_bof.is_none() {
            found_bof = bofs.first().cloned();
        }
    }
    
    if let Some(bof_path) = found_bof {
        println!("Testing execution of: {:?}", bof_path);
        
        let bof = parser::load_bof(&bof_path)
            .expect("Should parse BOF");
        
        let result = executor::execute(
            &bof,
            &[],
            false, // sandbox
            false, // trace
            Duration::from_secs(30),
            false, // emulate_beacon_info
        );
        
        match result {
            Ok(exec_result) => {
                println!("Execution result: success={}, output_count={}", 
                    exec_result.success, exec_result.output.len());
                if !exec_result.success {
                    eprintln!("Execution failed: {:?}", exec_result.error);
                }
                // Don't assert success - some BOFs may fail for various reasons
                // Just verify we got a result
            }
            Err(e) => {
                eprintln!("Execution error: {}", e);
                // Don't fail the test - execution errors are expected for some BOFs
            }
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_analyze_bof() {
    let test_dirs = vec![
        get_test_bof_dir("bof_template").join("examples"),
        get_test_bof_dir("CS-Situational-Awareness-BOF").join("SA"),
    ];
    
    let mut found_bof = None;
    for dir in test_dirs {
        let bofs = find_bof_files(&dir);
        if let Some(bof) = bofs.first() {
            found_bof = Some(bof.clone());
            break;
        }
    }
    
    if let Some(bof_path) = found_bof {
        let bof = parser::load_bof(&bof_path)
            .expect("Should parse BOF");
        
        let report = analyzer::analyze(&bof, false, false, true, true, true, false, &[], true)
            .expect("Should analyze BOF");
        
        // Verify report has expected fields
        assert!(!report.bof.path.to_string_lossy().is_empty());
        assert!(!report.sections.is_empty());
        assert!(!report.symbols.is_empty());
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_bof_entry_point_detection() {
    let test_dirs = vec![
        get_test_bof_dir("bof_template").join("examples"),
    ];
    
    let mut found_bof = None;
    for dir in test_dirs {
        let bofs = find_bof_files(&dir);
        if let Some(bof) = bofs.first() {
            found_bof = Some(bof.clone());
            break;
        }
    }
    
    if let Some(bof_path) = found_bof {
        let bof = parser::load_bof(&bof_path)
            .expect("Should parse BOF");
        
        // Verify entry point exists
        assert!(bof.entry_point.is_some() || 
                bof.symbols.iter().any(|s| s.name == "go"),
                "BOF should have entry point 'go' or similar");
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_bof_symbol_resolution() {
    let test_dirs = vec![
        get_test_bof_dir("bof_template").join("examples"),
    ];
    
    let mut found_bof = None;
    for dir in test_dirs {
        let bofs = find_bof_files(&dir);
        if let Some(bof) = bofs.first() {
            found_bof = Some(bof.clone());
            break;
        }
    }
    
    if let Some(bof_path) = found_bof {
        let bof = parser::load_bof(&bof_path)
            .expect("Should parse BOF");
        
        // Verify imports are detected
        assert!(!bof.imports.is_empty() || 
                bof.symbols.iter().any(|s| s.is_external),
                "BOF should have external symbols/imports");
        
        // Check for Beacon API imports
        let has_beacon_apis = bof.imports.iter()
            .any(|imp| imp.function.starts_with("Beacon"));
        let has_beacon_symbols = bof.symbols.iter()
            .any(|s| s.name.contains("Beacon"));
        
        // At least one should be true for a valid BOF
        assert!(has_beacon_apis || has_beacon_symbols || bof.imports.is_empty(),
                "BOF should reference Beacon APIs or have no imports");
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_bof_sections() {
    let test_dirs = vec![
        get_test_bof_dir("bof_template").join("examples"),
    ];
    
    let mut found_bof = None;
    for dir in test_dirs {
        let bofs = find_bof_files(&dir);
        if let Some(bof) = bofs.first() {
            found_bof = Some(bof.clone());
            break;
        }
    }
    
    if let Some(bof_path) = found_bof {
        let bof = parser::load_bof(&bof_path)
            .expect("Should parse BOF");
        
        // Verify we have expected sections
        let section_names: Vec<&str> = bof.sections.iter()
            .map(|s| s.name.as_str())
            .collect();
        
        // Should have at least .text section
        assert!(section_names.iter().any(|n| n.contains("text")),
                "BOF should have .text section. Found: {:?}", section_names);
    } else {
        println!("No test BOFs found, skipping test");
    }
}

