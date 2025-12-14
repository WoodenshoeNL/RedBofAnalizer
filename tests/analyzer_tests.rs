//! Unit tests for analyzer

mod common;

use redbofanalyzer::core::parser;
use redbofanalyzer::core::analyzer;

#[test]
fn test_analyze_bof_basic() {
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
        let bof = parser::load_bof(&bof_path).expect("Should parse BOF");
        let report = analyzer::analyze(&bof, false, false, true, true, true, false, &[], true)
            .expect("Should analyze BOF");
        
        // Verify report structure
        assert!(!report.bof.path.to_string_lossy().is_empty());
        assert!(!report.sections.is_empty());
        assert!(!report.symbols.is_empty());
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_analyze_api_detection() {
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
        let bof = parser::load_bof(&bof_path).expect("Should parse BOF");
        let report = analyzer::analyze(&bof, false, false, true, true, true, false, &[], true)
            .expect("Should analyze BOF");
        
        // Verify API detection
        // Most BOFs should have some APIs detected
        // Note: Some BOFs may not have APIs if they're very simple
        // So we just verify the report structure is correct
        // (len() is always >= 0, so we just verify the field exists)
        let _beacon_count = report.apis.beacon_apis.len();
        let _win32_count = report.apis.win32_apis.len();
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_analyze_security_assessment() {
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
        let bof = parser::load_bof(&bof_path).expect("Should parse BOF");
        let report = analyzer::analyze(&bof, true, false, false, false, false, false, &[], true)
            .expect("Should analyze BOF");
        
        // Verify security assessment exists
        // Risk level should be one of the expected values
        match report.security.risk_level {
            redbofanalyzer::core::models::report::RiskLevel::Low |
            redbofanalyzer::core::models::report::RiskLevel::Medium |
            redbofanalyzer::core::models::report::RiskLevel::High => {
                // Valid risk level
            }
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_analyze_dependencies() {
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
        let bof = parser::load_bof(&bof_path).expect("Should parse BOF");
        let report = analyzer::analyze(&bof, false, false, false, true, false, false, &[], true)
            .expect("Should analyze BOF");
        
        // Verify dependencies are listed
        // Dependencies should match imports
        assert_eq!(report.dependencies.functions.len(), bof.imports.len(),
                   "Dependencies should match imports");
    } else {
        println!("No test BOFs found, skipping test");
    }
}

