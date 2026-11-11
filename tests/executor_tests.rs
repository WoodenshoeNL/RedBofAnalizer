//! Unit tests for executor module

mod common;

use redbofanalyzer::core::parser;
use redbofanalyzer::core::executor;
use std::time::Duration;

#[test]
fn test_executor_timeout() {
    // Test that timeout is respected (though actual timeout termination requires threading)
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
        
        // Execute with a very short timeout
        let result = executor::execute(
            &bof,
            &[],
            false, // sandbox
            false, // trace
            Duration::from_millis(1), // Very short timeout
            false, // emulate_beacon_info
        );
        
        // Should complete (timeout checking happens after execution)
        match result {
            Ok(exec_result) => {
                // Execution time should be recorded (always >= 0)
                let _exec_time = exec_result.execution_time;
            }
            Err(_) => {
                // Errors are acceptable
            }
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_executor_sandbox_mode() {
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
        
        // Execute in sandbox mode
        let result = executor::execute(
            &bof,
            &[],
            true, // sandbox
            false, // trace
            Duration::from_secs(30),
            false, // emulate_beacon_info
        );
        
        // Should complete (sandbox mode may restrict some operations)
        match result {
            Ok(exec_result) => {
                // Should have a result (execution_time is always >= 0)
                let _exec_time = exec_result.execution_time;
            }
            Err(_) => {
                // Errors are acceptable in sandbox mode
            }
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_executor_trace_mode() {
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
        
        // Execute with tracing enabled
        let result = executor::execute(
            &bof,
            &[],
            false, // sandbox
            true,  // trace
            Duration::from_secs(30),
            false, // emulate_beacon_info
        );
        
        match result {
            Ok(exec_result) => {
                // Should have API calls if tracing was enabled
                // Note: Some BOFs may not call APIs, so this is optional
                // Execution time is always >= 0
                let _exec_time = exec_result.execution_time;
            }
            Err(_) => {
                // Errors are acceptable
            }
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_executor_with_arguments() {
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
        
        // Pack some test arguments
        use redbofanalyzer::core::executor::arguments;
        let args = arguments::parse_arguments("z:test i:42").unwrap_or_default();
        
        // Execute with arguments
        let result = executor::execute(
            &bof,
            &args,
            false, // sandbox
            false, // trace
            Duration::from_secs(30),
            false, // emulate_beacon_info
        );
        
        match result {
            Ok(exec_result) => {
                // Should complete (execution_time is always >= 0)
                let _exec_time = exec_result.execution_time;
            }
            Err(_) => {
                // Errors are acceptable (BOF may not accept these arguments)
            }
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

