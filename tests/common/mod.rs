//! Common test utilities and helpers

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Find BOF files in a directory
#[allow(dead_code)] // Used by integration tests
pub fn find_bof_files(dir: &Path) -> Vec<PathBuf> {
    let mut bofs = Vec::new();
    
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if ext_str == "o" || ext_str == "obj" {
                    bofs.push(path.to_path_buf());
                }
            }
        }
    }
    
    bofs.sort();
    bofs
}

/// Get the test BOFs directory
#[allow(dead_code)] // Used by integration tests
pub fn get_test_bofs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("src")
}

/// Get a specific test BOF directory
#[allow(dead_code)] // Used by integration tests
pub fn get_test_bof_dir(name: &str) -> PathBuf {
    get_test_bofs_dir().join(name)
}

/// Check if a BOF file exists
#[allow(dead_code)]
pub fn bof_exists(path: &Path) -> bool {
    path.exists() && path.is_file()
}

/// Assert that a BOF execution was successful
#[allow(dead_code)]
pub fn assert_execution_success(result: &redbofanalyzer::core::models::report::ExecutionResult) {
    assert!(result.success, "BOF execution should succeed. Error: {:?}", result.error);
    assert!(result.error.is_none(), "BOF execution should not have errors: {:?}", result.error);
}

/// Assert that a BOF execution produced output
#[allow(dead_code)]
pub fn assert_has_output(result: &redbofanalyzer::core::models::report::ExecutionResult) {
    assert!(!result.output.is_empty(), "BOF execution should produce output");
}

/// Assert that a BOF execution produced specific output
#[allow(dead_code)]
pub fn assert_output_contains(result: &redbofanalyzer::core::models::report::ExecutionResult, text: &str) {
    let all_output: String = result.output.iter()
        .map(|msg| msg.content.as_str())
        .collect::<Vec<_>>()
        .concat();
    assert!(
        all_output.contains(text),
        "Expected output to contain '{}', but got: {}",
        text,
        all_output
    );
}

