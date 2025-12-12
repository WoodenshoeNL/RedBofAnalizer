//! Utility functions

pub mod entropy;
pub mod disasm;

use std::path::PathBuf;
use anyhow::Result;
use walkdir::WalkDir;

/// Find all BOF files in a directory
pub fn find_bof_files(directory: &PathBuf, filter: Option<&str>) -> Result<Vec<PathBuf>> {
    let mut bof_files = Vec::new();

    for entry in WalkDir::new(directory) {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let extension = path.extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            // BOF files typically have .o or .obj extension
            if extension == "o" || extension == "obj" {
                if let Some(pattern) = filter {
                    if !path.to_string_lossy().contains(pattern) {
                        continue;
                    }
                }
                bof_files.push(path.to_path_buf());
            }
        }
    }

    Ok(bof_files)
}

