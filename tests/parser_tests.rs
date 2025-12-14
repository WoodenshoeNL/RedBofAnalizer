//! Unit tests for COFF parser

mod common;

use redbofanalyzer::core::parser;
use std::path::PathBuf;

#[test]
fn test_parse_coff_header() {
    // This test requires a real BOF file
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
        
        // Verify header information
        match bof.header.machine {
            redbofanalyzer::core::models::bof::MachineType::X64 | 
            redbofanalyzer::core::models::bof::MachineType::X86 => {
                // Valid machine type
            }
            _ => {
                panic!("Should be x64 or x86, got {:?}", bof.header.machine);
            }
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_parse_sections() {
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
        
        // Verify sections
        assert!(!bof.sections.is_empty(), "Should have sections");
        
        // Check for common sections
        let section_names: Vec<&str> = bof.sections.iter()
            .map(|s| s.name.as_str())
            .collect();
        
        // Should have at least one section
        assert!(!section_names.is_empty());
        
        // Verify section properties
        for section in &bof.sections {
            assert!(!section.name.is_empty(), "Section should have a name");
            assert!(section.raw_size > 0 || section.virtual_size > 0,
                    "Section should have size");
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_parse_symbols() {
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
        
        // Verify symbols
        assert!(!bof.symbols.is_empty(), "Should have symbols");
        
        // Check for entry point
        let has_entry = bof.entry_point.is_some() || 
                       bof.symbols.iter().any(|s| s.name == "go");
        assert!(has_entry, "Should have entry point");
        
        // Verify symbol properties
        for symbol in &bof.symbols {
            assert!(!symbol.name.is_empty(), "Symbol should have a name");
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_parse_imports() {
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
        
        // Verify imports (may be empty for some BOFs)
        for import in &bof.imports {
            assert!(!import.function.is_empty(), "Import should have function name");
            assert!(!import.symbol_name.is_empty(), "Import should have symbol name");
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_parse_relocations() {
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
        
        // Relocations may or may not be present
        for reloc in &bof.relocations {
            assert!(reloc.section_index < bof.sections.len(),
                    "Relocation should reference valid section");
        }
    } else {
        println!("No test BOFs found, skipping test");
    }
}

#[test]
fn test_invalid_file() {
    // Test with a non-existent file
    let invalid_path = PathBuf::from("nonexistent_file.o");
    let result = parser::load_bof(&invalid_path);
    assert!(result.is_err(), "Should fail to parse non-existent file");
}

#[test]
fn test_empty_file() {
    use tempfile::NamedTempFile;
    use std::io::Write;
    
    // Create a temporary empty file
    let mut temp_file = NamedTempFile::new().expect("Should create temp file");
    temp_file.write_all(b"").expect("Should write to temp file");
    
    let result = parser::load_bof(&temp_file.path().to_path_buf());
    assert!(result.is_err(), "Should fail to parse empty file");
}

