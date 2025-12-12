//! Static analysis module

use crate::core::models::bof::BofFile;
use crate::core::models::report::{
    AnalysisReport, ValidationResult, Overview, SectionInfo, SymbolInfo,
    ApiUsage, Win32Api, SecurityAssessment, RiskLevel, OpsecAnalysis,
    Dependencies, FunctionDependency,
};
use anyhow::Result;
use std::fs;

/// Analyze a BOF file
pub fn analyze(
    bof: &BofFile,
    _security: bool,
    _disasm: bool,
    apis: bool,
    dependencies: bool,
    _lints: bool,
) -> Result<AnalysisReport> {
    // Get file size
    let file_size = fs::metadata(&bof.path)?.len();
    
    // Build overview
    let overview = Overview {
        file_size,
        entry_point_found: bof.entry_point.is_some(),
        architecture: format!("{:?}", bof.header.machine),
    };
    
    // Build section info
    let sections: Vec<SectionInfo> = bof.sections.iter().map(|s| {
        SectionInfo {
            name: s.name.clone(),
            size: s.raw_size,
            entropy: s.entropy,
            flags: format_section_flags(s.characteristics),
        }
    }).collect();
    
    // Build symbol info
    let symbols: Vec<SymbolInfo> = bof.symbols.iter().map(|s| {
        SymbolInfo {
            name: s.name.clone(),
            r#type: format!("{:?}", s.symbol_type),
            section: s.section.and_then(|idx| {
                bof.sections.get(idx).map(|sec| sec.name.clone())
            }),
            address: s.value,
        }
    }).collect();
    
    // Extract API usage
    let (beacon_apis, win32_apis) = if apis || dependencies {
        extract_api_usage(&bof.imports)
    } else {
        (vec![], vec![])
    };
    
    // Build dependencies
    let deps = if dependencies {
        build_dependencies(&bof.imports)
    } else {
        Dependencies {
            dlls: vec![],
            functions: vec![],
        }
    };
    
    // Basic security assessment
    let security = SecurityAssessment {
        risk_level: assess_risk_level(&bof),
        capabilities: vec![], // TODO: Phase 2.1.4
        opsec_score: 100, // TODO: Phase 6.1
        opsec_analysis: OpsecAnalysis {
            risky_apis: vec![],
            suspicious_patterns: vec![],
            direct_syscalls: false,
        },
    };
    
    Ok(AnalysisReport {
        bof: bof.clone(),
        overview,
        sections,
        symbols,
        apis: ApiUsage {
            beacon_apis,
            win32_apis,
        },
        security,
        lints: vec![], // TODO: Phase 2.2
        dependencies: deps,
    })
}

/// Format section flags as string
fn format_section_flags(characteristics: u32) -> String {
    let mut flags = Vec::new();
    
    if characteristics & 0x00000020 != 0 { flags.push("CODE"); }
    if characteristics & 0x00000040 != 0 { flags.push("INIT_DATA"); }
    if characteristics & 0x00000080 != 0 { flags.push("UNINIT_DATA"); }
    if characteristics & 0x20000000 != 0 { flags.push("EXECUTE"); }
    if characteristics & 0x40000000 != 0 { flags.push("READ"); }
    if characteristics & 0x80000000 != 0 { flags.push("WRITE"); }
    
    if flags.is_empty() {
        "NONE".to_string()
    } else {
        flags.join("|")
    }
}

/// Extract API usage from imports
fn extract_api_usage(imports: &[crate::core::models::bof::Import]) -> (Vec<String>, Vec<Win32Api>) {
    let mut beacon_apis = Vec::new();
    let mut win32_apis = Vec::new();
    
    for import in imports {
        if import.library == "Beacon" {
            beacon_apis.push(import.function.clone());
        } else {
            win32_apis.push(Win32Api {
                dll: import.library.clone(),
                function: import.function.clone(),
            });
        }
    }
    
    (beacon_apis, win32_apis)
}

/// Build dependencies structure
fn build_dependencies(imports: &[crate::core::models::bof::Import]) -> Dependencies {
    let mut dlls = std::collections::HashSet::new();
    let mut functions = Vec::new();
    
    for import in imports {
        if import.library != "Beacon" {
            dlls.insert(import.library.clone());
            functions.push(FunctionDependency {
                dll: import.library.clone(),
                function: import.function.clone(),
            });
        }
    }
    
    Dependencies {
        dlls: dlls.into_iter().collect(),
        functions,
    }
}

/// Assess risk level based on BOF characteristics
fn assess_risk_level(bof: &BofFile) -> RiskLevel {
    // Basic risk assessment
    // TODO: Enhance in Phase 2.1.4
    
    // Check for suspicious imports
    let has_process_ops = bof.imports.iter().any(|imp| {
        imp.function.contains("Process") || 
        imp.function.contains("Inject") ||
        imp.function.contains("Spawn")
    });
    
    let has_token_ops = bof.imports.iter().any(|imp| {
        imp.function.contains("Token") ||
        imp.function.contains("Impersonate")
    });
    
    if has_process_ops || has_token_ops {
        RiskLevel::High
    } else if !bof.imports.is_empty() {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

/// Validate a BOF file
pub fn validate(bof: &BofFile) -> Result<ValidationResult> {
    let mut errors = Vec::new();

    // Check for entry point
    if bof.entry_point.is_none() {
        errors.push("Missing entry point 'go' function".to_string());
    } else {
        // Validate entry point signature (should be void go(char*, int))
        // This is a basic check - full signature validation would require disassembly
        if let Some(entry) = &bof.entry_point {
            if entry.name != "go" {
                errors.push(format!("Entry point has unexpected name: '{}' (expected 'go')", entry.name));
            }
        }
    }

    // Check architecture
    match bof.header.machine {
        crate::core::models::bof::MachineType::Unknown(val) => {
            errors.push(format!("Unknown or unsupported architecture: 0x{:04X}", val));
        }
        _ => {}
    }

    // Check for required sections
    let has_text = bof.sections.iter().any(|s| s.name == ".text");
    if !has_text {
        errors.push("Missing .text section (code section)".to_string());
    }

    // Check for symbols
    if bof.symbols.is_empty() {
        errors.push("No symbols found in BOF file".to_string());
    }

    // Check for external symbols (imports) - BOFs typically need at least Beacon APIs
    let has_imports = !bof.imports.is_empty();
    if !has_imports {
        errors.push("No external symbols (imports) found - BOF may not be properly linked".to_string());
    }

    Ok(ValidationResult {
        is_valid: errors.is_empty(),
        errors,
    })
}

