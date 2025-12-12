//! Symbol table parsing

use crate::core::models::bof::{Symbol, SymbolType, Import};
use anyhow::Result;
use object::{Object, ObjectSymbol, ObjectSection};

/// Parse all symbols
pub fn parse_symbols(obj: &object::File) -> Result<Vec<Symbol>> {
    let mut symbols = Vec::new();

    for symbol in obj.symbols() {
        let name = symbol.name().unwrap_or("<unknown>").to_string();
        let value = symbol.address();
        // COFF section numbers are 1-based (1 = first section, 0 = undefined)
        // Convert to 0-based index for our section_mappings array
        let section_index = symbol.section().index().map(|idx| {
            if idx.0 > 0 { idx.0 - 1 } else { idx.0 }
        });
        
        // Get the original COFF symbol index
        let coff_index = symbol.index().0;
        
        // Determine symbol type
        let symbol_type = if symbol.is_definition() {
            // Try to infer function vs data based on section
            match symbol.section() {
                object::SymbolSection::Section(section_index) => {
                    // Check if symbol is in .text section (typically functions)
                    if let Ok(section) = obj.section_by_index(section_index) {
                        if let Ok(section_name) = section.name() {
                            if section_name == ".text" {
                                SymbolType::Function
                            } else {
                                SymbolType::Data
                            }
                        } else {
                            SymbolType::Unknown
                        }
                    } else {
                        SymbolType::Unknown
                    }
                }
                _ => SymbolType::Unknown,
            }
        } else {
            // External symbols (imports) are typically functions
            // but we'll mark them as Unknown for now
            SymbolType::Unknown
        };

        let storage_class = 0; // object crate doesn't expose storage class directly
        let is_external = symbol.is_undefined();

        symbols.push(Symbol {
            name,
            value,
            section: section_index,
            symbol_type,
            storage_class,
            is_external,
            coff_index,
        });
    }

    Ok(symbols)
}

/// Extract import symbols
pub fn extract_imports(symbols: &[Symbol]) -> Result<Vec<Import>> {
    let mut imports = Vec::new();

    for symbol in symbols {
        if symbol.is_external && symbol.name.starts_with("__imp_") {
            // Parse import symbol format: __imp_LIBRARY$Function or __imp_Function
            let import_name = symbol.name.strip_prefix("__imp_").unwrap();
            
            if let Some((library, function)) = import_name.split_once('$') {
                imports.push(Import {
                    library: library.to_string(),
                    function: function.to_string(),
                    symbol_name: symbol.name.clone(),
                });
            } else {
                // Beacon API (no library prefix)
                imports.push(Import {
                    library: "Beacon".to_string(),
                    function: import_name.to_string(),
                    symbol_name: symbol.name.clone(),
                });
            }
        }
    }

    Ok(imports)
}

