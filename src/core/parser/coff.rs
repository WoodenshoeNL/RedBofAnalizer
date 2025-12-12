//! COFF header parsing

use crate::core::models::bof::{BofFile, CoffHeader, MachineType};
use crate::core::parser::{sections, symbols, relocations};
use std::path::PathBuf;
use anyhow::{Result, Context};
use object::Object;

/// Parse COFF file
pub fn parse_coff(data: &[u8], path: PathBuf) -> Result<BofFile> {
    let obj = object::File::parse(data)
        .context("Failed to parse COFF file")?;

    // Parse header
    let header = parse_header(&obj)?;

    // Parse sections
    let sections = sections::parse_sections(&obj)?;

    // Parse symbols
    let symbols = symbols::parse_symbols(&obj)?;

    // Parse relocations
    let relocations = relocations::parse_relocations(&obj)?;

    // Find entry point
    // Look for a symbol named "go" that is defined (has a section)
    // This is more lenient than requiring Function type, as the symbol type detection
    // might not always correctly identify functions, especially in COFF object files
    let entry_point = symbols.iter()
        .find(|s| {
            s.name == "go" && 
            s.section.is_some() &&  // Must be defined (have a section)
            !s.is_external           // Must not be an external/undefined symbol
        })
        .cloned();

    // Extract imports
    let imports = symbols::extract_imports(&symbols)?;

    Ok(BofFile {
        path,
        header,
        sections,
        symbols,
        relocations,
        entry_point,
        imports,
    })
}

/// Parse COFF header
fn parse_header(obj: &object::File) -> Result<CoffHeader> {
    let machine = MachineType::from(obj.architecture());
    let number_of_sections = obj.sections().count() as u16;
    let number_of_symbols = obj.symbols().count() as u32;
    
    Ok(CoffHeader {
        machine,
        number_of_sections,
        timestamp: 0, // object crate doesn't expose timestamp directly
        number_of_symbols,
        characteristics: 0, // object crate doesn't expose characteristics directly
    })
}

impl From<object::Architecture> for MachineType {
    fn from(arch: object::Architecture) -> Self {
        match arch {
            object::Architecture::X86_64 => MachineType::X64,
            object::Architecture::I386 => MachineType::X86,
            _ => MachineType::Unknown(0),
        }
    }
}

