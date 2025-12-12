//! Section parsing

use crate::core::models::bof::Section;
use crate::core::utils::entropy;
use anyhow::Result;
use object::{Object, ObjectSection};

/// Parse all sections
pub fn parse_sections(obj: &object::File) -> Result<Vec<Section>> {
    let mut sections = Vec::new();

    for section in obj.sections() {
        let name = section.name().unwrap_or("<unknown>").to_string();
        let data = section.data().unwrap_or(&[]).to_vec();
        let virtual_size = data.len() as u32;
        let raw_size = data.len() as u32;
        
        // Calculate entropy
        let section_entropy = entropy::calculate_entropy(&data);
        
        // Determine characteristics based on section name
        let characteristics = determine_section_characteristics(&name);

        sections.push(Section {
            name,
            virtual_size,
            raw_size,
            data,
            characteristics,
            entropy: section_entropy,
        });
    }

    Ok(sections)
}

/// Determine section characteristics based on name
fn determine_section_characteristics(name: &str) -> u32 {
    let mut characteristics = 0u32;
    
    // Common section characteristics flags (IMAGE_SCN_*)
    const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
    const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
    const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
    
    // Determine characteristics based on section name
    // Handle both exact matches and patterns (e.g., ".text$mn")
    if name == ".text" || name.starts_with(".text") {
        characteristics |= IMAGE_SCN_CNT_CODE;
        characteristics |= IMAGE_SCN_MEM_EXECUTE;
        characteristics |= IMAGE_SCN_MEM_READ;
    } else if name == ".data" || name.starts_with(".data") {
        characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
        characteristics |= IMAGE_SCN_MEM_READ;
        characteristics |= IMAGE_SCN_MEM_WRITE;
    } else if name == ".rdata" || name.starts_with(".rdata") {
        characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
        characteristics |= IMAGE_SCN_MEM_READ;
    } else if name == ".bss" || name.starts_with(".bss") {
        characteristics |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        characteristics |= IMAGE_SCN_MEM_READ;
        characteristics |= IMAGE_SCN_MEM_WRITE;
    } else if name == ".pdata" || name.starts_with(".pdata") {
        characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
        characteristics |= IMAGE_SCN_MEM_READ;
    } else if name == ".reloc" || name.starts_with(".reloc") {
        characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
        characteristics |= IMAGE_SCN_MEM_READ;
    } else {
        // Default: readable
        characteristics |= IMAGE_SCN_MEM_READ;
    }
    
    characteristics
}

