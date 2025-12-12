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
    match name {
        ".text" => {
            characteristics |= IMAGE_SCN_CNT_CODE;
            characteristics |= IMAGE_SCN_MEM_EXECUTE;
            characteristics |= IMAGE_SCN_MEM_READ;
        }
        ".data" => {
            characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
            characteristics |= IMAGE_SCN_MEM_READ;
            characteristics |= IMAGE_SCN_MEM_WRITE;
        }
        ".rdata" => {
            characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
            characteristics |= IMAGE_SCN_MEM_READ;
        }
        ".bss" => {
            characteristics |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
            characteristics |= IMAGE_SCN_MEM_READ;
            characteristics |= IMAGE_SCN_MEM_WRITE;
        }
        ".pdata" => {
            characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
            characteristics |= IMAGE_SCN_MEM_READ;
        }
        ".reloc" => {
            characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
            characteristics |= IMAGE_SCN_MEM_READ;
        }
        _ => {
            // Default: readable
            characteristics |= IMAGE_SCN_MEM_READ;
        }
    }
    
    characteristics
}

