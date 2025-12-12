//! Relocation parsing
//!
//! This module handles parsing of COFF relocation entries from BOF files.
//! Relocations are critical for BOF execution as they define how addresses
//! should be fixed up when the code is loaded at a different address.

use crate::core::models::bof::{Relocation, RelocationType, RelocationTarget as BofRelocationTarget};
use anyhow::Result;
use object::{Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget};

/// COFF relocation type constants for AMD64
#[allow(dead_code)]
pub mod amd64 {
    pub const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
    pub const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
    pub const IMAGE_REL_AMD64_ADDR32: u16 = 0x0002;
    pub const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
    pub const IMAGE_REL_AMD64_REL32: u16 = 0x0004;
    pub const IMAGE_REL_AMD64_REL32_1: u16 = 0x0005;
    pub const IMAGE_REL_AMD64_REL32_2: u16 = 0x0006;
    pub const IMAGE_REL_AMD64_REL32_3: u16 = 0x0007;
    pub const IMAGE_REL_AMD64_REL32_4: u16 = 0x0008;
    pub const IMAGE_REL_AMD64_REL32_5: u16 = 0x0009;
    pub const IMAGE_REL_AMD64_SECTION: u16 = 0x000A;
    pub const IMAGE_REL_AMD64_SECREL: u16 = 0x000B;
    pub const IMAGE_REL_AMD64_SECREL7: u16 = 0x000C;
    pub const IMAGE_REL_AMD64_TOKEN: u16 = 0x000D;
    pub const IMAGE_REL_AMD64_SREL32: u16 = 0x000E;
    pub const IMAGE_REL_AMD64_PAIR: u16 = 0x000F;
    pub const IMAGE_REL_AMD64_SSPAN32: u16 = 0x0010;
}

/// COFF relocation type constants for i386
#[allow(dead_code)]
pub mod i386 {
    pub const IMAGE_REL_I386_ABSOLUTE: u16 = 0x0000;
    pub const IMAGE_REL_I386_DIR16: u16 = 0x0001;
    pub const IMAGE_REL_I386_REL16: u16 = 0x0002;
    pub const IMAGE_REL_I386_DIR32: u16 = 0x0006;
    pub const IMAGE_REL_I386_DIR32NB: u16 = 0x0007;
    pub const IMAGE_REL_I386_SEG12: u16 = 0x0009;
    pub const IMAGE_REL_I386_SECTION: u16 = 0x000A;
    pub const IMAGE_REL_I386_SECREL: u16 = 0x000B;
    pub const IMAGE_REL_I386_TOKEN: u16 = 0x000C;
    pub const IMAGE_REL_I386_SECREL7: u16 = 0x000D;
    pub const IMAGE_REL_I386_REL32: u16 = 0x0014;
}

/// Extended relocation information with section context
#[derive(Debug, Clone, serde::Serialize)]
pub struct RelocationInfo {
    /// Section index where the relocation applies
    pub section_index: usize,
    /// Section name
    pub section_name: String,
    /// Offset within the section
    pub offset: u64,
    /// Symbol index being referenced
    pub symbol_index: u32,
    /// Symbol name (if resolved)
    pub symbol_name: Option<String>,
    /// Raw relocation type value
    pub raw_type: u16,
    /// Parsed relocation type
    pub relocation_type: RelocationType,
    /// Addend (for RELA-style relocations)
    pub addend: i64,
}

/// Parse all relocations from a COFF file
pub fn parse_relocations(obj: &object::File) -> Result<Vec<Relocation>> {
    let mut relocations = Vec::new();

    for (section_idx, section) in obj.sections().enumerate() {
        for (offset, reloc) in section.relocations() {
            let relocation_type = convert_relocation_type(&reloc, obj);
            
            // Get relocation target - can be a symbol or a section
            let target = match reloc.target() {
                RelocationTarget::Symbol(idx) => BofRelocationTarget::Symbol(idx.0 as u32),
                RelocationTarget::Section(idx) => {
                    // COFF section indices are 1-based (1 = first section)
                    // Convert to 0-based for our section_mappings array
                    let section_idx = if idx.0 > 0 { idx.0 - 1 } else { idx.0 };
                    BofRelocationTarget::Section(section_idx)
                },
                _ => continue, // Skip unknown relocation targets
            };

            relocations.push(Relocation {
                section_index: section_idx,
                virtual_address: offset as u32,
                target,
                relocation_type,
            });
        }
    }

    Ok(relocations)
}

/// Parse relocations with extended information
pub fn parse_relocations_extended(obj: &object::File) -> Result<Vec<RelocationInfo>> {
    let mut relocations = Vec::new();

    // Build symbol name lookup
    let symbol_names: Vec<Option<String>> = obj.symbols()
        .map(|sym| sym.name().ok().map(|s| s.to_string()))
        .collect();

    for (section_idx, section) in obj.sections().enumerate() {
        let section_name = section.name().unwrap_or("<unknown>").to_string();
        
        for (offset, reloc) in section.relocations() {
            let raw_type = get_raw_relocation_type(&reloc);
            let relocation_type = convert_relocation_type(&reloc, obj);
            
            // Get symbol info
            let (symbol_index, symbol_name) = match reloc.target() {
                RelocationTarget::Symbol(idx) => {
                    let name = symbol_names.get(idx.0)
                        .cloned()
                        .flatten();
                    (idx.0 as u32, name)
                }
                RelocationTarget::Section(idx) => {
                    (idx.0 as u32, Some(format!("section_{}", idx.0)))
                }
                _ => (0, None),
            };

            relocations.push(RelocationInfo {
                section_index: section_idx,
                section_name: section_name.clone(),
                offset,
                symbol_index,
                symbol_name,
                raw_type,
                relocation_type,
                addend: reloc.addend(),
            });
        }
    }

    Ok(relocations)
}

/// Get raw relocation type from object crate relocation
fn get_raw_relocation_type(reloc: &object::Relocation) -> u16 {
    // The object crate normalizes relocation types, but we can infer from kind
    match reloc.kind() {
        RelocationKind::Absolute => 0,
        RelocationKind::Relative => {
            // Could be REL32 or variants
            amd64::IMAGE_REL_AMD64_REL32
        }
        RelocationKind::Got | RelocationKind::GotRelative | 
        RelocationKind::GotBaseRelative | RelocationKind::GotBaseOffset => {
            amd64::IMAGE_REL_AMD64_REL32
        }
        RelocationKind::PltRelative => {
            amd64::IMAGE_REL_AMD64_REL32
        }
        RelocationKind::ImageOffset => {
            amd64::IMAGE_REL_AMD64_ADDR32NB
        }
        RelocationKind::SectionOffset => {
            amd64::IMAGE_REL_AMD64_SECREL
        }
        RelocationKind::SectionIndex => {
            amd64::IMAGE_REL_AMD64_SECTION
        }
        _ => 0xFFFF, // Unknown
    }
}

/// Convert object crate relocation to our RelocationType
fn convert_relocation_type(reloc: &object::Relocation, obj: &object::File) -> RelocationType {
    use object::Architecture;
    
    let arch = obj.architecture();
    let kind = reloc.kind();
    let size = reloc.size();
    
    match arch {
        Architecture::X86_64 => convert_amd64_relocation(kind, size),
        Architecture::I386 => convert_i386_relocation(kind, size),
        _ => RelocationType::Unknown(0),
    }
}

/// Convert AMD64 relocation
fn convert_amd64_relocation(kind: RelocationKind, size: u8) -> RelocationType {
    match (kind, size) {
        // 64-bit absolute address
        (RelocationKind::Absolute, 64) => RelocationType::Addr64,
        
        // 32-bit absolute address
        (RelocationKind::Absolute, 32) => RelocationType::Addr32,
        
        // 32-bit relative (most common in BOFs)
        (RelocationKind::Relative, 32) => RelocationType::Rel32,
        
        // Image-relative 32-bit
        (RelocationKind::ImageOffset, 32) => RelocationType::Addr32,
        
        // Section-relative
        (RelocationKind::SectionOffset, _) => RelocationType::Rel32,
        
        // GOT-relative (treat as REL32)
        (RelocationKind::Got, _) |
        (RelocationKind::GotRelative, _) |
        (RelocationKind::PltRelative, _) => RelocationType::Rel32,
        
        // Unknown
        _ => RelocationType::Unknown(0),
    }
}

/// Convert i386 relocation
fn convert_i386_relocation(kind: RelocationKind, size: u8) -> RelocationType {
    match (kind, size) {
        // 32-bit absolute
        (RelocationKind::Absolute, 32) => RelocationType::Addr32,
        
        // 32-bit relative
        (RelocationKind::Relative, 32) => RelocationType::Rel32,
        
        // Unknown
        _ => RelocationType::Unknown(0),
    }
}

/// Get relocation type name for display
pub fn relocation_type_name(reloc_type: &RelocationType, is_x64: bool) -> &'static str {
    match reloc_type {
        RelocationType::Rel32 => {
            if is_x64 { "AMD64_REL32" } else { "I386_REL32" }
        }
        RelocationType::Addr64 => "AMD64_ADDR64",
        RelocationType::Addr32 => {
            if is_x64 { "AMD64_ADDR32" } else { "I386_DIR32" }
        }
        RelocationType::Unknown(_) => "UNKNOWN",
    }
}

/// Get relocation statistics
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RelocationStats {
    pub total: usize,
    pub rel32_count: usize,
    pub addr64_count: usize,
    pub addr32_count: usize,
    pub unknown_count: usize,
    pub sections_with_relocs: usize,
}

/// Calculate relocation statistics
pub fn get_relocation_stats(relocations: &[RelocationInfo]) -> RelocationStats {
    let mut stats = RelocationStats::default();
    let mut section_set = std::collections::HashSet::new();
    
    stats.total = relocations.len();
    
    for reloc in relocations {
        section_set.insert(reloc.section_index);
        
        match reloc.relocation_type {
            RelocationType::Rel32 => stats.rel32_count += 1,
            RelocationType::Addr64 => stats.addr64_count += 1,
            RelocationType::Addr32 => stats.addr32_count += 1,
            RelocationType::Unknown(_) => stats.unknown_count += 1,
        }
    }
    
    stats.sections_with_relocs = section_set.len();
    stats
}

/// Format relocations for text output
pub fn format_relocations_text(relocations: &[RelocationInfo], is_x64: bool) -> String {
    let mut output = String::new();
    
    if relocations.is_empty() {
        output.push_str("No relocations found.\n");
        return output;
    }
    
    let stats = get_relocation_stats(relocations);
    
    output.push_str("=== Relocations ===\n\n");
    output.push_str(&format!("Total: {} | REL32: {} | ADDR64: {} | ADDR32: {} | Unknown: {}\n",
        stats.total, stats.rel32_count, stats.addr64_count, stats.addr32_count, stats.unknown_count));
    output.push_str(&format!("Sections with relocations: {}\n\n", stats.sections_with_relocs));
    
    output.push_str(&format!("{:<12} {:<10} {:<16} {:<16} {}\n",
        "Section", "Offset", "Type", "Symbol#", "Symbol Name"));
    output.push_str(&format!("{:-<12} {:-<10} {:-<16} {:-<16} {}\n",
        "", "", "", "", ""));
    
    for reloc in relocations.iter().take(50) {
        let type_name = relocation_type_name(&reloc.relocation_type, is_x64);
        let symbol_name = reloc.symbol_name.as_deref().unwrap_or("<unknown>");
        
        output.push_str(&format!("{:<12} 0x{:<8X} {:<16} {:<16} {}\n",
            &reloc.section_name[..reloc.section_name.len().min(12)],
            reloc.offset,
            type_name,
            reloc.symbol_index,
            symbol_name
        ));
    }
    
    if relocations.len() > 50 {
        output.push_str(&format!("\n... {} more relocations ...\n", relocations.len() - 50));
    }
    
    output
}

/// Format relocations for markdown output
pub fn format_relocations_markdown(relocations: &[RelocationInfo], is_x64: bool) -> String {
    let mut output = String::new();
    
    if relocations.is_empty() {
        output.push_str("*No relocations found.*\n");
        return output;
    }
    
    let stats = get_relocation_stats(relocations);
    
    output.push_str("## Relocations\n\n");
    output.push_str("### Statistics\n\n");
    output.push_str("| Metric | Count |\n");
    output.push_str("|--------|-------|\n");
    output.push_str(&format!("| Total | {} |\n", stats.total));
    output.push_str(&format!("| REL32 | {} |\n", stats.rel32_count));
    output.push_str(&format!("| ADDR64 | {} |\n", stats.addr64_count));
    output.push_str(&format!("| ADDR32 | {} |\n", stats.addr32_count));
    output.push_str(&format!("| Unknown | {} |\n", stats.unknown_count));
    output.push_str(&format!("| Sections with relocations | {} |\n", stats.sections_with_relocs));
    output.push_str("\n");
    
    output.push_str("### Relocation Entries\n\n");
    output.push_str("| Section | Offset | Type | Symbol | Name |\n");
    output.push_str("|---------|--------|------|--------|------|\n");
    
    for reloc in relocations.iter().take(50) {
        let type_name = relocation_type_name(&reloc.relocation_type, is_x64);
        let symbol_name = reloc.symbol_name.as_deref().unwrap_or("-");
        
        output.push_str(&format!("| `{}` | `0x{:X}` | {} | {} | `{}` |\n",
            reloc.section_name,
            reloc.offset,
            type_name,
            reloc.symbol_index,
            symbol_name
        ));
    }
    
    if relocations.len() > 50 {
        output.push_str(&format!("\n*... {} more relocations ...*\n", relocations.len() - 50));
    }
    
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_relocation_type_name() {
        assert_eq!(relocation_type_name(&RelocationType::Rel32, true), "AMD64_REL32");
        assert_eq!(relocation_type_name(&RelocationType::Rel32, false), "I386_REL32");
        assert_eq!(relocation_type_name(&RelocationType::Addr64, true), "AMD64_ADDR64");
    }
    
    #[test]
    fn test_relocation_stats() {
        let relocs = vec![
            RelocationInfo {
                section_index: 0,
                section_name: ".text".to_string(),
                offset: 0x10,
                symbol_index: 1,
                symbol_name: Some("test".to_string()),
                raw_type: 4,
                relocation_type: RelocationType::Rel32,
                addend: 0,
            },
            RelocationInfo {
                section_index: 0,
                section_name: ".text".to_string(),
                offset: 0x20,
                symbol_index: 2,
                symbol_name: None,
                raw_type: 1,
                relocation_type: RelocationType::Addr64,
                addend: 0,
            },
        ];
        
        let stats = get_relocation_stats(&relocs);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.rel32_count, 1);
        assert_eq!(stats.addr64_count, 1);
        assert_eq!(stats.sections_with_relocs, 1);
    }
}
