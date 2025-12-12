//! Relocation application for BOF execution

use crate::core::models::bof::{Relocation, RelocationType};
use crate::core::executor::loader::{MemoryRegion, SectionMapping};
use anyhow::Result;
use std::collections::HashMap;

/// Apply relocations to loaded BOF
pub fn apply_relocations(
    relocations: &[Relocation],
    memory: &MemoryRegion,
    section_mappings: &[SectionMapping],
    resolved_symbols: &HashMap<usize, usize>,
    base_address: usize,
) -> Result<()> {
    for reloc in relocations {
        apply_relocation(
            reloc,
            memory,
            section_mappings,
            resolved_symbols,
            base_address,
        )?;
    }
    Ok(())
}

/// Apply a single relocation
fn apply_relocation(
    reloc: &Relocation,
    memory: &MemoryRegion,
    section_mappings: &[SectionMapping],
    resolved_symbols: &HashMap<usize, usize>,
    base_address: usize,
) -> Result<()> {
    // Find the section this relocation belongs to
    // For now, we'll need to track which section each relocation belongs to
    // This is a simplified implementation - in practice, relocations are per-section
    
    let target_addr = *resolved_symbols.get(&(reloc.symbol_index as usize))
        .ok_or_else(|| anyhow::anyhow!("Symbol {} not resolved", reloc.symbol_index))?;
    
    // Calculate relocation location (simplified - assumes .text section)
    let text_section = section_mappings.iter()
        .find(|m| m.name == ".text")
        .ok_or_else(|| anyhow::anyhow!("No .text section found"))?;
    
    let reloc_location = base_address + text_section.offset + reloc.virtual_address as usize;
    let mem_offset = reloc_location - base_address;
    
    match reloc.relocation_type {
        RelocationType::Rel32 => {
            // 32-bit relative: target - location - 4
            let offset = (target_addr as i64 - reloc_location as i64 - 4) as i32;
            let bytes = offset.to_le_bytes();
            memory.write_at(mem_offset, &bytes)?;
        }
        RelocationType::Addr64 => {
            // 64-bit absolute address
            let bytes = (target_addr as u64).to_le_bytes();
            memory.write_at(mem_offset, &bytes)?;
        }
        RelocationType::Addr32 => {
            // 32-bit absolute address
            let bytes = (target_addr as u32).to_le_bytes();
            memory.write_at(mem_offset, &bytes)?;
        }
        RelocationType::Unknown(_) => {
            // Skip unknown relocation types
        }
        // Other types not yet implemented
        // TODO: Implement REL32_1-5, ADDR32NB, SECREL, etc.
    }
    
    Ok(())
}

