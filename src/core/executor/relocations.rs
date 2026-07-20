//! Relocation processing for BOF execution
#![cfg(windows)]

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
    bof_symbols: Option<&[crate::core::models::bof::Symbol]>,
) -> Result<()> {
    let mut applied = 0;
    let mut skipped = 0;
    let mut unresolved_symbols = std::collections::HashSet::new();
    let debug = super::is_debug_mode();
    
    // Debug: print ALL relocations in internal_printf (0x86-0x1F4)
    if debug {
        eprintln!("[BOF] All relocations in internal_printf (0x86-0x1F4):");
        for reloc in relocations.iter() {
            if reloc.section_index == 0 && reloc.virtual_address >= 0x86 && reloc.virtual_address <= 0x1F4 {
                let target_name = match &reloc.target {
                    crate::core::models::bof::RelocationTarget::Symbol(idx) => format!("Symbol({})", idx),
                    crate::core::models::bof::RelocationTarget::Section(idx) => format!("Section({})", idx),
                };
                eprintln!("[BOF]   Reloc at 0x{:x}: target={} type={:?}", 
                    reloc.virtual_address, target_name, reloc.relocation_type);
            }
        }
    }
    
    for (i, reloc) in relocations.iter().enumerate() {
        match apply_relocation(
            reloc,
            memory,
            section_mappings,
            resolved_symbols,
            base_address,
            bof_symbols,
        ) {
            Ok(_) => applied += 1,
            Err(e) => {
                // Extract symbol information for better error reporting
                if let crate::core::models::bof::RelocationTarget::Symbol(sym_idx) = &reloc.target {
                    if let Some(symbols) = bof_symbols {
                        if let Some(sym) = symbols.iter().find(|s| s.coff_index == *sym_idx as usize) {
                            unresolved_symbols.insert((*sym_idx, sym.name.clone()));
                            log::warn!("Failed to apply relocation {} at section[{}] offset 0x{:x}: {} (symbol: '{}', coff_idx: {})", 
                                i, reloc.section_index, reloc.virtual_address, e, sym.name, sym_idx);
                        } else {
                            log::warn!("Failed to apply relocation {}: {} (symbol index: {})", i, e, sym_idx);
                        }
                    } else {
                        log::warn!("Failed to apply relocation {}: {} (symbol index: {})", i, e, sym_idx);
                    }
                } else {
                    log::warn!("Failed to apply relocation {}: {}", i, e);
                }
                skipped += 1;
            }
        }
    }
    
    if debug {
        eprintln!("[BOF] Applied {} relocations, skipped {}", applied, skipped);
    }
    
    // If we have unresolved symbols, provide a helpful error message
    if !unresolved_symbols.is_empty() {
        let mut error_msg = format!("\n[BOF] ERROR: {} unresolved symbol(s) referenced by relocations:\n", unresolved_symbols.len());
        for (sym_idx, sym_name) in unresolved_symbols.iter() {
            error_msg.push_str(&format!("  - Symbol {} (coff_idx: {}): '{}'\n", sym_name, sym_idx, sym_name));
        }
        error_msg.push_str("\nThis usually means:\n");
        error_msg.push_str("  1. Missing function declarations in beacon.h\n");
        error_msg.push_str("  2. Functions not properly declared with WINBASEAPI/DECLSPEC_IMPORT\n");
        error_msg.push_str("  3. Missing import symbols (__imp_*)\n");
        error_msg.push_str("\nCheck the Lints tab for BOF009 errors with detailed suggestions.\n");
        
        if skipped > 0 && applied == 0 {
            // All relocations failed - this is critical
            return Err(anyhow::anyhow!("{}", error_msg));
        } else {
            // Some relocations failed - warn but continue
            log::warn!("{}", error_msg);
        }
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
    bof_symbols: Option<&[crate::core::models::bof::Symbol]>,
) -> Result<()> {
    use crate::core::models::bof::RelocationTarget;
    
    // Get the target address based on relocation target type
    let target_addr = match &reloc.target {
        RelocationTarget::Symbol(sym_idx) => {
            let sym_idx_usize = *sym_idx as usize;
            *resolved_symbols.get(&sym_idx_usize)
                .ok_or_else(|| {
                    // Try to get symbol name for better error message
                    let sym_name = if let Some(symbols) = bof_symbols {
                        symbols.iter()
                            .find(|s| s.coff_index == sym_idx_usize)
                            .map(|s| s.name.clone())
                            .unwrap_or_else(|| format!("Symbol({})", sym_idx))
                    } else {
                        format!("Symbol({})", sym_idx)
                    };
                    anyhow::anyhow!("Symbol '{}' (coff_idx: {}) not resolved - this symbol is referenced by a relocation but was not found in imports or defined in the BOF", sym_name, sym_idx)
                })?
        }
        RelocationTarget::Section(sec_idx) => {
            // For section relocations, target is the section base address
            let target_section = section_mappings.get(*sec_idx)
                .ok_or_else(|| anyhow::anyhow!("Target section {} not found", sec_idx))?;
            target_section.virtual_address
        }
    };
    
    // Find the section this relocation belongs to using section_index
    let section = section_mappings.get(reloc.section_index)
        .ok_or_else(|| anyhow::anyhow!("Section index {} out of bounds", reloc.section_index))?;
    
    // Calculate relocation location within the correct section
    let reloc_location = base_address + section.offset + reloc.virtual_address as usize;
    let mem_offset = reloc_location - base_address;
    
    log::debug!(
        "Applying relocation: section[{}]={} offset=0x{:x} type={:?} target={:?} -> addr=0x{:x} mem_offset=0x{:x}",
        reloc.section_index, section.name, reloc.virtual_address, reloc.relocation_type, 
        reloc.target, target_addr, mem_offset
    );
    
    match reloc.relocation_type {
        RelocationType::Rel32 => {
            // 32-bit relative: target + addend - location - 4
            // COFF stores the addend in the instruction bytes at the relocation site
            // We need to read it, add our adjustment, and write back
            let existing_bytes = unsafe {
                let ptr = (base_address + mem_offset) as *const [u8; 4];
                *ptr
            };
            let addend = i32::from_le_bytes(existing_bytes);
            let adjustment = (target_addr as i64 - reloc_location as i64 - 4) as i32;
            let final_offset = addend.wrapping_add(adjustment);
            let bytes = final_offset.to_le_bytes();
            log::trace!("REL32: existing=0x{:08x} + adjustment=0x{:08x} = 0x{:08x} at offset 0x{:x}", 
                addend as u32, adjustment as u32, final_offset as u32, mem_offset);
            memory.write_at(mem_offset, &bytes)?;
        }
        RelocationType::Addr64 => {
            // 64-bit absolute address - add addend from existing bytes
            let existing_bytes = unsafe {
                let ptr = (base_address + mem_offset) as *const [u8; 8];
                *ptr
            };
            let addend = i64::from_le_bytes(existing_bytes);
            let final_addr = (target_addr as i64).wrapping_add(addend) as u64;
            let bytes = final_addr.to_le_bytes();
            log::trace!("ADDR64: target=0x{:x} + addend=0x{:x} = 0x{:x} at offset 0x{:x}", 
                target_addr, addend, final_addr, mem_offset);
            memory.write_at(mem_offset, &bytes)?;
        }
        RelocationType::Addr32 => {
            // 32-bit absolute address - add addend from existing bytes
            let existing_bytes = unsafe {
                let ptr = (base_address + mem_offset) as *const [u8; 4];
                *ptr
            };
            let addend = i32::from_le_bytes(existing_bytes);
            let final_addr = (target_addr as i32).wrapping_add(addend) as u32;
            let bytes = final_addr.to_le_bytes();
            log::trace!("ADDR32: target=0x{:x} + addend=0x{:x} = 0x{:x} at offset 0x{:x}", 
                target_addr, addend, final_addr, mem_offset);
            memory.write_at(mem_offset, &bytes)?;
        }
        RelocationType::Unknown(_) => {
            // Skip unknown relocation types
            log::warn!("Skipping unknown relocation type at section {} offset 0x{:x}", 
                section.name, reloc.virtual_address);
        }
    }
    
    Ok(())
}

