//! Memory loader for BOF files

use crate::core::models::bof::BofFile;
use anyhow::{Result, Context};
use std::ptr::NonNull;
use windows::Win32::System::Memory::*;

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Memory region for loaded BOF
pub struct MemoryRegion {
    base: NonNull<u8>,
    size: usize,
}

unsafe impl Send for MemoryRegion {}

impl MemoryRegion {
    /// Allocate a memory region
    pub fn allocate(size: usize) -> Result<Self> {
        let aligned_size = align_to_page(size);
        
        unsafe {
            let ptr = VirtualAlloc(
                None,
                aligned_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            
            if ptr.is_null() {
                anyhow::bail!("VirtualAlloc returned null");
            }
            
            Ok(MemoryRegion {
                base: NonNull::new(ptr as *mut u8)
                    .ok_or_else(|| anyhow::anyhow!("Failed to create NonNull pointer"))?,
                size: aligned_size,
            })
        }
    }
    
    /// Get base address
    pub fn base(&self) -> *mut u8 {
        self.base.as_ptr()
    }
    
    /// Get size
    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.size
    }
    
    /// Set memory protection
    pub fn set_protection(&self, protect: u32) -> Result<()> {
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                self.base.as_ptr() as *const _,
                self.size,
                PAGE_PROTECTION_FLAGS(protect),
                &mut old_protect,
            )
            .context("Failed to set memory protection")?;
        }
        Ok(())
    }
    
    /// Write data at offset
    pub fn write_at(&self, offset: usize, data: &[u8]) -> Result<()> {
        if offset + data.len() > self.size {
            anyhow::bail!("Write out of bounds");
        }
        unsafe {
            let dst = self.base.as_ptr().add(offset);
            std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        Ok(())
    }
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(
                self.base.as_ptr() as *mut _,
                0,
                MEM_RELEASE,
            );
        }
    }
}

/// Align value to page boundary
pub fn align_to_page(value: usize) -> usize {
    (value + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Load BOF sections into memory
pub fn load_sections(
    bof: &BofFile,
    memory: &MemoryRegion,
) -> Result<Vec<SectionMapping>> {
    let mut mappings = Vec::new();
    let mut offset = 0usize;
    
    for section in &bof.sections {
        let section_size = section.raw_size as usize;
        let aligned_size = align_to_page(section_size);
        
        // Write section data
        if !section.data.is_empty() {
            memory.write_at(offset, &section.data)?;
        } else if section.name == ".bss" {
            // Initialize .bss to zero
            let zeros = vec![0u8; section_size];
            memory.write_at(offset, &zeros)?;
        }
        
        // Note: In a real implementation, we'd set protection per-section
        // For now, we'll set it on the whole region after loading
        // Protection is set after all sections are loaded
        
        mappings.push(SectionMapping {
            name: section.name.clone(),
            offset,
            size: section_size,
            virtual_address: memory.base() as usize + offset,
        });
        
        offset += aligned_size;
    }
    
    // Set overall protection (executable for .text sections)
    // In a real implementation, we'd use VirtualProtect per section
    memory.set_protection(PAGE_EXECUTE_READWRITE.0)?;
    
    Ok(mappings)
}

/// Section mapping information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SectionMapping {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub virtual_address: usize,
}
