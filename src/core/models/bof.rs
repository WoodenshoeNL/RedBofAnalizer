//! BOF file data structures

use std::path::PathBuf;

/// BOF file representation
#[derive(Debug, Clone, serde::Serialize)]
pub struct BofFile {
    pub path: PathBuf,
    pub header: CoffHeader,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub entry_point: Option<Symbol>,
    pub imports: Vec<Import>,
}

/// COFF header information
#[derive(Debug, Clone, serde::Serialize)]
pub struct CoffHeader {
    pub machine: MachineType,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub number_of_symbols: u32,
    pub characteristics: u16,
}

/// Machine type (architecture)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum MachineType {
    X86,    // 0x014C
    X64,    // 0x8664
    Unknown(u16),
}

impl From<u16> for MachineType {
    fn from(value: u16) -> Self {
        match value {
            0x014C => MachineType::X86,
            0x8664 => MachineType::X64,
            _ => MachineType::Unknown(value),
        }
    }
}

/// Section information
#[derive(Debug, Clone, serde::Serialize)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub data: Vec<u8>,
    pub characteristics: u32,
    pub entropy: f64,
}

/// Symbol information
#[derive(Debug, Clone, serde::Serialize)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub section: Option<usize>,
    pub symbol_type: SymbolType,
    pub storage_class: u8,
    pub is_external: bool,
    /// Original index in COFF symbol table (for relocation lookups)
    pub coff_index: usize,
}

/// Symbol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SymbolType {
    Function,
    Data,
    Unknown,
}

/// Relocation target type
#[derive(Debug, Clone, serde::Serialize)]
pub enum RelocationTarget {
    /// Target is a symbol (by COFF symbol index)
    Symbol(u32),
    /// Target is a section (by section index, 0-based)
    Section(usize),
}

/// Relocation information
#[derive(Debug, Clone, serde::Serialize)]
pub struct Relocation {
    /// Section index where this relocation applies
    pub section_index: usize,
    /// Offset within the section
    pub virtual_address: u32,
    /// What this relocation targets
    pub target: RelocationTarget,
    pub relocation_type: RelocationType,
}

/// Relocation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RelocationType {
    /// 32-bit relative address (AMD64_REL32)
    Rel32,
    /// 64-bit absolute address (ADDR64)
    Addr64,
    /// 32-bit absolute address (ADDR32)
    Addr32,
    /// Unknown relocation type
    Unknown(u16),
}

/// Import symbol information
#[derive(Debug, Clone, serde::Serialize)]
pub struct Import {
    pub library: String,
    pub function: String,
    pub symbol_name: String,
}

impl BofFile {
    /// Find all potential entry points (functions that could serve as entry points)
    /// This includes the default "go" entry point and any other functions in code sections
    pub fn find_potential_entry_points(&self) -> Vec<&Symbol> {
        let mut entry_points = Vec::new();
        
        // Add the default entry point if it exists
        if let Some(ref ep) = self.entry_point {
            entry_points.push(ep);
        }
        
        // Find all function symbols in code sections that aren't already included
        // We look for symbols that:
        // 1. Are defined (have a section) and not external
        // 2. Are in an executable section
        // 3. Are either marked as Function type OR are in .text section (common for functions)
        for symbol in &self.symbols {
            // Skip if already included (the default entry point)
            if self.entry_point.as_ref().map(|ep| ep.name == symbol.name).unwrap_or(false) {
                continue;
            }
            
            // Must be defined (has section) and not external
            if symbol.section.is_some() && !symbol.is_external {
                // Check if it's in a code section (executable)
                if let Some(section_idx) = symbol.section {
                    if let Some(section) = self.sections.get(section_idx) {
                        // Check if section is executable (IMAGE_SCN_MEM_EXECUTE = 0x20000000)
                        // or contains code (IMAGE_SCN_CNT_CODE = 0x00000020)
                        let is_executable = (section.characteristics & 0x20000000) != 0;
                        let is_code = (section.characteristics & 0x00000020) != 0;
                        let is_text_section = section.name == ".text" || section.name.starts_with(".text");
                        
                        if is_executable || is_code || is_text_section {
                            // Skip compiler-generated symbols and common non-function symbols
                            let name = &symbol.name;
                            if !name.starts_with('$') 
                                && !name.starts_with('.')
                                && name != "main"
                                && !name.starts_with("__")
                                && !name.contains("$unwind$")
                                && !name.contains("$pdata$") {
                                entry_points.push(symbol);
                            }
                        }
                    }
                }
            }
        }
        
        entry_points
    }
}

