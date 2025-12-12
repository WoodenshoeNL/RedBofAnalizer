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
}

/// Symbol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SymbolType {
    Function,
    Data,
    Unknown,
}

/// Relocation information
#[derive(Debug, Clone, serde::Serialize)]
pub struct Relocation {
    pub virtual_address: u32,
    pub symbol_index: u32,
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

