//! COFF parser module

pub mod coff;
pub mod pe;
pub mod sections;
pub mod symbols;
pub mod relocations;

use crate::core::models::bof::BofFile;
use std::path::PathBuf;
use anyhow::Result;

/// Load and parse a BOF file (COFF object or BOF-PE image)
pub fn load_bof(path: &PathBuf) -> Result<BofFile> {
    let data = std::fs::read(path)?;
    if pe::is_pe_image(&data) {
        pe::parse_pe(&data, path.clone())
    } else {
        coff::parse_coff(&data, path.clone())
    }
}

