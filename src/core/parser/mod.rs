//! COFF parser module

pub mod coff;
pub mod sections;
pub mod symbols;
pub mod relocations;

use crate::core::models::bof::BofFile;
use std::path::PathBuf;
use anyhow::Result;

/// Load and parse a BOF file
pub fn load_bof(path: &PathBuf) -> Result<BofFile> {
    let data = std::fs::read(path)?;
    coff::parse_coff(&data, path.clone())
}

