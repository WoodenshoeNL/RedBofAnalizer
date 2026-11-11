//! BOF-PE support: DLL-disguised-as-`.x64.o` images (Outflank OC2 style).
//!
//! Some C2 ecosystems (notably OC2's async BOFs) ship BOFs that are really
//! tiny MinGW/MSVC-linked **PE DLLs** renamed to `*.x64.o`, distinguished
//! from COFF BOFs only by the `MZ` magic. They import the Beacon API from
//! `beacon.dll` (resolved by the C2 against its API table, not a real DLL)
//! and export the standard entry `go(const char* data, int len)`.
//!
//! The loader does *not* call `DllMain` — it maps the image, applies base
//! relocations, binds imports, and calls the export.
//!
//! Ported from RedLoader (`src/loader/pe.rs`, live-verified on Windows
//! Server 2019 — see RedLoader `tests/deep-verify/`). Parsing, export
//! lookup, import enumeration and relocation listing are pure and
//! unit-tested on any platform; only mapping/execution is Windows-gated
//! (same split as the COFF path).
//!
//! [`PeBof::to_bof_file`] converts the parsed image into the analyzer's
//! [`BofFile`] model so the full analysis pipeline (sections/entropy,
//! imports, lints, OPSEC, yara) works on PE BOFs unchanged.

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;

use crate::core::models::bof::{
    BofFile, CoffHeader, Import, MachineType, Relocation, RelocationTarget, RelocationType,
    Section, Symbol, SymbolType,
};
use crate::core::utils::entropy::calculate_entropy;

/// Maximum sane image size we are willing to map (512 MB).
const MAX_IMAGE_SIZE: usize = 512 * 1024 * 1024;
/// Maximum sane number of sections.
const MAX_SECTIONS: u16 = 96;

/// Quick sniff: does this buffer start with an `MZ` PE image?
///
/// Checks the DOS magic, a plausible `e_lfanew`, and the `PE\0\0` signature.
/// Used to dispatch between the COFF and BOF-PE loaders.
pub fn is_pe_image(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }
    let lf = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    lf >= 0x40 && lf + 4 <= data.len() && &data[lf..lf + 4] == b"PE\0\0"
}

fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}

fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn u64_at(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

fn cstring_at(d: &[u8], off: usize) -> Option<&str> {
    let rest = d.get(off..)?;
    let end = rest.iter().position(|&c| c == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}

/// One section header, flattened.
#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl PeSection {
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }
    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }
}

/// A recognized base-relocation entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeRelocKind {
    /// Padding / no-op.
    Absolute,
    /// 64-bit addend relative to image base.
    Dir64,
    /// Anything else — must be rejected by the loader.
    Unsupported(u16),
}

/// One base-relocation entry (RVA inside the image).
#[derive(Debug, Clone, Copy)]
pub struct PeReloc {
    pub rva: u32,
    pub kind: PeRelocKind,
}

/// What one import slot resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportTarget {
    Name(String),
    Ordinal(u16),
}

/// One import: where to write the resolved address (ILT slot; the IAT slot
/// is also patched when it differs) and what to resolve.
#[derive(Debug, Clone)]
pub struct PeImportSlot {
    /// RVA of the Import Lookup Table entry (also used when no IAT split).
    pub ilt_rva: u32,
    /// RVA of the Import Address Table entry.
    pub iat_rva: u32,
    pub target: ImportTarget,
}

impl PeImportSlot {
    /// Import name, or `#ordinal`.
    pub fn target_name(&self) -> String {
        match &self.target {
            ImportTarget::Name(n) => n.clone(),
            ImportTarget::Ordinal(o) => format!("#{}", o),
        }
    }
}

/// Imports from one DLL.
#[derive(Debug, Clone)]
pub struct PeImportDll {
    pub dll: String,
    pub slots: Vec<PeImportSlot>,
}

/// A parsed BOF-PE image (borrowed from the input buffer).
#[derive(Debug)]
pub struct PeBof<'a> {
    data: &'a [u8],
    pub machine: u16,
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: usize,
    pub size_of_headers: usize,
    pub sections: Vec<PeSection>,
    exports: Vec<(String, u32)>,
    imports: Vec<PeImportDll>,
    relocs: Vec<PeReloc>,
}

impl<'a> PeBof<'a> {
    /// Parse and validate a BOF-PE image. `is_pe_image` need not have run.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            anyhow::bail!("not an MZ image");
        }
        let lf = u32_at(data, 0x3c).unwrap() as usize;
        if lf < 0x40 || lf + 24 > data.len() || &data[lf..lf + 4] != b"PE\0\0" {
            anyhow::bail!("bad e_lfanew or missing PE signature");
        }
        let machine = u16_at(data, lf + 4).unwrap();
        if machine != 0x8664 {
            anyhow::bail!(
                "unsupported machine 0x{:04x} (only x64 BOF-PE is supported; \
                 x86 PE BOFs need a 32-bit host process)",
                machine
            );
        }
        let num_sections = u16_at(data, lf + 6).unwrap();
        if num_sections > MAX_SECTIONS {
            anyhow::bail!("implausible section count");
        }
        let optsz = u16_at(data, lf + 20).unwrap() as usize;
        if optsz < 112 {
            anyhow::bail!("optional header too small");
        }
        let oh = lf + 24;
        let magic = u16_at(data, oh).unwrap();
        if magic != 0x20b {
            anyhow::bail!(
                "unsupported optional header magic 0x{:x} (only PE32+)",
                magic
            );
        }
        let entry_rva = u32_at(data, oh + 16).unwrap();
        let image_base = u64_at(data, oh + 24).unwrap();
        let size_of_image = u32_at(data, oh + 56).unwrap() as usize;
        let size_of_headers = u32_at(data, oh + 60).unwrap() as usize;
        if size_of_image == 0 || size_of_image > MAX_IMAGE_SIZE {
            anyhow::bail!("implausible SizeOfImage");
        }
        if size_of_headers == 0 || size_of_headers > data.len() {
            anyhow::bail!("implausible SizeOfHeaders");
        }
        let nrva = u32_at(data, oh + 108).unwrap().min(16) as usize;
        let dd = oh + 112;
        let dir = |i: usize| -> Option<(u32, u32)> {
            if i < nrva {
                let rva = u32_at(data, dd + i * 8).unwrap();
                let size = u32_at(data, dd + i * 8 + 4).unwrap();
                if rva != 0 && size != 0 {
                    return Some((rva, size));
                }
            }
            None
        };

        // Section table.
        let sec_off = oh + optsz;
        let mut sections = Vec::with_capacity(num_sections as usize);
        for i in 0..num_sections as usize {
            let o = sec_off + i * 40;
            if o + 40 > data.len() {
                anyhow::bail!("section table overruns file");
            }
            let raw_name = &data[o..o + 8];
            let nend = raw_name.iter().position(|&c| c == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..nend]).into_owned();
            sections.push(PeSection {
                name,
                virtual_size: u32_at(data, o + 8).unwrap(),
                virtual_address: u32_at(data, o + 12).unwrap(),
                raw_size: u32_at(data, o + 16).unwrap(),
                raw_offset: u32_at(data, o + 20).unwrap(),
                characteristics: u32_at(data, o + 36).unwrap(),
            });
        }

        let pe = PeBof {
            data,
            machine,
            image_base,
            entry_rva,
            size_of_image,
            size_of_headers,
            sections,
            exports: Vec::new(),
            imports: Vec::new(),
            relocs: Vec::new(),
        };

        let exports = pe.parse_exports(dir(0))?;
        let imports = pe.parse_imports(dir(1))?;
        let relocs = pe.parse_relocs(dir(5))?;
        Ok(PeBof {
            data,
            machine,
            image_base,
            entry_rva,
            size_of_image,
            size_of_headers,
            sections: pe.sections,
            exports,
            imports,
            relocs,
        })
    }

    fn rva_to_file_off(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            let va = s.virtual_address;
            let span = s.virtual_size.max(s.raw_size);
            if rva >= va && rva.wrapping_sub(va) < span {
                let off = s.raw_offset.checked_add(rva - va)? as usize;
                if off < self.data.len() {
                    return Some(off);
                }
                return None;
            }
        }
        None
    }

    fn parse_exports(&self, dir: Option<(u32, u32)>) -> Result<Vec<(String, u32)>> {
        let Some((rva, _)) = dir else {
            return Ok(Vec::new());
        };
        let Some(o) = self.rva_to_file_off(rva) else {
            return Ok(Vec::new()); // exports directory in a bad region: ignore
        };
        let d = self.data;
        let nfuncs = u32_at(d, o + 20).context("exports dir truncated")? as usize;
        let nnames = u32_at(d, o + 24).context("exports dir truncated")? as usize;
        let addr_tab = u32_at(d, o + 28).context("exports dir truncated")?;
        let name_tab = u32_at(d, o + 32).context("exports dir truncated")?;
        let ord_tab = u32_at(d, o + 36).context("exports dir truncated")?;
        if nfuncs > 4096 || nnames > 4096 {
            anyhow::bail!("implausible export counts");
        }
        let addr_o = self
            .rva_to_file_off(addr_tab)
            .ok_or_else(|| anyhow!("export address table outside image"))?;
        let name_o = self
            .rva_to_file_off(name_tab)
            .ok_or_else(|| anyhow!("export name table outside image"))?;
        let ord_o = self
            .rva_to_file_off(ord_tab)
            .ok_or_else(|| anyhow!("export ordinal table outside image"))?;
        let mut exports = Vec::with_capacity(nnames);
        for j in 0..nnames {
            let nrva = u32_at(d, name_o + j * 4).context("export name table truncated")?;
            let ord = u16_at(d, ord_o + j * 2).context("export ordinal table truncated")?;
            if ord as usize >= nfuncs {
                anyhow::bail!("export ordinal out of range");
            }
            let func_rva =
                u32_at(d, addr_o + ord as usize * 4).context("export address table truncated")?;
            let name = cstring_at(
                d,
                self.rva_to_file_off(nrva)
                    .ok_or_else(|| anyhow!("export name string outside image"))?,
            )
            .ok_or_else(|| anyhow!("export name not valid utf-8"))?
            .to_string();
            exports.push((name, func_rva));
        }
        Ok(exports)
    }

    fn parse_imports(&self, dir: Option<(u32, u32)>) -> Result<Vec<PeImportDll>> {
        let Some((rva, _)) = dir else {
            return Ok(Vec::new());
        };
        let mut dlls = Vec::new();
        let mut ent = self
            .rva_to_file_off(rva)
            .ok_or_else(|| anyhow!("import directory outside image"))?;
        // Guard against descriptors running off the end of the file.
        for _ in 0..256 {
            if ent + 20 > self.data.len() {
                break;
            }
            let d = self.data;
            let oft = u32_at(d, ent).unwrap();
            let name_rva = u32_at(d, ent + 12).unwrap();
            let thrunk = u32_at(d, ent + 16).unwrap();
            if name_rva == 0 {
                break; // end of descriptor array
            }
            let dll = cstring_at(
                d,
                self.rva_to_file_off(name_rva)
                    .ok_or_else(|| anyhow!("import dll name outside image"))?,
            )
            .ok_or_else(|| anyhow!("import dll name not utf-8"))?
            .to_string();
            let lookup = if oft != 0 { oft } else { thrunk };
            let lookup_o = self
                .rva_to_file_off(lookup)
                .ok_or_else(|| anyhow!("import lookup table outside image"))?;
            let iat_rva = thrunk;
            let iat_o = self
                .rva_to_file_off(thrunk)
                .ok_or_else(|| anyhow!("import address table outside image"))?;
            let mut slots = Vec::new();
            let mut i = 0u32;
            loop {
                if i > 4096 {
                    anyhow::bail!("implausible import count");
                }
                let lo = lookup_o + i as usize * 8;
                let io = iat_o + i as usize * 8;
                if lo + 8 > self.data.len() || io + 8 > self.data.len() {
                    anyhow::bail!("import thunks run off end of file");
                }
                let thunk = u64_at(d, lo).unwrap();
                if thunk == 0 {
                    break;
                }
                let target = if thunk >> 63 == 1 {
                    ImportTarget::Ordinal((thunk & 0xFFFF) as u16)
                } else {
                    let hn = self
                        .rva_to_file_off((thunk & 0x7FFF_FFFF) as u32)
                        .ok_or_else(|| anyhow!("hint/name outside image"))?;
                    let name = cstring_at(d, hn + 2)
                        .ok_or_else(|| anyhow!("import name not utf-8"))?
                        .to_string();
                    ImportTarget::Name(name)
                };
                slots.push(PeImportSlot {
                    ilt_rva: lookup + i * 8,
                    iat_rva: iat_rva + i * 8,
                    target,
                });
                i += 1;
            }
            dlls.push(PeImportDll { dll, slots });
            ent += 20;
        }
        Ok(dlls)
    }

    fn parse_relocs(&self, dir: Option<(u32, u32)>) -> Result<Vec<PeReloc>> {
        let Some((rva, size)) = dir else {
            // No relocation directory: image cannot be relocated.
            return Ok(Vec::new());
        };
        let mut o = self
            .rva_to_file_off(rva)
            .ok_or_else(|| anyhow!("reloc directory outside image"))?;
        let mut remaining = size as usize;
        let mut out = Vec::new();
        while remaining >= 8 {
            let block = u32_at(self.data, o).context("reloc block truncated")?;
            let bsize = u32_at(self.data, o + 4).context("reloc block truncated")? as usize;
            if bsize < 8 || bsize > remaining || o + bsize > self.data.len() {
                anyhow::bail!("malformed base relocation block");
            }
            let n = (bsize - 8) / 2;
            for j in 0..n {
                let w = u16_at(self.data, o + 8 + j * 2).unwrap();
                let kind = match w >> 12 {
                    0 => PeRelocKind::Absolute,
                    10 => PeRelocKind::Dir64,
                    t => PeRelocKind::Unsupported(t),
                };
                out.push(PeReloc {
                    rva: block + (w & 0xFFF) as u32,
                    kind,
                });
            }
            o += bsize;
            remaining -= bsize;
        }
        Ok(out)
    }

    /// RVA of a named export.
    /// Whether any relocation uses a type we cannot apply (not DIR64/Absolute).
    pub fn has_unsupported_relocs(&self) -> bool {
        self.relocs
            .iter()
            .any(|r| matches!(r.kind, PeRelocKind::Unsupported(_)))
    }

    pub fn export_rva(&self, name: &str) -> Option<u32> {
        self.exports
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, rva)| *rva)
    }

    /// All named exports (name, rva).
    pub fn exports(&self) -> &[(String, u32)] {
        &self.exports
    }

    /// Parsed import groups.
    pub fn imports(&self) -> &[PeImportDll] {
        &self.imports
    }

    /// Parsed base-relocation entries.
    pub fn relocs(&self) -> &[PeReloc] {
        &self.relocs
    }

    /// Names of the imported DLLs (lowercased).
    pub fn imported_dll_names(&self) -> Vec<String> {
        self.imports.iter().map(|d| d.dll.to_lowercase()).collect()
    }

    /// Convert the parsed PE image into the analyzer's [`BofFile`] model so
    /// the standard analysis pipeline (sections, imports, lints, OPSEC,
    /// yara) runs on PE BOFs unchanged.
    pub fn to_bof_file(&self, path: PathBuf) -> BofFile {
        // Sections: raw data sliced from the file, entropy computed.
        let sections: Vec<Section> = self
            .sections
            .iter()
            .map(|s| {
                let start = s.raw_offset as usize;
                let end = (start + s.raw_size as usize).min(self.data.len());
                let data = if start < end {
                    self.data[start..end].to_vec()
                } else {
                    Vec::new() // .bss-style sections carry no file data
                };
                let entropy = if data.is_empty() {
                    0.0
                } else {
                    calculate_entropy(&data)
                };
                Section {
                    name: s.name.clone(),
                    virtual_size: s.virtual_size,
                    raw_size: s.raw_size,
                    data,
                    characteristics: s.characteristics,
                    entropy,
                }
            })
            .collect();

        // Containing section index for an RVA (for exports and relocs).
        let section_of_rva = |rva: u32| -> Option<usize> {
            self.sections.iter().position(|s| {
                let span = s.virtual_size.max(s.raw_size);
                rva >= s.virtual_address && rva.wrapping_sub(s.virtual_address) < span
            })
        };

        // Symbols: one per named export; `go` becomes the entry point.
        let mut symbols: Vec<Symbol> = self
            .exports
            .iter()
            .map(|(name, rva)| Symbol {
                name: name.clone(),
                value: *rva as u64,
                section: section_of_rva(*rva),
                symbol_type: SymbolType::Function,
                storage_class: 2, // IMAGE_SYM_CLASS_EXTERNAL
                is_external: true,
                coff_index: usize::MAX, // not from a COFF symbol table
            })
            .collect();
        let entry_point = symbols.iter().find(|s| s.name == "go").cloned();

        // Imports: dll -> function entries.
        let imports: Vec<Import> = self
            .imports
            .iter()
            .flat_map(|d| {
                d.slots.iter().map(move |s| Import {
                    library: d.dll.clone(),
                    function: s.target_name(),
                    symbol_name: format!("__imp_{}${}", d.dll, s.target_name()),
                })
            })
            .collect();

        // Base relocations -> Addr64 relocations against their section.
        let relocations: Vec<Relocation> = self
            .relocs
            .iter()
            .filter_map(|r| {
                if r.kind != PeRelocKind::Dir64 {
                    return None;
                }
                let idx = section_of_rva(r.rva)?;
                Some(Relocation {
                    section_index: idx,
                    virtual_address: r.rva - self.sections[idx].virtual_address,
                    target: RelocationTarget::Section(idx),
                    relocation_type: RelocationType::Addr64,
                })
            })
            .collect();

        BofFile {
            path,
            header: CoffHeader {
                machine: MachineType::from(self.machine),
                number_of_sections: self.sections.len() as u16,
                timestamp: 0,
                number_of_symbols: self.exports.len() as u32,
                characteristics: 0x2000, // IMAGE_FILE_DLL
            },
            sections,
            symbols,
            relocations,
            entry_point,
            imports,
        }
    }
}

/// Load and parse a BOF-PE file into the analyzer's [`BofFile`] model.
pub fn parse_pe(data: &[u8], path: PathBuf) -> Result<BofFile> {
    let pe = PeBof::parse(data).map_err(|e| e.context("invalid BOF-PE image"))?;
    Ok(pe.to_bof_file(path))
}
