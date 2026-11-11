//! BOF-PE execution: manual mapping of PE32+ BOF images.
//!
//! Ported from RedLoader's `loader::pe::execute` (live-verified on Windows
//! Server 2019 — see RedLoader `tests/deep-verify/`). The flow:
//!
//! ```text
//! MZ check -> parse -> VirtualAlloc(SizeOfImage) -> copy headers+sections
//!   -> DIR64 base relocs by delta -> bind imports (beacon.dll -> Beacon
//!   API table, other DLLs -> GetModuleHandleA/LoadLibraryA + GetProcAddress)
//!   -> VirtualProtect(RWX) -> call the `go` export
//! ```
//!
//! `DllMain` is intentionally NOT called (BOF-PE contract: entry is `go`).
//! The mapped image is intentionally leaked: async BOFs may keep threads
//! alive after `go` returns, and the process exits shortly after anyway
//! (same lifetime policy as the COFF path).

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};

use crate::core::executor::symbols::SymbolResolver;
use crate::core::parser::pe::{ImportTarget, PeBof, PeRelocKind};

/// Map `data` (a BOF-PE image) and call its `go(args, args_len)` export.
///
/// `beacon_apis` maps (lowercase) Beacon API names to function pointers —
/// pass a populated [`SymbolResolver`]'s table (see
/// `register_all_beacon_apis`). Returns the mapped image base.
///
/// # Safety-relevant contract
/// Runs arbitrary untrusted code from the BOF image inside this process;
/// only call with images you intend to execute.
pub fn execute_pe(
    data: &[u8],
    args: &[u8],
    resolver: &SymbolResolver,
    entry: &str,
) -> Result<usize> {
    use windows::core::PCSTR;
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        PAGE_READWRITE,
    };

    let pe = PeBof::parse(data).context("invalid BOF-PE image")?;
    if pe.has_unsupported_relocs() {
        return Err(anyhow!("image uses base relocation types beyond DIR64"));
    }
    let entry_rva = pe
        .export_rva(entry)
        .ok_or_else(|| anyhow!("entry export '{}' not found in BOF-PE image", entry))?;

    // Beacon API table (what beacon.dll resolves to), lowercase-keyed.
    let api_table: HashMap<String, usize> = resolver
        .beacon_api_table()
        .iter()
        .map(|(k, v)| (k.to_lowercase(), *v))
        .collect();

    unsafe {
        let base = VirtualAlloc(
            None,
            pe.size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if base.is_null() {
            return Err(anyhow!(
                "VirtualAlloc of 0x{:x} bytes for BOF-PE image failed",
                pe.size_of_image
            ));
        }
        let base = base as usize;

        // Headers.
        let hdr = pe.size_of_headers.min(data.len()).min(pe.size_of_image);
        std::ptr::copy_nonoverlapping(data.as_ptr(), base as *mut u8, hdr);

        // Sections (VirtualAlloc gives zero pages: .bss needs no copy).
        for s in &pe.sections {
            let n = s.raw_size.min(s.virtual_size) as usize;
            if n == 0 {
                continue;
            }
            let from = s.raw_offset as usize;
            if from + n > data.len()
                || base
                    .checked_add(s.virtual_address as usize)
                    .map(|a| a.checked_add(n))
                    .flatten()
                    .map(|end| end > base + pe.size_of_image)
                    .unwrap_or(true)
            {
                return Err(anyhow!("section {} extends beyond file/image", s.name));
            }
            std::ptr::copy_nonoverlapping(
                data.as_ptr().add(from),
                (base + s.virtual_address as usize) as *mut u8,
                n,
            );
        }

        // Base relocations (DIR64 only, which is all PE32+ uses in practice).
        let delta = (base as u64).wrapping_sub(pe.image_base);
        if delta != 0 {
            for r in pe.relocs() {
                match r.kind {
                    PeRelocKind::Absolute => {}
                    PeRelocKind::Dir64 => {
                        let at = (base + r.rva as usize) as *mut u64;
                        let cur = std::ptr::read_unaligned(at);
                        std::ptr::write_unaligned(at, cur.wrapping_add(delta));
                    }
                    PeRelocKind::Unsupported(t) => {
                        return Err(anyhow!("unsupported reloc type {} at rva 0x{:x}", t, r.rva));
                    }
                }
            }
        }

        // Bind imports: beacon.dll against the Beacon API table, system
        // DLLs against the real loaded modules.
        let mut lib_cache: HashMap<String, HMODULE> = HashMap::new();
        for imp in pe.imports() {
            let is_beacon = imp.dll.eq_ignore_ascii_case("beacon.dll")
                || imp.dll.eq_ignore_ascii_case("beacon");
            let module = if is_beacon {
                None
            } else {
                let key = imp.dll.to_lowercase();
                if let Some(&m) = lib_cache.get(&key) {
                    Some(m)
                } else {
                    let name = format!("{}\0", imp.dll);
                    let pc = PCSTR::from_raw(name.as_ptr());
                    let m = GetModuleHandleA(pc)
                        .or_else(|_| LoadLibraryA(pc))
                        .with_context(|| {
                            format!("GetModuleHandleA/LoadLibraryA failed for {}", imp.dll)
                        })?;
                    lib_cache.insert(key, m);
                    Some(m)
                }
            };
            for slot in &imp.slots {
                let addr: usize = if is_beacon {
                    match &slot.target {
                        ImportTarget::Name(n) => {
                            *api_table.get(&n.to_lowercase()).ok_or_else(|| {
                                anyhow!("beacon.dll::{} not found in Beacon API table", n)
                            })?
                        }
                        ImportTarget::Ordinal(o) => {
                            return Err(anyhow!(
                                "beacon.dll::#{} (ordinal import) not supported",
                                o
                            ))
                        }
                    }
                } else {
                    let module = module.unwrap();
                    match &slot.target {
                        ImportTarget::Name(n) => {
                            let cn = std::ffi::CString::new(n.as_str())
                                .with_context(|| format!("invalid import name {}", n))?;
                            GetProcAddress(module, PCSTR::from_raw(cn.as_ptr() as *const u8))
                                .ok_or_else(|| {
                                    anyhow!("GetProcAddress({},{}) failed", imp.dll, n)
                                })? as usize
                        }
                        ImportTarget::Ordinal(o) => {
                            GetProcAddress(module, PCSTR::from_raw(*o as usize as *const u8))
                                .ok_or_else(|| {
                                    anyhow!("GetProcAddress({},#{}) failed", imp.dll, o)
                                })? as usize
                        }
                    }
                };
                // Patch both ILT and IAT slots (they alias unless bound
                // imports split them); harmless when equal.
                std::ptr::write_unaligned((base + slot.ilt_rva as usize) as *mut u64, addr as u64);
                if slot.iat_rva != slot.ilt_rva {
                    std::ptr::write_unaligned(
                        (base + slot.iat_rva as usize) as *mut u64,
                        addr as u64,
                    );
                }
            }
        }

        // Executable. (The BOF's own VirtualProtect calls — e.g. the
        // beacon.h atexit-patch bootstrap — also rely on this.)
        let mut old = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            base as *const _,
            pe.size_of_image,
            PAGE_EXECUTE_READWRITE,
            &mut old,
        )
        .map_err(|_| anyhow!("VirtualProtect(RWX) on mapped BOF-PE image failed"))?;

        // Call go(args, args_len). Empty args: pass a valid-but-empty buffer
        // (RedBofAnalizer BOFs dereference the pointer to check for NUL).
        let dummy = [0u8; 1];
        let (ptr, len) = if args.is_empty() {
            (dummy.as_ptr(), 0i32)
        } else {
            (args.as_ptr(), args.len() as i32)
        };
        let entry_addr = base + entry_rva as usize;
        log::debug!("calling BOF-PE export '{}' at 0x{:x}", entry, entry_addr);
        let go: unsafe extern "C" fn(*const u8, i32) = std::mem::transmute(entry_addr);
        go(ptr, len);

        Ok(base)
    }
}
