//! BOF-PE parsing tests — run against real fixtures:
//!
//! - `race.x64.o`  — MSVC-built PE BOF from chryzsh/company-portal-lpe
//! - `tpe.x64.o`   — mingw-built PE BOF from RedLoader `tests/deep-verify`
//! - `race.x86.o`  — x86 PE BOF (must be rejected with a clean error)

use redbofanalyzer::core::models::bof::MachineType;
use redbofanalyzer::core::parser::pe;

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pe")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("missing fixture {}: {}", name, e))
}

fn coff_fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("missing fixture {}: {}", name, e))
}

#[test]
fn detects_pe_vs_coff_magic() {
    assert!(pe::is_pe_image(&fixture("race.x64.o")));
    assert!(pe::is_pe_image(&fixture("tpe.x64.o")));
    // A real COFF object must not sniff as PE.
    let coff = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/intune_race_bof.x64.o");
    if let Ok(data) = std::fs::read(&coff) {
        assert!(!pe::is_pe_image(&data));
    }
    assert!(!pe::is_pe_image(b"\x00\x00"));
    assert!(!pe::is_pe_image(b"MZ")); // too short
}

#[test]
fn parses_msvc_pe_bof() {
    let data = fixture("race.x64.o");
    let parsed = pe::PeBof::parse(&data).expect("race PE BOF must parse");
    assert_eq!(parsed.machine, 0x8664);
    assert_eq!(parsed.sections.len(), 11);
    assert!(parsed.export_rva("go").is_some(), "go export required");
    let dlls = parsed.imported_dll_names();
    assert!(dlls.iter().any(|d| d == "beacon.dll"), "beacon.dll import");
    // RedLoader maps the same image; DIR64 relocs must be present.
    assert!(parsed
        .relocs()
        .iter()
        .any(|r| r.kind == pe::PeRelocKind::Dir64));
    // No unsupported relocation kinds in a well-formed image.
    assert!(parsed
        .relocs()
        .iter()
        .all(|r| !matches!(r.kind, pe::PeRelocKind::Unsupported(_))));
}

#[test]
fn parses_mingw_pe_bof() {
    let data = fixture("tpe.x64.o");
    let parsed = pe::PeBof::parse(&data).expect("mingw PE BOF must parse");
    assert!(parsed.export_rva("go").is_some());
    let dlls = parsed.imported_dll_names();
    assert!(dlls.iter().any(|d| d == "beacon.dll"));
    // mingw links CRT support: msvcrt/kernel32 expected alongside beacon.
    assert!(dlls
        .iter()
        .any(|d| d.contains("msvcrt") || d.contains("kernel32")));
}

#[test]
fn rejects_x86_pe_bof_cleanly() {
    let data = fixture("race.x86.o");
    let err = pe::PeBof::parse(&data).unwrap_err().to_string();
    assert!(
        err.contains("unsupported machine 0x014c"),
        "expected clean x86 rejection, got: {err}"
    );
}

#[test]
fn pe_bof_file_model_feeds_analyzer() {
    let data = fixture("tpe.x64.o");
    let bof = pe::parse_pe(&data, "tpe.x64.o".into()).expect("conversion");
    assert_eq!(bof.header.machine, MachineType::X64);
    assert_eq!(bof.entry_point.as_ref().unwrap().name, "go");
    assert!(!bof.imports.is_empty());
    // Beacon imports normalized to library=function form.
    assert!(bof.imports.iter().any(|i| i.library == "beacon.dll"
        && (i.function.starts_with("BeaconPrintf") || i.function.starts_with("BeaconOutput"))));
    // DIR64 relocs mapped to Addr64 relocation entries.
    assert!(bof.relocations.iter().any(|r| matches!(
        r.relocation_type,
        redbofanalyzer::core::models::bof::RelocationType::Addr64
    )));
    // Sections carry data + entropy.
    assert!(bof
        .sections
        .iter()
        .any(|s| s.raw_size > 0 && s.entropy > 0.0));
}

#[test]
fn load_bof_dispatches_on_magic() {
    // PE fixture through the generic loader.
    let pe_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pe/race.x64.o");
    let bof = redbofanalyzer::core::parser::load_bof(&pe_path).expect("load PE via load_bof");
    assert_eq!(bof.header.machine, MachineType::X64);
    assert!(bof.entry_point.is_some());
}

#[test]
fn truncated_optional_header_is_err_not_panic() {
    // Valid MZ + e_lfanew + PE sig + machine, but the file ends right after
    // the COFF header while SizeOfOptionalHeader claims 0xF0 bytes.
    let b = truncated_header(0x58);
    let r = std::panic::catch_unwind(|| pe::PeBof::parse(&b));
    assert!(
        matches!(r, Ok(Err(_))),
        "parse must return Err, not panic (file len {})",
        b.len()
    );
}

#[test]
fn truncated_mid_optional_header_is_err_not_panic() {
    // File ends inside the optional header (after AddressOfEntryPoint).
    let b = truncated_header(0x58 + 40);
    let r = std::panic::catch_unwind(|| pe::PeBof::parse(&b));
    assert!(matches!(r, Ok(Err(_))), "parse must return Err, not panic");
}

#[test]
fn truncated_data_directories_is_err_not_panic() {
    // File ends inside the data-directory array (optional header present,
    // NumberOfRvaAndSizes claims entries that are not in the file).
    let b = truncated_header(0x58 + 112 + 8);
    let r = std::panic::catch_unwind(|| pe::PeBof::parse(&b));
    assert!(matches!(r, Ok(Err(_))), "parse must return Err, not panic");
}

/// Craft a truncated PE: full MZ/DOS stub + e_lfanew=0x40 + PE\0\0 +
/// x64 machine + SizeOfOptionalHeader=0xF0, file cut to `len` bytes.
fn truncated_header(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    if len < 2 {
        return b;
    }
    b[0] = b'M';
    b[1] = b'Z';
    if len >= 0x40 {
        b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    }
    if len >= 0x46 {
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        b[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes()); // machine
    }
    if len >= 0x5a {
        b[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes()); // optsz claim
                                                               // PE32+ magic so parse proceeds past the magic check
        b[0x58..0x5a].copy_from_slice(&0x020bu16.to_le_bytes());
    }
    if len >= 0x58 + 110 {
        // NumberOfRvaAndSizes at oh+108 claims the maximum 16 entries
        b[0x58 + 108..0x58 + 112].copy_from_slice(&16u32.to_le_bytes());
    }
    b
}

#[test]
fn hostile_reloc_page_rva_rejected() {
    // tpe.x64.o with the first .reloc block's PageRVA patched to point far
    // outside the image: must Err, never parse into an out-of-image write.
    let mut b = std::fs::read("tests/fixtures/pe/tpe.x64.o").unwrap();
    let off = 0x3600; // first reloc block (dir RVA 0xc000 -> file 0x3600)
    b[off..off + 4].copy_from_slice(&0x7fff_0000u32.to_le_bytes());
    let r = std::panic::catch_unwind(|| pe::PeBof::parse(&b));
    assert!(
        matches!(r, Ok(Err(_))),
        "hostile reloc PageRVA must be rejected"
    );
}

#[test]
fn hostile_reloc_entry_rva_rejected() {
    // Entry offset (low 12 bits) pushing the fixed-up RVA past SizeOfImage.
    let mut b = std::fs::read("tests/fixtures/pe/tpe.x64.o").unwrap();
    let off = 0x3600; // first reloc block: page near the image end...
    b[off..off + 4].copy_from_slice(&0x0000_CFFFu32.to_le_bytes());
    let off = 0x3608; // ...so entry offset 0xFFF pushes the RVA past SizeOfImage
    let w = u16::from_le_bytes([b[off], b[off + 1]]);
    b[off..off + 2].copy_from_slice(&((w & 0xF000) | 0x0FFF).to_le_bytes());
    let r = std::panic::catch_unwind(|| pe::PeBof::parse(&b));
    assert!(
        matches!(r, Ok(Err(_))),
        "reloc entry past image end must be rejected"
    );
}

#[test]
fn hostile_import_thunk_rva_rejected() {
    // Patch the first descriptor's ILT (OFT) RVA to outside the image.
    let mut b = std::fs::read("tests/fixtures/pe/tpe.x64.o").unwrap();
    let off = 0x2c00; // first import descriptor (dir file offset)
    b[off..off + 4].copy_from_slice(&0xF000_0000u32.to_le_bytes());
    let r = std::panic::catch_unwind(|| pe::PeBof::parse(&b));
    assert!(
        matches!(r, Ok(Err(_))),
        "import thunk RVA outside image must be rejected"
    );
}

#[test]
fn hostile_export_rva_rejected() {
    // Patch the first export address-table entry (go = 0x13b0) to 0x7fffffff.
    let mut b = std::fs::read("tests/fixtures/pe/tpe.x64.o").unwrap();
    let off = 0x2a28; // export address table (dir RVA 0x8028 -> file 0x2a28)
    b[off..off + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
    let r = std::panic::catch_unwind(|| pe::PeBof::parse(&b));
    assert!(
        matches!(r, Ok(Err(_))),
        "export RVA outside image must be rejected"
    );
}
