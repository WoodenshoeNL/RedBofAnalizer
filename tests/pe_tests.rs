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
