//! Canonical bof_pack argument serialization.
//!
//! This module is the single source of truth for the packed argument
//! datapipe format shared by Cobalt Strike's `bof_pack`, Outflank OC2's
//! `BOFArgumentEncoding` packing (`*.s1.py` wrappers), and the
//! `BeaconDataParse`/`BeaconDataExtract` side implemented in
//! [`crate::beacon::DataParser`].
//!
//! ## Canonical wire format (per argument, concatenated in order)
//!
//! | Spec char | Type    | Encoding                                             |
//! |-----------|---------|------------------------------------------------------|
//! | `i`       | int32   | 4-byte little-endian value, raw                       |
//! | `s`       | int16   | 2-byte little-endian value, raw                       |
//! | `z`       | string  | int32 length (including NUL) + UTF-8 bytes + `0x00`   |
//! | `Z`       | wstring | int32 length (including wide NUL) + UTF-16LE + `0x0000` |
//! | `b`       | buffer  | int32 length (bytes, no NUL) + raw bytes              |
//!
//! There is no per-argument trailing padding or extra terminator beyond
//! what the length prefix covers, and no total-size prefix: the packed
//! buffer is passed to `go(char* args, int len)` with its byte length.
//!
//! This layout matches Cobalt Strike `bof_pack` (verified against the
//! `custom_pack.cna` reference implementation and Mythic Apollo's
//! `execute_coff` packer) and OC2's Stage1 `_encode_arguments_bof`
//! encodings for `STR`/`WSTR`/`INT`/`BUFFER`.

use thiserror::Error;

/// Error returned when a bof_pack format specification is invalid.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// The format string contains an unknown specifier character.
    #[error("unknown argument type '{0}' in format string (expected one of: i s z Z b)")]
    UnknownType(char),
    /// The number of provided values does not match the format string.
    #[error("format string expects {expected} arguments, got {got}")]
    ArityMismatch { expected: usize, got: usize },
    /// A provided value does not match the declared type.
    #[error("argument {index} has type mismatch: expected {expected}")]
    TypeMismatch {
        index: usize,
        expected: &'static str,
    },
}

/// A bof_pack argument type, addressed by its spec character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgType {
    /// 32-bit integer (`i`).
    Int,
    /// 16-bit integer (`s`).
    Short,
    /// ANSI/narrow string (`z`).
    Str,
    /// Wide string, UTF-16LE (`Z`).
    WStr,
    /// Binary buffer (`b`).
    Buffer,
}

impl ArgType {
    /// Parse a single specifier character.
    pub fn from_char(c: char) -> Result<Self, FormatError> {
        match c {
            'i' => Ok(ArgType::Int),
            's' => Ok(ArgType::Short),
            'z' => Ok(ArgType::Str),
            'Z' => Ok(ArgType::WStr),
            'b' => Ok(ArgType::Buffer),
            other => Err(FormatError::UnknownType(other)),
        }
    }

    /// The spec character for this type.
    pub fn as_char(self) -> char {
        match self {
            ArgType::Int => 'i',
            ArgType::Short => 's',
            ArgType::Str => 'z',
            ArgType::WStr => 'Z',
            ArgType::Buffer => 'b',
        }
    }
}

/// A typed argument value ready for packing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgValue {
    /// 32-bit integer.
    Int(i32),
    /// 16-bit integer.
    Short(i16),
    /// Narrow string (no embedded NULs).
    Str(String),
    /// Wide string (no embedded NULs).
    WStr(String),
    /// Raw bytes.
    Buffer(Vec<u8>),
}

impl ArgValue {
    /// The [`ArgType`] of this value.
    pub fn arg_type(&self) -> ArgType {
        match self {
            ArgValue::Int(_) => ArgType::Int,
            ArgValue::Short(_) => ArgType::Short,
            ArgValue::Str(_) => ArgType::Str,
            ArgValue::WStr(_) => ArgType::WStr,
            ArgValue::Buffer(_) => ArgType::Buffer,
        }
    }
}

/// Parse a bof_pack format specification (e.g. `"bzi"`) into types.
pub fn parse_arg_format(fmt: &str) -> Result<Vec<ArgType>, FormatError> {
    fmt.chars().map(ArgType::from_char).collect()
}

// ---------------------------------------------------------------------------
// Wire primitives (single implementation shared by all builders)
// ---------------------------------------------------------------------------

/// Append a raw little-endian int32 (bof_pack `i`).
pub fn emit_int(buf: &mut Vec<u8>, value: i32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Append a raw little-endian int16 (bof_pack `s`).
pub fn emit_short(buf: &mut Vec<u8>, value: i16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Append a length-prefixed narrow string; length includes the NUL (bof_pack `z`).
pub fn emit_str(buf: &mut Vec<u8>, s: &str) {
    let len = (s.len() + 1) as i32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

/// Append a length-prefixed wide string; length includes the wide NUL (bof_pack `Z`).
pub fn emit_wstr(buf: &mut Vec<u8>, s: &str) {
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes: Vec<u8> = wide.iter().flat_map(|&c| c.to_le_bytes()).collect();
    buf.extend_from_slice(&(bytes.len() as i32).to_le_bytes());
    buf.extend_from_slice(&bytes);
}

/// Append a length-prefixed buffer with no terminator (bof_pack `b`).
pub fn emit_buffer(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as i32).to_le_bytes());
    buf.extend_from_slice(data);
}

/// Append one typed value according to the canonical layout.
pub fn emit_value(buf: &mut Vec<u8>, value: &ArgValue) {
    match value {
        ArgValue::Int(v) => emit_int(buf, *v),
        ArgValue::Short(v) => emit_short(buf, *v),
        ArgValue::Str(v) => emit_str(buf, v),
        ArgValue::WStr(v) => emit_wstr(buf, v),
        ArgValue::Buffer(v) => emit_buffer(buf, v),
    }
}

/// Pack typed values, validating the optional format string.
///
/// When `fmt` is provided, each value's type must match the corresponding
/// spec character (arity is checked too). When `fmt` is `None`, values are
/// packed using their own types in order.
pub fn pack(fmt: Option<&[ArgType]>, values: &[ArgValue]) -> Result<Vec<u8>, FormatError> {
    if let Some(fmt) = fmt {
        if fmt.len() != values.len() {
            return Err(FormatError::ArityMismatch {
                expected: fmt.len(),
                got: values.len(),
            });
        }
        for (i, (t, v)) in fmt.iter().zip(values.iter()).enumerate() {
            if t != &v.arg_type() {
                return Err(FormatError::TypeMismatch {
                    index: i,
                    expected: match t {
                        ArgType::Int => "int32",
                        ArgType::Short => "int16",
                        ArgType::Str => "string",
                        ArgType::WStr => "wstring",
                        ArgType::Buffer => "buffer",
                    },
                });
            }
        }
    }
    let mut buf = Vec::new();
    for v in values {
        emit_value(&mut buf, v);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_format_string_all_types() {
        let fmt = parse_arg_format("bziZs").unwrap();
        assert_eq!(
            fmt,
            vec![
                ArgType::Buffer,
                ArgType::Str,
                ArgType::Int,
                ArgType::WStr,
                ArgType::Short
            ]
        );
        assert_eq!(
            parse_arg_format("q").unwrap_err(),
            FormatError::UnknownType('q')
        );
    }

    #[test]
    fn pack_int_short_raw_little_endian() {
        assert_eq!(
            pack(None, &[ArgValue::Int(-2)]).unwrap(),
            vec![0xFE, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(pack(None, &[ArgValue::Short(1)]).unwrap(), vec![0x01, 0x00]);
    }

    #[test]
    fn pack_str_length_includes_null() {
        let buf = pack(None, &[ArgValue::Str("hi".into())]).unwrap();
        assert_eq!(buf, vec![0x03, 0x00, 0x00, 0x00, b'h', b'i', 0x00]);
    }

    #[test]
    fn pack_empty_str() {
        let buf = pack(None, &[ArgValue::Str(String::new())]).unwrap();
        assert_eq!(buf, vec![0x01, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn pack_wstr_length_includes_wide_null() {
        let buf = pack(None, &[ArgValue::WStr("A".into())]).unwrap();
        // len = 4 (A + NUL as UTF-16), bytes: 'A' as UTF-16LE, NUL, NUL
        assert_eq!(buf, vec![0x04, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn pack_buffer_no_terminator() {
        let buf = pack(None, &[ArgValue::Buffer(vec![0xDE, 0xAD])]).unwrap();
        assert_eq!(buf, vec![0x02, 0x00, 0x00, 0x00, 0xDE, 0xAD]);
    }

    /// Golden vector: company-portal-lpe `race` (`bzi`) —
    /// payload 4 bytes `MZ\x90\x00`, plugin `nsExec.dll`, timeout 120.
    #[test]
    fn golden_race_bzi() {
        let fmt = parse_arg_format("bzi").unwrap();
        let buf = pack(
            Some(&fmt),
            &[
                ArgValue::Buffer(vec![0x4D, 0x5A, 0x90, 0x00]),
                ArgValue::Str("nsExec.dll".into()),
                ArgValue::Int(120),
            ],
        )
        .unwrap();

        let mut expect: Vec<u8> = vec![0x04, 0x00, 0x00, 0x00, 0x4D, 0x5A, 0x90, 0x00];
        expect.extend_from_slice(&[0x0B, 0x00, 0x00, 0x00]); // 10 chars + NUL
        expect.extend_from_slice(b"nsExec.dll\0");
        expect.extend_from_slice(&120i32.to_le_bytes());
        assert_eq!(buf, expect);
        assert_eq!(buf.len(), 8 + 4 + 11 + 4);
    }

    /// Golden vector: askWAM (`zzzzzzziiii` per askwam.cna): seven strings
    /// (empty defaults), then ints timeout=30, hide=0, cae=0, enum=0.
    #[test]
    fn golden_askwam_defaults() {
        let fmt = parse_arg_format("zzzzzzziiii").unwrap();
        let values: Vec<ArgValue> = std::iter::repeat_with(|| ArgValue::Str(String::new()))
            .take(7)
            .chain([
                ArgValue::Int(30),
                ArgValue::Int(0),
                ArgValue::Int(0),
                ArgValue::Int(0),
            ])
            .collect();
        let buf = pack(Some(&fmt), &values).unwrap();
        // 7 empty z: each 5 bytes = 35; 4 i: 16
        assert_eq!(buf.len(), 35 + 16);
        assert_eq!(&buf[0..5], &[0x01, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&buf[35..39], &30i32.to_le_bytes());
        assert_eq!(&buf[39..51], &[0u8; 12]);
    }

    #[test]
    fn pack_arity_and_type_checks() {
        let fmt = parse_arg_format("zi").unwrap();
        let e = pack(Some(&fmt), &[ArgValue::Int(1)]).unwrap_err();
        assert_eq!(
            e,
            FormatError::ArityMismatch {
                expected: 2,
                got: 1
            }
        );
        let e = pack(Some(&fmt), &[ArgValue::Int(1), ArgValue::Str("x".into())]).unwrap_err();
        assert!(matches!(e, FormatError::TypeMismatch { index: 0, .. }));
    }

    #[test]
    fn arg_type_roundtrip() {
        for c in "bizZs".chars() {
            assert_eq!(ArgType::from_char(c).unwrap().as_char(), c);
        }
    }
}
