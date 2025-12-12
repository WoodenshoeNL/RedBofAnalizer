//! Printf format string parser and formatter
//!
//! This module implements a printf-style formatter for BeaconPrintf and
//! BeaconFormatPrintf functions. It parses format strings and applies
//! formatting to provided arguments.

#![allow(dead_code)]

use std::ffi::CStr;
use std::os::raw::c_char;

/// Format specifier parsed from a printf format string
#[derive(Debug, Clone)]
pub struct FormatSpec {
    /// Full specifier string (e.g., "%-10.5s")
    pub raw: String,
    /// Flags ('-', '+', ' ', '#', '0')
    pub flags: FormatFlags,
    /// Minimum field width
    pub width: Option<usize>,
    /// Precision (after '.')
    pub precision: Option<usize>,
    /// Length modifier ('h', 'l', 'll', 'z', etc.)
    pub length: LengthModifier,
    /// Conversion specifier ('d', 's', 'x', etc.)
    pub specifier: char,
}

/// Format flags
#[derive(Debug, Clone, Default)]
pub struct FormatFlags {
    pub left_justify: bool,   // '-'
    pub sign_plus: bool,      // '+'
    pub sign_space: bool,     // ' '
    pub alternate: bool,      // '#'
    pub zero_pad: bool,       // '0'
}

/// Length modifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthModifier {
    None,
    H,      // short
    HH,     // char
    L,      // long
    LL,     // long long
    Z,      // size_t
    J,      // intmax_t
    T,      // ptrdiff_t
}

impl Default for LengthModifier {
    fn default() -> Self {
        LengthModifier::None
    }
}

/// Argument types that can be formatted
#[derive(Debug, Clone)]
pub enum FormatArg {
    Int(i64),
    UInt(u64),
    Float(f64),
    Char(char),
    String(String),
    Pointer(usize),
}

/// Parse a printf format string and extract format specifiers
pub fn parse_format_string(format: &str) -> Vec<FormatPart> {
    let mut parts = Vec::new();
    let mut chars = format.chars().peekable();
    let mut literal = String::new();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Check for %%
            if chars.peek() == Some(&'%') {
                chars.next();
                literal.push('%');
                continue;
            }

            // Flush literal
            if !literal.is_empty() {
                parts.push(FormatPart::Literal(std::mem::take(&mut literal)));
            }

            // Parse format specifier
            if let Some(spec) = parse_format_spec(&mut chars) {
                parts.push(FormatPart::Specifier(spec));
            }
        } else {
            literal.push(c);
        }
    }

    // Flush remaining literal
    if !literal.is_empty() {
        parts.push(FormatPart::Literal(literal));
    }

    parts
}

/// Part of a format string
#[derive(Debug, Clone)]
pub enum FormatPart {
    Literal(String),
    Specifier(FormatSpec),
}

/// Parse a single format specifier
fn parse_format_spec(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<FormatSpec> {
    let mut raw = String::from("%");
    let mut flags = FormatFlags::default();
    let mut width = None;
    let mut precision = None;
    let mut length = LengthModifier::None;

    // Parse flags
    while let Some(&c) = chars.peek() {
        match c {
            '-' => { flags.left_justify = true; raw.push(chars.next().unwrap()); }
            '+' => { flags.sign_plus = true; raw.push(chars.next().unwrap()); }
            ' ' => { flags.sign_space = true; raw.push(chars.next().unwrap()); }
            '#' => { flags.alternate = true; raw.push(chars.next().unwrap()); }
            '0' => { flags.zero_pad = true; raw.push(chars.next().unwrap()); }
            _ => break,
        }
    }

    // Parse width
    if let Some(&c) = chars.peek() {
        if c == '*' {
            raw.push(chars.next().unwrap());
            width = Some(0); // Will be replaced by argument
        } else if c.is_ascii_digit() && c != '0' {
            let mut w = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    w.push(chars.next().unwrap());
                    raw.push(d);
                } else {
                    break;
                }
            }
            width = w.parse().ok();
        }
    }

    // Parse precision
    if chars.peek() == Some(&'.') {
        raw.push(chars.next().unwrap());
        if chars.peek() == Some(&'*') {
            raw.push(chars.next().unwrap());
            precision = Some(0); // Will be replaced by argument
        } else {
            let mut p = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    p.push(chars.next().unwrap());
                    raw.push(d);
                } else {
                    break;
                }
            }
            precision = p.parse().ok().or(Some(0));
        }
    }

    // Parse length modifier
    if let Some(&c) = chars.peek() {
        match c {
            'h' => {
                raw.push(chars.next().unwrap());
                if chars.peek() == Some(&'h') {
                    raw.push(chars.next().unwrap());
                    length = LengthModifier::HH;
                } else {
                    length = LengthModifier::H;
                }
            }
            'l' => {
                raw.push(chars.next().unwrap());
                if chars.peek() == Some(&'l') {
                    raw.push(chars.next().unwrap());
                    length = LengthModifier::LL;
                } else {
                    length = LengthModifier::L;
                }
            }
            'z' => {
                raw.push(chars.next().unwrap());
                length = LengthModifier::Z;
            }
            'j' => {
                raw.push(chars.next().unwrap());
                length = LengthModifier::J;
            }
            't' => {
                raw.push(chars.next().unwrap());
                length = LengthModifier::T;
            }
            'I' => {
                // Windows-specific I64, I32
                raw.push(chars.next().unwrap());
                if chars.peek() == Some(&'6') {
                    raw.push(chars.next().unwrap());
                    if chars.peek() == Some(&'4') {
                        raw.push(chars.next().unwrap());
                        length = LengthModifier::LL;
                    }
                } else if chars.peek() == Some(&'3') {
                    raw.push(chars.next().unwrap());
                    if chars.peek() == Some(&'2') {
                        raw.push(chars.next().unwrap());
                        length = LengthModifier::L;
                    }
                }
            }
            _ => {}
        }
    }

    // Parse conversion specifier
    let specifier = chars.next()?;
    raw.push(specifier);

    // Validate specifier
    if !"diouxXeEfFgGaAcspn%".contains(specifier) {
        return None;
    }

    Some(FormatSpec {
        raw,
        flags,
        width,
        precision,
        length,
        specifier,
    })
}

/// Format an argument according to a format specifier
pub fn format_arg(spec: &FormatSpec, arg: &FormatArg) -> String {
    match (spec.specifier, arg) {
        // Signed decimal integer
        ('d' | 'i', FormatArg::Int(n)) => format_integer(*n, spec, 10, true),
        ('d' | 'i', FormatArg::UInt(n)) => format_integer(*n as i64, spec, 10, true),
        
        // Unsigned integer
        ('u', FormatArg::Int(n)) => format_unsigned(*n as u64, spec, 10),
        ('u', FormatArg::UInt(n)) => format_unsigned(*n, spec, 10),
        
        // Unsigned octal
        ('o', FormatArg::Int(n)) => format_unsigned(*n as u64, spec, 8),
        ('o', FormatArg::UInt(n)) => format_unsigned(*n, spec, 8),
        
        // Unsigned hex (lowercase)
        ('x', FormatArg::Int(n)) => format_hex(*n as u64, spec, false),
        ('x', FormatArg::UInt(n)) => format_hex(*n, spec, false),
        
        // Unsigned hex (uppercase)
        ('X', FormatArg::Int(n)) => format_hex(*n as u64, spec, true),
        ('X', FormatArg::UInt(n)) => format_hex(*n, spec, true),
        
        // Floating point
        ('f' | 'F', FormatArg::Float(f)) => format_float(*f, spec, 'f'),
        ('e' | 'E', FormatArg::Float(f)) => format_float(*f, spec, 'e'),
        ('g' | 'G', FormatArg::Float(f)) => format_float(*f, spec, 'g'),
        
        // Character
        ('c', FormatArg::Char(c)) => format_char(*c, spec),
        ('c', FormatArg::Int(n)) => format_char((*n as u8) as char, spec),
        
        // String
        ('s', FormatArg::String(s)) => format_string(s, spec),
        
        // Pointer
        ('p', FormatArg::Pointer(p)) => format!("{:#x}", p),
        ('p', FormatArg::UInt(n)) => format!("{:#x}", n),
        
        // Default: just return the argument as string
        _ => format!("{:?}", arg),
    }
}

fn format_integer(n: i64, spec: &FormatSpec, base: u32, _signed: bool) -> String {
    let is_negative = n < 0;
    let abs_val = if is_negative { -(n as i128) as u64 } else { n as u64 };
    
    let mut result = match base {
        8 => format!("{:o}", abs_val),
        10 => format!("{}", abs_val),
        16 => format!("{:x}", abs_val),
        _ => format!("{}", abs_val),
    };
    
    // Add precision (minimum digits)
    if let Some(prec) = spec.precision {
        while result.len() < prec {
            result.insert(0, '0');
        }
    }
    
    // Add sign
    if is_negative {
        result.insert(0, '-');
    } else if spec.flags.sign_plus {
        result.insert(0, '+');
    } else if spec.flags.sign_space {
        result.insert(0, ' ');
    }
    
    // Apply width
    apply_width(&result, spec)
}

fn format_unsigned(n: u64, spec: &FormatSpec, base: u32) -> String {
    let mut result = match base {
        8 => format!("{:o}", n),
        10 => format!("{}", n),
        16 => format!("{:x}", n),
        _ => format!("{}", n),
    };
    
    // Add precision
    if let Some(prec) = spec.precision {
        while result.len() < prec {
            result.insert(0, '0');
        }
    }
    
    // Add alternate form prefix
    if spec.flags.alternate && n != 0 {
        match base {
            8 => { if !result.starts_with('0') { result.insert(0, '0'); } }
            16 => result.insert_str(0, "0x"),
            _ => {}
        }
    }
    
    apply_width(&result, spec)
}

fn format_hex(n: u64, spec: &FormatSpec, uppercase: bool) -> String {
    let mut result = if uppercase {
        format!("{:X}", n)
    } else {
        format!("{:x}", n)
    };
    
    // Add precision
    if let Some(prec) = spec.precision {
        while result.len() < prec {
            result.insert(0, '0');
        }
    }
    
    // Add alternate form prefix
    if spec.flags.alternate && n != 0 {
        if uppercase {
            result.insert_str(0, "0X");
        } else {
            result.insert_str(0, "0x");
        }
    }
    
    apply_width(&result, spec)
}

fn format_float(f: f64, spec: &FormatSpec, style: char) -> String {
    let precision = spec.precision.unwrap_or(6);
    
    let result = match style {
        'f' => format!("{:.prec$}", f, prec = precision),
        'e' => format!("{:.prec$e}", f, prec = precision),
        'g' => {
            // Use shortest representation
            let f_fmt = format!("{:.prec$}", f, prec = precision);
            let e_fmt = format!("{:.prec$e}", f, prec = precision);
            if f_fmt.len() <= e_fmt.len() { f_fmt } else { e_fmt }
        }
        _ => format!("{}", f),
    };
    
    apply_width(&result, spec)
}

fn format_char(c: char, spec: &FormatSpec) -> String {
    apply_width(&c.to_string(), spec)
}

fn format_string(s: &str, spec: &FormatSpec) -> String {
    let mut result = s.to_string();
    
    // Apply precision (max characters)
    if let Some(prec) = spec.precision {
        if result.len() > prec {
            result.truncate(prec);
        }
    }
    
    apply_width(&result, spec)
}

fn apply_width(s: &str, spec: &FormatSpec) -> String {
    let width = spec.width.unwrap_or(0);
    if s.len() >= width {
        return s.to_string();
    }
    
    let padding = width - s.len();
    let pad_char = if spec.flags.zero_pad && !spec.flags.left_justify { '0' } else { ' ' };
    
    if spec.flags.left_justify {
        format!("{}{}", s, pad_char.to_string().repeat(padding))
    } else {
        format!("{}{}", pad_char.to_string().repeat(padding), s)
    }
}

/// Format a string with the given arguments
pub fn sprintf(format: &str, args: &[FormatArg]) -> String {
    let parts = parse_format_string(format);
    let mut result = String::new();
    let mut arg_idx = 0;

    for part in parts {
        match part {
            FormatPart::Literal(s) => result.push_str(&s),
            FormatPart::Specifier(spec) => {
                if spec.specifier == 'n' {
                    // %n writes count - skip for safety
                    continue;
                }
                
                if let Some(arg) = args.get(arg_idx) {
                    result.push_str(&format_arg(&spec, arg));
                    arg_idx += 1;
                } else {
                    // Not enough arguments - append specifier as-is
                    result.push_str(&spec.raw);
                }
            }
        }
    }

    result
}

/// Extract a C string safely
pub unsafe fn extract_c_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string())
}

/// Extract a wide C string (UTF-16)
#[cfg(windows)]
pub unsafe fn extract_wide_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    
    // Find null terminator
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
        if len > 10000 { // Safety limit
            return None;
        }
    }
    
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16(slice).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_format_string() {
        let parts = parse_format_string("Hello %s, you have %d messages");
        assert_eq!(parts.len(), 5);
    }

    #[test]
    fn test_sprintf_string() {
        let result = sprintf("Hello %s!", &[FormatArg::String("World".to_string())]);
        assert_eq!(result, "Hello World!");
    }

    #[test]
    fn test_sprintf_int() {
        let result = sprintf("Count: %d", &[FormatArg::Int(42)]);
        assert_eq!(result, "Count: 42");
    }

    #[test]
    fn test_sprintf_hex() {
        let result = sprintf("Hex: 0x%08X", &[FormatArg::UInt(255)]);
        assert_eq!(result, "Hex: 0x000000FF");
    }

    #[test]
    fn test_sprintf_width() {
        let result = sprintf("[%10s]", &[FormatArg::String("test".to_string())]);
        assert_eq!(result, "[      test]");
        
        let result = sprintf("[%-10s]", &[FormatArg::String("test".to_string())]);
        assert_eq!(result, "[test      ]");
    }

    #[test]
    fn test_sprintf_precision() {
        let result = sprintf("%.3s", &[FormatArg::String("hello".to_string())]);
        assert_eq!(result, "hel");
    }

    #[test]
    fn test_sprintf_mixed() {
        let result = sprintf(
            "Process %s (PID: %d) at 0x%08X",
            &[
                FormatArg::String("notepad.exe".to_string()),
                FormatArg::Int(1234),
                FormatArg::UInt(0x7FFE0000),
            ]
        );
        assert_eq!(result, "Process notepad.exe (PID: 1234) at 0x7FFE0000");
    }
}

