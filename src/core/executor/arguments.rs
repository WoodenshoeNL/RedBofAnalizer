//! Argument parsing and packing

#![allow(dead_code)]

use anyhow::{Result, Context};
use super::is_debug_mode;

/// Argument parsing mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentMode {
    /// Standard Beacon format (packed with length prefixes)
    Standard,
    /// Cobalt Strike compatible (simple strings as null-terminated)
    CobaltStrike,
}

/// Argument type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ArgumentType {
    String,      // z: null-terminated ANSI string
    WideString,  // Z: null-terminated wide string
    Int32,       // i: 32-bit integer
    Int16,       // s: 16-bit integer
    Binary,      // b: binary data (hex encoded)
}

impl ArgumentType {
    /// Parse from type character
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'z' => Some(ArgumentType::String),
            'Z' => Some(ArgumentType::WideString),
            'i' => Some(ArgumentType::Int32),
            's' => Some(ArgumentType::Int16),
            'b' => Some(ArgumentType::Binary),
            _ => None,
        }
    }
    
    /// Get type character
    pub fn as_char(self) -> char {
        match self {
            ArgumentType::String => 'z',
            ArgumentType::WideString => 'Z',
            ArgumentType::Int32 => 'i',
            ArgumentType::Int16 => 's',
            ArgumentType::Binary => 'b',
        }
    }
}

/// Parse argument signature string (e.g., "zis" means string, int32, int16)
pub fn parse_signature(sig: &str) -> Result<Vec<ArgumentType>> {
    sig.chars()
        .map(|c| ArgumentType::from_char(c)
            .ok_or_else(|| anyhow::anyhow!("Invalid argument type in signature: '{}'", c)))
        .collect()
}

/// Validate arguments match signature
pub fn validate_arguments(signature: &[ArgumentType], arg_str: &str) -> Result<()> {
    let parts: Vec<&str> = arg_str.split_whitespace().collect();
    
    if parts.len() != signature.len() {
        anyhow::bail!(
            "Argument count mismatch: expected {}, got {}",
            signature.len(),
            parts.len()
        );
    }
    
    for (i, (sig_type, part)) in signature.iter().zip(parts.iter()).enumerate() {
        // Allow empty strings: "z:" or "Z:" (type prefix + colon with no value)
        if part.len() < 2 || !part.contains(':') {
            anyhow::bail!("Invalid argument format at position {}: {}", i + 1, part);
        }
        
        let (arg_type_char, _) = part.split_at(1);
        let expected_char = sig_type.as_char();
        
        if arg_type_char.chars().next() != Some(expected_char) {
            anyhow::bail!(
                "Argument type mismatch at position {}: expected '{}', got '{}'",
                i + 1,
                expected_char,
                arg_type_char
            );
        }
    }
    
    Ok(())
}

/// Parse arguments in Cobalt Strike compatible mode
/// 
/// For simple cases (single string argument), passes as null-terminated string
/// For complex cases, falls back to standard packed format
pub fn parse_arguments_cs_compat(arg_str: &str) -> Result<Vec<u8>> {
    if arg_str.is_empty() {
        if is_debug_mode() {
            eprintln!("[ARGS-CS] No arguments provided");
        }
        return Ok(Vec::new());
    }
    
    if is_debug_mode() {
        eprintln!("[ARGS-CS] Parsing arguments (CS Compatible mode): {}", arg_str);
    }
    
    // Split into parts first to handle both simple strings and typed arguments
    let parts: Vec<&str> = arg_str.split_whitespace().collect();
    
    // Check if it's a simple case: single string argument without type prefix
    // Examples: "test", "hello world", "C:\\Windows"
    if parts.len() == 1 && !parts[0].contains(':') {
        // Simple string - pass as null-terminated
        let mut buffer = Vec::new();
        buffer.extend_from_slice(parts[0].as_bytes());
        buffer.push(0); // Null terminator
        if is_debug_mode() {
            eprintln!("[ARGS-CS] Simple string: \"{}\" -> {} bytes (null-terminated)", 
                parts[0], buffer.len());
        }
        return Ok(buffer);
    }
    
    // Check if it's a single typed string argument
    // Examples: "z:test", "Z:hello"
    if parts.len() == 1 {
        if let Some((type_char, value)) = parts[0].split_once(':') {
            match type_char {
                "z" => {
                    // ANSI string - pass as null-terminated (CS compatible)
                    let mut buffer = Vec::new();
                    buffer.extend_from_slice(value.as_bytes());
                    buffer.push(0);
                    if is_debug_mode() {
                        eprintln!("[ARGS-CS] ANSI string (z): \"{}\" -> {} bytes (null-terminated)", 
                            value, buffer.len());
                        eprintln!("[ARGS-CS] Extracted value from '{}': '{}'", parts[0], value);
                        eprintln!("[ARGS-CS] Buffer hex: {:02x?}", buffer);
                    }
                    return Ok(buffer);
                }
                "Z" => {
                    // Wide string - pass as null-terminated UTF-16LE
                    let utf16: Vec<u16> = value.encode_utf16().collect();
                    let mut buffer: Vec<u8> = utf16.iter()
                        .flat_map(|&c| c.to_le_bytes())
                        .collect();
                    buffer.extend_from_slice(&[0u8, 0u8]); // Null terminator
                    if is_debug_mode() {
                        eprintln!("[ARGS-CS] Wide string (Z): \"{}\" -> {} bytes (null-terminated UTF-16LE)", 
                            value, buffer.len());
                    }
                    return Ok(buffer);
                }
                _ => {
                    // Other types (i, s, b) - use standard packed format
                    if is_debug_mode() {
                        eprintln!("[ARGS-CS] Non-string type '{}', falling back to standard format", type_char);
                    }
                    return parse_arguments(arg_str);
                }
            }
        }
    }
    
    // Multiple arguments or complex format - use standard packed format
    if is_debug_mode() {
        eprintln!("[ARGS-CS] Multiple/complex arguments, falling back to standard format");
    }
    parse_arguments(arg_str)
}

/// Parse arguments with specified mode
pub fn parse_arguments_with_mode(arg_str: &str, mode: ArgumentMode) -> Result<Vec<u8>> {
    match mode {
        ArgumentMode::Standard => parse_arguments(arg_str),
        ArgumentMode::CobaltStrike => parse_arguments_cs_compat(arg_str),
    }
}

/// Parse arguments using a detected signature
/// 
/// This function automatically converts plain arguments to the correct types
/// based on the signature. For example, if signature is "zzii" and args are
/// "ntdll.dll EtwEventWrite 5 0", it will parse them as:
/// - z: "ntdll.dll"
/// - z: "EtwEventWrite"
/// - i: 5
/// - i: 0
pub fn parse_arguments_with_signature(arg_str: &str, signature: &str) -> Result<Vec<u8>> {
    if arg_str.is_empty() {
        if is_debug_mode() {
            eprintln!("[ARGS] No arguments provided");
        }
        return Ok(Vec::new());
    }
    
    if is_debug_mode() {
        eprintln!("[ARGS] Parsing arguments with signature '{}': {}", signature, arg_str);
    }
    
    // Parse the signature
    let sig_types = parse_signature(signature)?;
    
    // Split arguments
    let parts: Vec<&str> = arg_str.split_whitespace().collect();
    
    // Validate argument count
    if parts.len() != sig_types.len() {
        anyhow::bail!(
            "Argument count mismatch: signature '{}' expects {} arguments, but got {}",
            signature,
            sig_types.len(),
            parts.len()
        );
    }
    
    let mut buffer = Vec::new();
    
    // Parse each argument according to its signature type
    for (idx, (arg_type, value)) in sig_types.iter().zip(parts.iter()).enumerate() {
        if is_debug_mode() {
            eprintln!("[ARGS]   [{}] Parsing as {:?}: \"{}\"", idx, arg_type, value);
        }
        
        match arg_type {
            ArgumentType::String => {
                // Null-terminated string with length prefix
                let bytes = value.as_bytes();
                let len = bytes.len() + 1; // Length includes null terminator
                buffer.extend_from_slice(&(len as u32).to_le_bytes());
                buffer.extend_from_slice(bytes);
                buffer.push(0); // Null terminator
                if is_debug_mode() {
                    eprintln!("[ARGS]   [{}] String (z): \"{}\" -> {} bytes (len={})", 
                        idx, value, len, len);
                }
            }
            ArgumentType::WideString => {
                // Null-terminated wide string with length prefix
                let utf16: Vec<u16> = value.encode_utf16().collect();
                let wide_bytes: Vec<u8> = utf16.iter().flat_map(|&c| c.to_le_bytes()).collect();
                let len = wide_bytes.len() + 2; // Length includes null terminator (2 bytes for wide char)
                buffer.extend_from_slice(&(len as u32).to_le_bytes());
                buffer.extend_from_slice(&wide_bytes);
                buffer.extend_from_slice(&[0u8, 0u8]); // Null terminator
                if is_debug_mode() {
                    eprintln!("[ARGS]   [{}] Wide String (Z): \"{}\" -> {} bytes (len={})", 
                        idx, value, len + 2, len);
                }
            }
            ArgumentType::Int32 => {
                // 32-bit integer
                let num: i32 = value.parse()
                    .context(format!("Invalid integer '{}' at position {} (expected int32)", value, idx + 1))?;
                buffer.extend_from_slice(&num.to_le_bytes());
                if is_debug_mode() {
                    eprintln!("[ARGS]   [{}] Int32 (i): {} -> 0x{:08x} (4 bytes)", 
                        idx, num, num as u32);
                }
            }
            ArgumentType::Int16 => {
                // 16-bit integer
                let num: i16 = value.parse()
                    .context(format!("Invalid short '{}' at position {} (expected int16)", value, idx + 1))?;
                buffer.extend_from_slice(&num.to_le_bytes());
                if is_debug_mode() {
                    eprintln!("[ARGS]   [{}] Int16 (s): {} -> 0x{:04x} (2 bytes)", 
                        idx, num, num as u16);
                }
            }
            ArgumentType::Binary => {
                // Binary data (hex encoded)
                let hex_bytes = hex::decode(value)
                    .context(format!("Invalid hex data '{}' at position {} (expected binary)", value, idx + 1))?;
                // Prepend length (4 bytes)
                buffer.extend_from_slice(&(hex_bytes.len() as u32).to_le_bytes());
                buffer.extend_from_slice(&hex_bytes);
                if is_debug_mode() {
                    eprintln!("[ARGS]   [{}] Binary (b): {} -> {} bytes (hex: {})", 
                        idx, value, hex_bytes.len() + 4, 
                        hex_bytes.iter().take(32).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
                }
            }
        }
    }
    
    if is_debug_mode() {
        eprintln!("[ARGS] Packed {} arguments into {} bytes total", parts.len(), buffer.len());
        eprintln!("[ARGS] Buffer hex (first 64 bytes): {}", 
            buffer.iter().take(64).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
    }
    
    Ok(buffer)
}

/// Parse argument format string and pack into Beacon format
/// 
/// Format: "z:string i:123 s:456 b:hexdata"
/// Types:
/// - z: null-terminated string
/// - Z: null-terminated wide string  
/// - i: 32-bit integer
/// - s: 16-bit integer
/// - b: binary data (hex encoded)
/// 
/// Also supports simple strings without type prefix (treats as z:)
pub fn parse_arguments(arg_str: &str) -> Result<Vec<u8>> {
    if arg_str.is_empty() {
        if is_debug_mode() {
            eprintln!("[ARGS] No arguments provided");
        }
        return Ok(Vec::new());
    }
    
    if is_debug_mode() {
        eprintln!("[ARGS] Parsing arguments: {}", arg_str);
    }
    
    let mut buffer = Vec::new();
    let parts: Vec<&str> = arg_str.split_whitespace().collect();
    
    for (idx, part) in parts.iter().enumerate() {
        // Handle simple strings without type prefix (treat as z:)
        let (arg_type_char, value) = if !part.contains(':') {
            // Simple string without prefix - treat as z: (ANSI string)
            if is_debug_mode() {
                eprintln!("[ARGS]   [{}] Simple string without prefix, treating as z:", idx);
            }
            ('z', *part)
        } else if part.len() < 2 {
            anyhow::bail!("Invalid argument format: {}", part);
        } else {
            // Parse type:value format
            if part.chars().nth(1) != Some(':') {
                anyhow::bail!("Invalid argument format: missing colon in {}", part);
            }
            
            let arg_type_char = part.chars().next()
                .ok_or_else(|| anyhow::anyhow!("Empty argument type in {}", part))?;
            let value = if part.len() > 2 {
                &part[2..] // Skip type char and colon
            } else {
                "" // Empty string when just "z:" or "Z:"
            };
            (arg_type_char, value)
        };
        
        match arg_type_char {
            'z' => {
                // Null-terminated string with length prefix
                // BeaconDataExtract expects length-prefixed data
                let bytes = value.as_bytes();
                let len = bytes.len() + 1; // Length includes null terminator
                buffer.extend_from_slice(&(len as u32).to_le_bytes());
                buffer.extend_from_slice(bytes);
                buffer.push(0); // Null terminator
                if is_debug_mode() {
                    eprintln!("[ARGS]   [{}] String (z): \"{}\" -> {} bytes (len={})", 
                        idx, value, len, len);
                }
            }
            'Z' => {
                // Null-terminated wide string with length prefix
                // BeaconDataExtract expects length-prefixed data
                let utf16: Vec<u16> = value.encode_utf16().collect();
                let wide_bytes: Vec<u8> = utf16.iter().flat_map(|&c| c.to_le_bytes()).collect();
                let len = wide_bytes.len() + 2; // Length includes null terminator (2 bytes for wide char)
                buffer.extend_from_slice(&(len as u32).to_le_bytes());
                buffer.extend_from_slice(&wide_bytes);
                buffer.extend_from_slice(&[0u8, 0u8]); // Null terminator
                if is_debug_mode() {
                    eprintln!("[ARGS]   [{}] Wide String (Z): \"{}\" -> {} bytes (len={})", 
                        idx, value, len + 2, len);
                }
            }
            'i' => {
                // 32-bit integer
                let num: i32 = value.parse()
                    .context(format!("Invalid integer '{}' in argument: {}", value, part))?;
                buffer.extend_from_slice(&num.to_le_bytes());
                if is_debug_mode() {
                    eprintln!("[ARGS]   [{}] Int32 (i): {} -> 0x{:08x} (4 bytes)", 
                        idx, num, num as u32);
                }
            }
            's' => {
                // 16-bit integer
                let num: i16 = value.parse()
                    .context(format!("Invalid short '{}' in argument: {}", value, part))?;
                buffer.extend_from_slice(&num.to_le_bytes());
                if is_debug_mode() {
                    eprintln!("[ARGS]   [{}] Int16 (s): {} -> 0x{:04x} (2 bytes)", 
                        idx, num, num as u16);
                }
            }
            'b' => {
                // Binary data (hex encoded)
                let hex_bytes = hex::decode(value)
                    .context(format!("Invalid hex data '{}' in argument: {}", value, part))?;
                // Prepend length (4 bytes)
                buffer.extend_from_slice(&(hex_bytes.len() as u32).to_le_bytes());
                buffer.extend_from_slice(&hex_bytes);
                if is_debug_mode() {
                    eprintln!("[ARGS]   [{}] Binary (b): {} -> {} bytes (hex: {})", 
                        idx, value, hex_bytes.len() + 4, 
                        hex_bytes.iter().take(32).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
                }
            }
            _ => {
                anyhow::bail!("Unknown argument type '{}' in argument: {}", arg_type_char, part);
            }
        }
    }
    
    if is_debug_mode() {
        eprintln!("[ARGS] Packed {} arguments into {} bytes total", parts.len(), buffer.len());
        eprintln!("[ARGS] Buffer hex (first 64 bytes): {}", 
            buffer.iter().take(64).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
    }
    
    Ok(buffer)
}
