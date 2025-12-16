//! Argument signature detection
//!
//! This module analyzes BOF code to detect the expected argument signature
//! by examining how the entry point function uses BeaconData* APIs.

use crate::core::models::bof::BofFile;
use crate::core::executor::arguments::ArgumentType;
use crate::core::utils::disasm::{disassemble_section, build_import_map};
use std::collections::HashMap;

/// Detected argument signature
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArgumentSignature {
    /// The detected signature string (e.g., "iizZ" for int, int, string, wide string)
    pub signature: String,
    /// Detailed argument types in order
    pub argument_types: Vec<ArgumentTypeInfo>,
    /// Confidence level (0.0 to 1.0)
    pub confidence: f64,
    /// Detection method used
    pub method: DetectionMethod,
    /// Additional notes about the detection
    pub notes: Vec<String>,
}

/// Information about a single argument
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArgumentTypeInfo {
    /// Argument type
    pub arg_type: ArgumentType,
    /// Position (0-based)
    pub position: usize,
    /// Description
    pub description: String,
}

/// Detection method
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DetectionMethod {
    /// Detected by analyzing disassembly
    Disassembly,
    /// Detected from imports/API usage patterns
    ApiPattern,
    /// Not detected (no signature found)
    Unknown,
}

/// Detect argument signature from BOF
pub fn detect_argument_signature(bof: &BofFile) -> ArgumentSignature {
    // Try to detect from disassembly first (most accurate)
    if let Some(sig) = detect_from_disassembly(bof) {
        return sig;
    }
    
    // Fallback to API pattern detection
    if let Some(sig) = detect_from_api_patterns(bof) {
        return sig;
    }
    
    // No signature detected
    ArgumentSignature {
        signature: String::new(),
        argument_types: vec![],
        confidence: 0.0,
        method: DetectionMethod::Unknown,
        notes: vec!["Could not detect argument signature. BOF may not use standard BeaconData* APIs.".to_string()],
    }
}

/// Detect signature by disassembling the entry point and analyzing BeaconData* calls
fn detect_from_disassembly(bof: &BofFile) -> Option<ArgumentSignature> {
    // Find entry point
    let entry_point = bof.entry_point.as_ref()?;
    
    // Find the section containing the entry point
    let section_idx = entry_point.section?;
    let section = bof.sections.get(section_idx)?;
    
    // Check if section is executable
    let is_code = section.characteristics & 0x00000020 != 0 // IMAGE_SCN_CNT_CODE
        || section.characteristics & 0x20000000 != 0; // IMAGE_SCN_MEM_EXECUTE
    
    if !is_code {
        return None;
    }
    
    // Get bitness
    let bitness = match bof.header.machine {
        crate::core::models::bof::MachineType::X64 => 64,
        crate::core::models::bof::MachineType::X86 => 32,
        crate::core::models::bof::MachineType::Unknown(_) => return None,
    };
    
    // Build symbol map
    let symbol_map = build_symbol_map(bof);
    
    // Build import map for resolving indirect API calls
    let import_map = build_import_map(bof);
    
    // Build relocation map: map section offset -> symbol index
    // For indirect calls, we need to check relocations in the code section
    let relocation_map = build_relocation_map(bof, section_idx);
    
    // Build import map: map symbol index -> function name
    let import_symbol_map: HashMap<u32, String> = bof.symbols.iter()
        .filter_map(|sym| {
            if sym.name.starts_with("__imp_") {
                let func_name = sym.name.strip_prefix("__imp_").unwrap_or(&sym.name);
                // Handle both __imp_Function and __imp_LIBRARY$Function formats
                let func_name = func_name.split('$').last().unwrap_or(func_name);
                Some((sym.coff_index as u32, func_name.to_string()))
            } else {
                None
            }
        })
        .collect();
    
    // Disassemble the section
    let result = disassemble_section(section, bitness, &symbol_map, &import_map);
    
    // Find the entry point function in the disassembly
    let entry_offset = entry_point.value as usize;
    
    // Extract instructions from entry point onwards
    // We'll look for a reasonable function size (up to 2000 bytes or until we hit a return)
    let mut entry_instructions = Vec::new();
    let mut found_entry = false;
    
    for instr in &result.instructions {
        let instr_offset = instr.address as usize;
        
        // Start collecting when we reach the entry point
        if !found_entry && instr_offset >= entry_offset {
            found_entry = true;
        }
        
        if found_entry {
            entry_instructions.push(instr.clone());
            
            // Stop at return instruction (end of function)
            // But only if we've collected at least a few instructions (avoid early returns)
            if instr.is_return && entry_instructions.len() > 10 {
                break;
            }
            
            // Also stop if we've gone too far (likely wrong function)
            if instr_offset > entry_offset + 2000 {
                break;
            }
        }
    }
    
    log::debug!("[SIG] Entry point at 0x{:x}, collected {} instructions", 
        entry_offset, entry_instructions.len());
    
    if entry_instructions.is_empty() {
        return None;
    }
    
    // Track calls with their addresses and identified function names
    #[derive(Debug, Clone)]
    struct CallInfo {
        address: u64,
        function_name: Option<String>,
    }
    
    let mut detected_calls: Vec<CallInfo> = Vec::new();
    let mut seen_call_addresses = std::collections::HashSet::new();
    
    // Analyze the instructions to find BeaconData* API calls
    let mut total_calls_found = 0;
    let mut calls_with_names = 0;
    
    for instr in &entry_instructions {
        if !instr.is_call {
            continue;
        }
        
        total_calls_found += 1;
        let mut function_name: Option<String> = None;
        
        // Method 1: Check comment (direct symbol reference)
        if let Some(ref comment) = instr.comment {
            if comment.contains("BeaconData") {
                // Extract function name from comment
                // Comment might be "__imp_BeaconDataExtract" or "BeaconDataExtract"
                let name = if comment.starts_with("__imp_") {
                    comment.strip_prefix("__imp_").unwrap_or(comment)
                } else {
                    comment
                };
                // Handle LIBRARY$Function format
                let name = name.split('$').last().unwrap_or(name);
                function_name = Some(name.to_string());
            }
        }
        
        // Method 2: Use relocation information to identify indirect calls
        if function_name.is_none() {
            let instr_addr = instr.address;
            let instr_len = instr.bytes.len() as u32;
            
            // For x64 indirect calls: "call qword ptr [rip+offset]"
            // The relocation is at the memory operand address (IAT slot), not the call instruction
            // The relocation address = instruction_address + instruction_length + RIP_offset
            // Since we don't know the exact offset, we'll check all relocations and find the closest one
            // that matches a BeaconData* function
            
            // Check all relocations in the code section and find the best match
            let mut best_match: Option<(u32, String)> = None;
            let mut best_distance = u32::MAX;
            
            // For RIP-relative calls, the relocation is typically after the instruction
            // Check a wide range: from instruction start to instruction + 8KB ahead
            let min_addr = instr_addr as u32;
            let max_addr = (instr_addr as u32).saturating_add(instr_len).saturating_add(8192);
            
            for (reloc_addr, symbol_idx) in relocation_map.iter() {
                // Only consider relocations that are after or at the instruction address
                // (RIP-relative relocations are always after the instruction)
                if *reloc_addr >= min_addr && *reloc_addr <= max_addr {
                    if let Some(func_name) = import_symbol_map.get(symbol_idx) {
                        if func_name.starts_with("BeaconData") {
                            // Calculate distance from instruction end
                            let instruction_end = (instr_addr as u32).saturating_add(instr_len);
                            let distance = if *reloc_addr >= instruction_end {
                                reloc_addr - instruction_end
                            } else {
                                instruction_end - reloc_addr
                            };
                            
                            // Prefer relocations that are reasonably close (within 4KB)
                            // This helps avoid false matches
                            if distance < 4096 && distance < best_distance {
                                best_distance = distance;
                                best_match = Some((*reloc_addr, func_name.clone()));
                            }
                        }
                    }
                }
            }
            
            if let Some((reloc_addr, func_name)) = best_match {
                log::debug!("[SIG] Matched call at 0x{:x} to relocation at 0x{:x} -> {}", 
                    instr_addr, reloc_addr, func_name);
                function_name = Some(func_name);
            }
            
            // Fallback: Check exact address and nearby addresses (for direct calls or edge cases)
            if function_name.is_none() {
                for offset in [0u32, 1, 2, 3, 4, 5, 6, 7, 8] {
                    let check_addr = (instr_addr as u32).saturating_sub(offset);
                    if let Some(symbol_idx) = relocation_map.get(&check_addr) {
                        if let Some(func_name) = import_symbol_map.get(symbol_idx) {
                            if func_name.starts_with("BeaconData") {
                                function_name = Some(func_name.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        // Method 3: Check instruction text for indirect call patterns
        if function_name.is_none() && instr.text.contains("call") {
            // For indirect calls like "call qword ptr [rip+0x1234]"
            // We can't directly identify the target, but we can check if there's
            // a relocation at the memory operand address
            // This is approximate - the actual target would require runtime analysis
        }
        
        if let Some(name) = function_name {
            calls_with_names += 1;
            // Only add if we haven't seen this address before (early deduplication)
            if !seen_call_addresses.contains(&instr.address) {
                seen_call_addresses.insert(instr.address);
                detected_calls.push(CallInfo {
                    address: instr.address,
                    function_name: Some(name),
                });
            }
        } else {
            log::debug!("[SIG] Call at 0x{:x} not identified: text='{}', comment={:?}", 
                instr.address, instr.text, instr.comment);
        }
    }
    
    log::debug!("[SIG] Entry point analysis: {} total calls, {} identified, {} with BeaconData* names", 
        total_calls_found, calls_with_names, 
        detected_calls.iter().filter(|c| c.function_name.as_ref().map(|n| n.contains("BeaconData")).unwrap_or(false)).count());
    log::debug!("[SIG] Relocation map has {} entries, import_symbol_map has {} entries", 
        relocation_map.len(), import_symbol_map.len());
    
    // Sort calls by address to preserve execution order
    detected_calls.sort_by_key(|c| c.address);
    
    // Deduplicate calls by address - same instruction address should only appear once
    // This prevents the same call from being counted multiple times if detected through
    // multiple methods (comment, relocation, etc.)
    let mut seen_addresses = std::collections::HashSet::new();
    let mut final_calls = Vec::new();
    for call in &detected_calls {
        if !seen_addresses.contains(&call.address) {
            seen_addresses.insert(call.address);
            final_calls.push(call.clone());
        }
    }
    
    // If we found BeaconDataParse, look for subsequent BeaconData* calls
    // The typical pattern is:
    // 1. BeaconDataParse(&parser, args, len)
    // 2. BeaconDataInt(&parser) -> 'i'
    // 3. BeaconDataShort(&parser) -> 's'
    // 4. BeaconDataExtract(&parser, size) -> 'z', 'Z', or 'b'
    
    let has_parse = final_calls.iter()
        .any(|c| c.function_name.as_ref().map(|n| n.contains("BeaconDataParse")).unwrap_or(false));
    
    if !has_parse {
        return None;
    }
    
    // Find the order of BeaconData* calls after BeaconDataParse
    let mut arg_types = Vec::new();
    let mut found_parse = false;
    
    for call in &final_calls {
        if let Some(ref func_name) = call.function_name {
            if func_name.contains("BeaconDataParse") {
                found_parse = true;
                continue;
            }
            
            if !found_parse {
                continue;
            }
            
            // Map API calls to argument types
            // Each call in final_calls is already unique by address, so we count each once
            if func_name.contains("BeaconDataInt") {
                arg_types.push(ArgumentType::Int32);
            } else if func_name.contains("BeaconDataShort") {
                arg_types.push(ArgumentType::Int16);
            } else if func_name.contains("BeaconDataExtract") {
                // BeaconDataExtract can be used for strings or binary data
                // We'll default to String (z) but note that it could be binary
                arg_types.push(ArgumentType::String);
            }
        }
    }
    
    if arg_types.is_empty() {
        return None;
    }
    
    // Build signature string
    let signature: String = arg_types.iter()
        .map(|t| t.as_char())
        .collect();
    
    // Build detailed argument info
    let argument_types: Vec<ArgumentTypeInfo> = arg_types.iter()
        .enumerate()
        .map(|(i, &arg_type)| {
            ArgumentTypeInfo {
                arg_type,
                position: i,
                description: format_argument_description(arg_type),
            }
        })
        .collect();
    
    // Debug: count how many calls we detected
    let total_beacon_calls = final_calls.iter()
        .filter(|c| c.function_name.as_ref().map(|n| n.contains("BeaconData")).unwrap_or(false))
        .count();
    
    // Debug: log what we found
    log::debug!("[SIG] Disassembly detection: found {} total calls, {} BeaconData* calls", 
        final_calls.len(), total_beacon_calls);
    for call in &final_calls {
        if let Some(ref name) = call.function_name {
            log::debug!("[SIG]   Call at 0x{:x}: {}", call.address, name);
        }
    }
    log::debug!("[SIG]   Signature: {} ({} args)", signature, arg_types.len());
    
    Some(ArgumentSignature {
        signature,
        argument_types,
        confidence: 0.85, // Higher confidence - we're tracking order and using relocations
        method: DetectionMethod::Disassembly,
        notes: vec![
            "Signature detected by analyzing disassembly of entry point function.".to_string(),
            format!("Found {} argument(s) after BeaconDataParse.", arg_types.len()),
            format!("Detected {} total BeaconData* call(s) in entry point.", total_beacon_calls),
            format!("Total {} call instruction(s) analyzed.", final_calls.len()),
            "Call order preserved using instruction addresses and relocation information.".to_string(),
        ],
    })
}

/// Build a map of section offsets to symbol indices from relocations
fn build_relocation_map(bof: &BofFile, section_idx: usize) -> HashMap<u32, u32> {
    let mut map = HashMap::new();
    
    for reloc in &bof.relocations {
        if reloc.section_index == section_idx {
            if let crate::core::models::bof::RelocationTarget::Symbol(sym_idx) = reloc.target {
                map.insert(reloc.virtual_address, sym_idx);
            }
        }
    }
    
    map
}

/// Detect signature from API usage patterns (imports)
fn detect_from_api_patterns(bof: &BofFile) -> Option<ArgumentSignature> {
    // Check if BOF uses BeaconDataParse
    let has_parse = bof.imports.iter()
        .any(|imp| imp.function == "BeaconDataParse");
    
    if !has_parse {
        return None;
    }
    
    // Count occurrences of each BeaconData* API
    // Use a HashSet to avoid double-counting the same function from both imports and symbols
    let mut seen_functions = std::collections::HashSet::new();
    let mut int_count = 0;
    let mut short_count = 0;
    let mut extract_count = 0;
    
    // First, count from imports list
    for imp in &bof.imports {
        match imp.function.as_str() {
            "BeaconDataInt" => {
                if seen_functions.insert("BeaconDataInt".to_string()) {
                    int_count += 1;
                }
            }
            "BeaconDataShort" => {
                if seen_functions.insert("BeaconDataShort".to_string()) {
                    short_count += 1;
                }
            }
            "BeaconDataExtract" => {
                if seen_functions.insert("BeaconDataExtract".to_string()) {
                    extract_count += 1;
                }
            }
            _ => {}
        }
    }
    
    // Also check symbols for __imp_ prefixed imports (they might not be in imports list)
    // Only count if we haven't seen this function already
    for sym in &bof.symbols {
        if sym.name.starts_with("__imp_") {
            let func_name = sym.name.strip_prefix("__imp_").unwrap_or(&sym.name);
            // Handle LIBRARY$Function format
            let func_name = func_name.split('$').last().unwrap_or(func_name);
            match func_name {
                "BeaconDataInt" => {
                    if seen_functions.insert("BeaconDataInt".to_string()) {
                        int_count += 1;
                    }
                }
                "BeaconDataShort" => {
                    if seen_functions.insert("BeaconDataShort".to_string()) {
                        short_count += 1;
                    }
                }
                "BeaconDataExtract" => {
                    if seen_functions.insert("BeaconDataExtract".to_string()) {
                        extract_count += 1;
                    }
                }
                _ => {}
            }
        }
    }
    
    // Build signature based on available APIs
    // Note: This is less accurate since we don't know the order
    // But we can at least count how many of each type
    let mut arg_types = Vec::new();
    let mut notes = Vec::new();
    
    // Add all detected argument types (we don't know order, so we'll list them)
    // Common pattern: strings first, then ints
    // So we'll put extracts first, then ints, then shorts
    for _ in 0..extract_count {
        arg_types.push(ArgumentType::String);
    }
    for _ in 0..int_count {
        arg_types.push(ArgumentType::Int32);
    }
    for _ in 0..short_count {
        arg_types.push(ArgumentType::Int16);
    }
    
    if extract_count > 0 {
        notes.push(format!("BeaconDataExtract detected {} time(s) - expects {} string/binary argument(s)", 
            extract_count, extract_count));
    }
    if int_count > 0 {
        notes.push(format!("BeaconDataInt detected {} time(s) - expects {} int32 argument(s)", 
            int_count, int_count));
    }
    if short_count > 0 {
        notes.push(format!("BeaconDataShort detected {} time(s) - expects {} int16 argument(s)", 
            short_count, short_count));
    }
    
    if arg_types.is_empty() {
        return None;
    }
    
    // Build signature (order is uncertain, so we'll list all types)
    let signature: String = arg_types.iter()
        .map(|t| t.as_char())
        .collect();
    
    let argument_types: Vec<ArgumentTypeInfo> = arg_types.iter()
        .enumerate()
        .map(|(i, &arg_type)| {
            ArgumentTypeInfo {
                arg_type,
                position: i,
                description: format_argument_description(arg_type),
            }
        })
        .collect();
    
    notes.push("Note: Argument order is uncertain - detected from API imports only. Actual order may differ.".to_string());
    notes.push("Warning: This method counts API imports, not actual calls. If the same API is called multiple times, it will only be counted once. Use disassembly-based detection for accurate results.".to_string());
    
    // Lower confidence when we have multiple of the same type (order is more uncertain)
    // Also lower confidence because we can't detect multiple calls to the same function
    let confidence = if extract_count > 1 || int_count > 1 || short_count > 1 {
        0.3 // Even lower confidence when we can't determine order
    } else {
        0.3 // Lower confidence - API pattern can't detect multiple calls to same function
    };
    
    Some(ArgumentSignature {
        signature,
        argument_types,
        confidence,
        method: DetectionMethod::ApiPattern,
        notes,
    })
}

/// Build symbol map for disassembly annotations
fn build_symbol_map(bof: &BofFile) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    
    for symbol in &bof.symbols {
        if !symbol.name.is_empty() {
            map.insert(symbol.value, symbol.name.clone());
        }
    }
    
    map
}

/// Format argument type description
fn format_argument_description(arg_type: ArgumentType) -> String {
    match arg_type {
        ArgumentType::String => "ANSI string (null-terminated, length-prefixed)".to_string(),
        ArgumentType::WideString => "Wide string (UTF-16LE, null-terminated, length-prefixed)".to_string(),
        ArgumentType::Int32 => "32-bit signed integer".to_string(),
        ArgumentType::Int16 => "16-bit signed integer".to_string(),
        ArgumentType::Binary => "Binary data (length-prefixed)".to_string(),
    }
}

