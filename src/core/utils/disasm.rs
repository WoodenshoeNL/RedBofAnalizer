//! Disassembly utilities
//!
//! This module provides disassembly support for BOF analysis using iced-x86.
//! It can disassemble code sections and provide instruction-level analysis.

#![allow(dead_code)]

use crate::core::models::bof::{BofFile, MachineType, Section};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, Mnemonic};
use std::collections::HashMap;

/// Disassembly result for a section
#[derive(Debug, Clone, serde::Serialize)]
pub struct DisassemblyResult {
    /// Section name
    pub section_name: String,
    /// Architecture
    pub architecture: String,
    /// Disassembled instructions
    pub instructions: Vec<DisassembledInstruction>,
    /// Function boundaries detected
    pub functions: Vec<FunctionInfo>,
    /// API calls detected
    pub api_calls: Vec<ApiCallInfo>,
    /// Statistics
    pub stats: DisassemblyStats,
}

/// A single disassembled instruction
#[derive(Debug, Clone, serde::Serialize)]
pub struct DisassembledInstruction {
    /// Address/offset
    pub address: u64,
    /// Raw bytes
    pub bytes: Vec<u8>,
    /// Mnemonic (instruction name)
    pub mnemonic: String,
    /// Full instruction text
    pub text: String,
    /// Is this a call instruction
    pub is_call: bool,
    /// Is this a jump instruction
    pub is_jump: bool,
    /// Is this a return instruction
    pub is_return: bool,
    /// Optional comment/annotation
    pub comment: Option<String>,
}

/// Function boundary information
#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionInfo {
    /// Function name (if known)
    pub name: Option<String>,
    /// Start address
    pub start_address: u64,
    /// End address (estimated)
    pub end_address: u64,
    /// Size in bytes
    pub size: usize,
    /// Number of instructions
    pub instruction_count: usize,
}

/// API call information
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiCallInfo {
    /// Address of the call instruction
    pub address: u64,
    /// Target address or symbol
    pub target: String,
    /// Is it a direct or indirect call
    pub call_type: CallType,
}

/// Call type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CallType {
    Direct,
    Indirect,
    Register,
}

/// Disassembly statistics
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DisassemblyStats {
    /// Total instructions
    pub total_instructions: usize,
    /// Call instructions
    pub call_count: usize,
    /// Jump instructions
    pub jump_count: usize,
    /// Return instructions
    pub return_count: usize,
    /// NOP instructions
    pub nop_count: usize,
    /// Invalid/unknown instructions
    pub invalid_count: usize,
    /// Unique mnemonics
    pub unique_mnemonics: usize,
}

/// Disassemble a BOF file
pub fn disassemble_bof(bof: &BofFile) -> Vec<DisassemblyResult> {
    let mut results = Vec::new();
    
    // Get architecture
    let bitness = match bof.header.machine {
        MachineType::X64 => 64,
        MachineType::X86 => 32,
        MachineType::Unknown(_) => return results, // Can't disassemble unknown arch
    };
    
    // Build symbol map for annotations
    let symbol_map = build_symbol_map(bof);
    
    // Build import address map for resolving indirect API calls
    let import_map = build_import_map(bof);
    
    // Disassemble code sections
    for section in &bof.sections {
        // Check if section is executable
        let is_code = section.characteristics & 0x00000020 != 0 // IMAGE_SCN_CNT_CODE
            || section.characteristics & 0x20000000 != 0; // IMAGE_SCN_MEM_EXECUTE
        
        if is_code && !section.data.is_empty() {
            let result = disassemble_section(section, bitness, &symbol_map, &import_map);
            results.push(result);
        }
    }
    
    results
}

/// Disassemble a single section
pub fn disassemble_section(
    section: &Section,
    bitness: u32,
    symbol_map: &HashMap<u64, String>,
    import_map: &HashMap<u64, String>,
) -> DisassemblyResult {
    let mut instructions = Vec::new();
    let mut api_calls = Vec::new();
    let mut stats = DisassemblyStats::default();
    let mut mnemonic_set = std::collections::HashSet::new();
    
    // Create decoder
    let decoder_opts = DecoderOptions::NONE;
    let mut decoder = Decoder::with_ip(bitness, &section.data, 0, decoder_opts);
    
    // Create formatter
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_uppercase_mnemonics(false);
    formatter.options_mut().set_space_after_operand_separator(true);
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    
    let mut output = String::new();
    let mut instruction = Instruction::default();
    
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        
        // Format instruction
        output.clear();
        formatter.format(&instruction, &mut output);
        
        // Get raw bytes
        let start = instruction.ip() as usize;
        let len = instruction.len();
        let bytes = if start + len <= section.data.len() {
            section.data[start..start + len].to_vec()
        } else {
            vec![]
        };
        
        // Determine instruction properties
        let mnemonic = instruction.mnemonic();
        let mnemonic_str = format!("{:?}", mnemonic).to_lowercase();
        mnemonic_set.insert(mnemonic_str.clone());
        
        let is_call = matches!(mnemonic, Mnemonic::Call);
        let is_jump = matches!(
            mnemonic,
            Mnemonic::Jmp | Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jg | Mnemonic::Jge |
            Mnemonic::Jl | Mnemonic::Jle | Mnemonic::Ja | Mnemonic::Jae | Mnemonic::Jb |
            Mnemonic::Jbe | Mnemonic::Jo | Mnemonic::Jno | Mnemonic::Js | Mnemonic::Jns |
            Mnemonic::Jp | Mnemonic::Jnp | Mnemonic::Jecxz | Mnemonic::Jrcxz | Mnemonic::Loop |
            Mnemonic::Loope | Mnemonic::Loopne
        );
        let is_return = matches!(mnemonic, Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq);
        let is_nop = matches!(mnemonic, Mnemonic::Nop);
        let is_invalid = mnemonic == Mnemonic::INVALID;
        
        // Update stats
        stats.total_instructions += 1;
        if is_call { stats.call_count += 1; }
        if is_jump { stats.jump_count += 1; }
        if is_return { stats.return_count += 1; }
        if is_nop { stats.nop_count += 1; }
        if is_invalid { stats.invalid_count += 1; }
        
        // Generate comment/annotation
        let comment = symbol_map.get(&instruction.ip()).cloned();
        
        // Track API calls
        if is_call {
            let call_info = analyze_call(&instruction, symbol_map, import_map);
            if let Some(info) = call_info {
                api_calls.push(info);
            }
        }
        
        instructions.push(DisassembledInstruction {
            address: instruction.ip(),
            bytes,
            mnemonic: mnemonic_str,
            text: output.clone(),
            is_call,
            is_jump,
            is_return,
            comment,
        });
    }
    
    stats.unique_mnemonics = mnemonic_set.len();
    
    // Detect function boundaries
    let functions = detect_functions(&instructions, symbol_map);
    
    DisassemblyResult {
        section_name: section.name.clone(),
        architecture: if bitness == 64 { "x64".to_string() } else { "x86".to_string() },
        instructions,
        functions,
        api_calls,
        stats,
    }
}

/// Disassemble a specific range of bytes
pub fn disassemble_bytes(bytes: &[u8], bitness: u32, base_address: u64) -> Vec<DisassembledInstruction> {
    let mut instructions = Vec::new();
    
    let decoder_opts = DecoderOptions::NONE;
    let mut decoder = Decoder::with_ip(bitness, bytes, base_address, decoder_opts);
    
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_uppercase_mnemonics(false);
    formatter.options_mut().set_space_after_operand_separator(true);
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    
    let mut output = String::new();
    let mut instruction = Instruction::default();
    
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        
        output.clear();
        formatter.format(&instruction, &mut output);
        
        let start = (instruction.ip() - base_address) as usize;
        let len = instruction.len();
        let raw_bytes = if start + len <= bytes.len() {
            bytes[start..start + len].to_vec()
        } else {
            vec![]
        };
        
        let mnemonic = instruction.mnemonic();
        let mnemonic_str = format!("{:?}", mnemonic).to_lowercase();
        
        let is_call = matches!(mnemonic, Mnemonic::Call);
        let is_jump = matches!(
            mnemonic,
            Mnemonic::Jmp | Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jg | Mnemonic::Jge |
            Mnemonic::Jl | Mnemonic::Jle | Mnemonic::Ja | Mnemonic::Jae | Mnemonic::Jb |
            Mnemonic::Jbe | Mnemonic::Jo | Mnemonic::Jno | Mnemonic::Js | Mnemonic::Jns |
            Mnemonic::Jp | Mnemonic::Jnp | Mnemonic::Jecxz | Mnemonic::Jrcxz | Mnemonic::Loop |
            Mnemonic::Loope | Mnemonic::Loopne
        );
        let is_return = matches!(mnemonic, Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq);
        
        instructions.push(DisassembledInstruction {
            address: instruction.ip(),
            bytes: raw_bytes,
            mnemonic: mnemonic_str,
            text: output.clone(),
            is_call,
            is_jump,
            is_return,
            comment: None,
        });
    }
    
    instructions
}

/// Build a symbol map for annotations
fn build_symbol_map(bof: &BofFile) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    
    for symbol in &bof.symbols {
        if !symbol.name.is_empty() {
            map.insert(symbol.value, symbol.name.clone());
        }
    }
    
    map
}

/// Build a map from addresses to import API names (for resolving indirect calls)
pub fn build_import_map(bof: &BofFile) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    
    // Build a map from import symbol names to their API names
    let mut symbol_to_api: HashMap<String, String> = HashMap::new();
    for import in &bof.imports {
        // Format: LIBRARY!Function
        let api_name = format!("{}!{}", import.library, import.function);
        symbol_to_api.insert(import.symbol_name.clone(), api_name);
    }
    
    // Map symbol addresses to API names
    for symbol in &bof.symbols {
        // Check if this symbol is an import symbol (starts with __imp_)
        if symbol.name.starts_with("__imp_") {
            if let Some(api_name) = symbol_to_api.get(&symbol.name) {
                map.insert(symbol.value, api_name.clone());
            }
        }
    }
    
    map
}

/// Analyze a call instruction
fn analyze_call(
    instruction: &Instruction, 
    symbol_map: &HashMap<u64, String>,
    import_map: &HashMap<u64, String>,
) -> Option<ApiCallInfo> {
    use iced_x86::OpKind;
    
    if instruction.op_count() == 0 {
        return None;
    }
    
    let op_kind = instruction.op0_kind();
    
    let (target, call_type) = match op_kind {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 |
        OpKind::FarBranch16 | OpKind::FarBranch32 => {
            let target_addr = instruction.near_branch_target();
            let target_name = symbol_map.get(&target_addr)
                .cloned()
                .unwrap_or_else(|| format!("0x{:X}", target_addr));
            (target_name, CallType::Direct)
        }
        OpKind::Memory => {
            // Indirect call through memory - try to resolve to API name
            let mem_disp = instruction.memory_displacement64();
            
            // For x64, memory operands are typically RIP-relative
            // Calculate the actual address: next_instruction + displacement
            let next_ip = instruction.ip() + instruction.len() as u64;
            let calculated_addr = next_ip.wrapping_add(mem_disp as i64 as u64);
            
            // Try to resolve using the calculated address (RIP-relative)
            let resolved = import_map.get(&calculated_addr)
                .or_else(|| {
                    // Also try the raw displacement (in case it's already absolute)
                    import_map.get(&mem_disp)
                });
            
            if let Some(api_name) = resolved {
                (api_name.clone(), CallType::Indirect)
            } else {
                // Fallback to showing the address
                let target = format!("[0x{:X}]", mem_disp);
                (target, CallType::Indirect)
            }
        }
        OpKind::Register => {
            let reg = instruction.op0_register();
            let target = format!("{:?}", reg).to_lowercase();
            (target, CallType::Register)
        }
        _ => return None,
    };
    
    Some(ApiCallInfo {
        address: instruction.ip(),
        target,
        call_type,
    })
}

/// Detect function boundaries
fn detect_functions(
    instructions: &[DisassembledInstruction],
    symbol_map: &HashMap<u64, String>,
) -> Vec<FunctionInfo> {
    let mut functions = Vec::new();
    
    if instructions.is_empty() {
        return functions;
    }
    
    // Find known function entry points from symbols
    let mut entry_points: Vec<u64> = symbol_map.iter()
        .filter(|(_, name)| !name.starts_with("__imp_") && !name.starts_with("$"))
        .map(|(addr, _)| *addr)
        .collect();
    entry_points.sort();
    
    // Also detect function starts by looking for typical prologue patterns
    // (push rbp; mov rbp, rsp) or (sub rsp, ...)
    for (i, instr) in instructions.iter().enumerate() {
        if instr.mnemonic == "push" && instr.text.contains("rbp") {
            // Check if next instruction is mov rbp, rsp
            if i + 1 < instructions.len() {
                let next = &instructions[i + 1];
                if next.mnemonic == "mov" && next.text.contains("rbp") && next.text.contains("rsp") {
                    if !entry_points.contains(&instr.address) {
                        entry_points.push(instr.address);
                    }
                }
            }
        }
    }
    entry_points.sort();
    entry_points.dedup();
    
    // Build function info for each entry point
    for (i, &start_addr) in entry_points.iter().enumerate() {
        // Find the end (next function start or last return)
        let end_addr = if i + 1 < entry_points.len() {
            entry_points[i + 1]
        } else {
            // Find last instruction address
            instructions.last().map(|i| i.address + i.bytes.len() as u64).unwrap_or(start_addr)
        };
        
        // Count instructions in this function
        let instruction_count = instructions.iter()
            .filter(|i| i.address >= start_addr && i.address < end_addr)
            .count();
        
        let name = symbol_map.get(&start_addr).cloned();
        
        if instruction_count > 0 {
            functions.push(FunctionInfo {
                name,
                start_address: start_addr,
                end_address: end_addr,
                size: (end_addr - start_addr) as usize,
                instruction_count,
            });
        }
    }
    
    functions
}

/// Format disassembly as text
pub fn format_disassembly_text(result: &DisassemblyResult, max_instructions: Option<usize>) -> String {
    let mut output = String::new();
    
    output.push_str(&format!("=== Disassembly: {} ({}) ===\n\n", result.section_name, result.architecture));
    output.push_str(&format!("Instructions: {} | Calls: {} | Jumps: {} | Returns: {}\n",
        result.stats.total_instructions,
        result.stats.call_count,
        result.stats.jump_count,
        result.stats.return_count
    ));
    
    if !result.functions.is_empty() {
        output.push_str(&format!("Functions detected: {}\n", result.functions.len()));
    }
    output.push_str("\n");
    
    // Print functions
    if !result.functions.is_empty() {
        output.push_str("Functions:\n");
        for func in &result.functions {
            let name = func.name.as_deref().unwrap_or("<unknown>");
            output.push_str(&format!("  0x{:08X} {} ({} bytes, {} instructions)\n",
                func.start_address, name, func.size, func.instruction_count));
        }
        output.push_str("\n");
    }
    
    // Print instructions
    output.push_str("Instructions:\n");
    let limit = max_instructions.unwrap_or(result.instructions.len());
    
    for (i, instr) in result.instructions.iter().take(limit).enumerate() {
        // Format bytes
        let bytes_str: String = instr.bytes.iter()
            .take(8)
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        
        let bytes_padded = format!("{:<24}", bytes_str);
        
        // Address and instruction
        output.push_str(&format!("  0x{:08X}: {} {}", instr.address, bytes_padded, instr.text));
        
        // Add comment if present
        if let Some(ref comment) = instr.comment {
            output.push_str(&format!("  ; {}", comment));
        }
        
        // Mark special instructions
        if instr.is_call {
            output.push_str("  <-- CALL");
        } else if instr.is_return {
            output.push_str("  <-- RET");
        }
        
        output.push_str("\n");
        
        // Indicate truncation
        if i + 1 == limit && limit < result.instructions.len() {
            output.push_str(&format!("\n... {} more instructions ...\n", 
                result.instructions.len() - limit));
        }
    }
    
    output
}

/// Format disassembly as markdown
pub fn format_disassembly_markdown(result: &DisassemblyResult, max_instructions: Option<usize>) -> String {
    let mut output = String::new();
    
    output.push_str(&format!("## Disassembly: `{}` ({})\n\n", result.section_name, result.architecture));
    
    // Stats
    output.push_str("### Statistics\n\n");
    output.push_str("| Metric | Value |\n");
    output.push_str("|--------|-------|\n");
    output.push_str(&format!("| Total Instructions | {} |\n", result.stats.total_instructions));
    output.push_str(&format!("| Call Instructions | {} |\n", result.stats.call_count));
    output.push_str(&format!("| Jump Instructions | {} |\n", result.stats.jump_count));
    output.push_str(&format!("| Return Instructions | {} |\n", result.stats.return_count));
    output.push_str(&format!("| NOP Instructions | {} |\n", result.stats.nop_count));
    output.push_str(&format!("| Unique Mnemonics | {} |\n", result.stats.unique_mnemonics));
    output.push_str("\n");
    
    // Functions
    if !result.functions.is_empty() {
        output.push_str("### Functions\n\n");
        output.push_str("| Address | Name | Size | Instructions |\n");
        output.push_str("|---------|------|------|-------------|\n");
        for func in &result.functions {
            let name = func.name.as_deref().unwrap_or("<unknown>");
            output.push_str(&format!("| `0x{:08X}` | `{}` | {} | {} |\n",
                func.start_address, name, func.size, func.instruction_count));
        }
        output.push_str("\n");
    }
    
    // API Calls
    if !result.api_calls.is_empty() {
        output.push_str("### API Calls\n\n");
        output.push_str("| Address | Target | Type |\n");
        output.push_str("|---------|--------|------|\n");
        for call in &result.api_calls {
            let call_type = match call.call_type {
                CallType::Direct => "Direct",
                CallType::Indirect => "Indirect",
                CallType::Register => "Register",
            };
            output.push_str(&format!("| `0x{:08X}` | `{}` | {} |\n",
                call.address, call.target, call_type));
        }
        output.push_str("\n");
    }
    
    // Instructions
    output.push_str("### Instructions\n\n");
    output.push_str("```asm\n");
    
    let limit = max_instructions.unwrap_or(result.instructions.len());
    
    for (i, instr) in result.instructions.iter().take(limit).enumerate() {
        let bytes_str: String = instr.bytes.iter()
            .take(8)
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        
        output.push_str(&format!("0x{:08X}: {:24} {}", instr.address, bytes_str, instr.text));
        
        if let Some(ref comment) = instr.comment {
            output.push_str(&format!("  ; {}", comment));
        }
        
        output.push_str("\n");
        
        if i + 1 == limit && limit < result.instructions.len() {
            output.push_str(&format!("\n; ... {} more instructions ...\n", 
                result.instructions.len() - limit));
        }
    }
    
    output.push_str("```\n");
    
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_disassemble_bytes() {
        // Simple x64 code: push rbp; mov rbp, rsp; pop rbp; ret
        let code = vec![0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3];
        let result = disassemble_bytes(&code, 64, 0);
        
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].mnemonic, "push");
        assert_eq!(result[1].mnemonic, "mov");
        assert_eq!(result[2].mnemonic, "pop");
        assert_eq!(result[3].mnemonic, "ret");
        assert!(result[3].is_return);
    }
    
    #[test]
    fn test_call_detection() {
        // call instruction: E8 00 00 00 00 (call $+5)
        let code = vec![0xE8, 0x00, 0x00, 0x00, 0x00];
        let result = disassemble_bytes(&code, 64, 0);
        
        assert_eq!(result.len(), 1);
        assert!(result[0].is_call);
    }
}
