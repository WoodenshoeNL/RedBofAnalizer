//! Stack usage analysis module
//!
//! This module analyzes stack usage in BOF functions by examining disassembly
//! to estimate stack frame sizes and detect potential stack overflows.

use crate::core::models::bof::BofFile;
use crate::core::utils::disasm::{disassemble_bof, DisassembledInstruction};

/// Stack usage analysis result
#[derive(Debug, Clone, serde::Serialize)]
pub struct StackAnalysis {
    /// Stack usage per function
    pub function_stack_usage: Vec<FunctionStackUsage>,
    /// Potential stack overflow warnings
    pub warnings: Vec<StackWarning>,
    /// Overall statistics
    pub stats: StackStats,
}

/// Stack usage for a specific function
#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionStackUsage {
    /// Function name (if known)
    pub function_name: Option<String>,
    /// Function start address
    pub start_address: u64,
    /// Estimated stack frame size (in bytes)
    pub estimated_stack_size: usize,
    /// Maximum stack usage detected
    pub max_stack_usage: usize,
    /// Stack operations detected
    pub stack_operations: Vec<StackOperation>,
    /// Risk level for this function
    pub risk_level: StackRiskLevel,
}

/// Stack operation detected in disassembly
#[derive(Debug, Clone, serde::Serialize)]
pub struct StackOperation {
    /// Address of the instruction
    pub address: u64,
    /// Instruction text
    pub instruction: String,
    /// Operation type
    pub operation_type: StackOpType,
    /// Stack offset change (positive = allocate, negative = deallocate)
    pub stack_delta: i64,
    /// Current estimated stack usage after this operation
    pub current_stack_usage: usize,
}

/// Type of stack operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum StackOpType {
    /// Function prologue (push rbp, mov rbp, rsp)
    Prologue,
    /// Stack allocation (sub rsp, imm)
    Allocation,
    /// Stack deallocation (add rsp, imm)
    Deallocation,
    /// Push operation
    Push,
    /// Pop operation
    Pop,
    /// Function call (uses stack for return address)
    Call,
    /// Function epilogue (mov rsp, rbp; pop rbp)
    Epilogue,
}

/// Stack risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum StackRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Stack warning
#[derive(Debug, Clone, serde::Serialize)]
pub struct StackWarning {
    /// Warning severity
    pub severity: StackWarningSeverity,
    /// Function name (if known)
    pub function_name: Option<String>,
    /// Address where warning occurs
    pub address: u64,
    /// Warning message
    pub message: String,
    /// Estimated stack usage at this point
    pub stack_usage: usize,
}

/// Warning severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[allow(dead_code)] // Info variant may be used in future enhancements
pub enum StackWarningSeverity {
    Info,
    Warning,
    Error,
}

/// Stack statistics
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StackStats {
    /// Total functions analyzed
    pub functions_analyzed: usize,
    /// Functions with high stack usage (>1KB)
    pub high_usage_functions: usize,
    /// Functions with very high stack usage (>4KB)
    pub very_high_usage_functions: usize,
    /// Functions with potential overflow risk
    pub overflow_risk_functions: usize,
    /// Average stack usage per function
    pub average_stack_usage: f64,
    /// Maximum stack usage detected
    pub max_stack_usage: usize,
}

/// Analyze stack usage for a BOF file
pub fn analyze_stack_usage(bof: &BofFile) -> StackAnalysis {
    // First, disassemble the BOF to get instruction-level analysis
    let disassembly_results = disassemble_bof(bof);
    
    let mut function_stack_usage = Vec::new();
    let mut warnings = Vec::new();
    let mut stats = StackStats::default();
    
    // Analyze each disassembly result (typically one per code section)
    for disasm_result in &disassembly_results {
        // Analyze each function in this section
        for function in &disasm_result.functions {
            let func_analysis = analyze_function_stack(
                function.start_address,
                function.end_address,
                &disasm_result.instructions,
                function.name.as_deref(),
            );
            
            // Check for warnings
            if func_analysis.estimated_stack_size > 4096 {
                warnings.push(StackWarning {
                    severity: StackWarningSeverity::Error,
                    function_name: func_analysis.function_name.clone(),
                    address: func_analysis.start_address,
                    message: format!(
                        "Very high stack usage detected: {} bytes (>4KB). Risk of stack overflow.",
                        func_analysis.estimated_stack_size
                    ),
                    stack_usage: func_analysis.estimated_stack_size,
                });
                stats.overflow_risk_functions += 1;
            } else if func_analysis.estimated_stack_size > 1024 {
                warnings.push(StackWarning {
                    severity: StackWarningSeverity::Warning,
                    function_name: func_analysis.function_name.clone(),
                    address: func_analysis.start_address,
                    message: format!(
                        "High stack usage detected: {} bytes (>1KB). Consider optimizing.",
                        func_analysis.estimated_stack_size
                    ),
                    stack_usage: func_analysis.estimated_stack_size,
                });
            }
            
            // Update statistics
            stats.functions_analyzed += 1;
            if func_analysis.estimated_stack_size > 1024 {
                stats.high_usage_functions += 1;
            }
            if func_analysis.estimated_stack_size > 4096 {
                stats.very_high_usage_functions += 1;
            }
            if func_analysis.max_stack_usage > stats.max_stack_usage {
                stats.max_stack_usage = func_analysis.max_stack_usage;
            }
            
            function_stack_usage.push(func_analysis);
        }
    }
    
    // Calculate average stack usage
    if !function_stack_usage.is_empty() {
        let total: usize = function_stack_usage.iter()
            .map(|f| f.estimated_stack_size)
            .sum();
        stats.average_stack_usage = total as f64 / function_stack_usage.len() as f64;
    }
    
    StackAnalysis {
        function_stack_usage,
        warnings,
        stats,
    }
}

/// Analyze stack usage for a single function
fn analyze_function_stack(
    start_addr: u64,
    end_addr: u64,
    instructions: &[DisassembledInstruction],
    function_name: Option<&str>,
) -> FunctionStackUsage {
    // Filter instructions for this function
    let func_instructions: Vec<&DisassembledInstruction> = instructions
        .iter()
        .filter(|instr| instr.address >= start_addr && instr.address < end_addr)
        .collect();
    
    let mut stack_operations = Vec::new();
    let mut current_stack_usage: i64 = 0;
    let mut max_stack_usage: usize = 0;
    let mut estimated_frame_size: usize = 0;
    
    // Track if we've seen function prologue
    let mut has_prologue = false;
    
    for instr in &func_instructions {
        let stack_delta = analyze_stack_instruction(instr, &mut stack_operations, &mut has_prologue);
        
        if stack_delta != 0 {
            current_stack_usage += stack_delta;
            
            // Update max stack usage
            if current_stack_usage > 0 && current_stack_usage as usize > max_stack_usage {
                max_stack_usage = current_stack_usage as usize;
            }
            
            // Track frame size from prologue
            if has_prologue && estimated_frame_size == 0 {
                // After prologue, any sub rsp indicates frame size
                if let Some(op) = stack_operations.last() {
                    if matches!(op.operation_type, StackOpType::Allocation) {
                        estimated_frame_size = op.current_stack_usage;
                    }
                }
            }
        }
        
        // Update current_stack_usage in the last operation
        if let Some(op) = stack_operations.last_mut() {
            op.current_stack_usage = if current_stack_usage > 0 {
                current_stack_usage as usize
            } else {
                0
            };
        }
    }
    
    // If we couldn't determine frame size from prologue, use max usage
    if estimated_frame_size == 0 {
        estimated_frame_size = max_stack_usage;
    }
    
    // Determine risk level
    let risk_level = if estimated_frame_size > 4096 {
        StackRiskLevel::Critical
    } else if estimated_frame_size > 2048 {
        StackRiskLevel::High
    } else if estimated_frame_size > 1024 {
        StackRiskLevel::Medium
    } else {
        StackRiskLevel::Low
    };
    
    FunctionStackUsage {
        function_name: function_name.map(|s| s.to_string()),
        start_address: start_addr,
        estimated_stack_size: estimated_frame_size,
        max_stack_usage,
        stack_operations,
        risk_level,
    }
}

/// Analyze a single instruction for stack operations
/// Returns the stack delta (positive = allocate, negative = deallocate)
fn analyze_stack_instruction(
    instr: &DisassembledInstruction,
    stack_operations: &mut Vec<StackOperation>,
    has_prologue: &mut bool,
) -> i64 {
    let text = &instr.text;
    let mnemonic = &instr.mnemonic;
    let mut delta = 0i64;
    let mut op_type = None;
    
    // Function prologue detection: push rbp; mov rbp, rsp
    if mnemonic == "push" && text.contains("rbp") {
        delta = 8; // x64: push is 8 bytes
        op_type = Some(StackOpType::Prologue);
        *has_prologue = true;
    }
    
    // Stack allocation: sub rsp, <imm>
    else if mnemonic == "sub" && text.contains("rsp") {
        // Try to extract the immediate value
        if let Some(imm) = extract_immediate_value(text) {
            delta = imm as i64;
            op_type = Some(StackOpType::Allocation);
        }
    }
    
    // Stack deallocation: add rsp, <imm>
    else if mnemonic == "add" && text.contains("rsp") {
        if let Some(imm) = extract_immediate_value(text) {
            delta = -(imm as i64);
            op_type = Some(StackOpType::Deallocation);
        }
    }
    
    // Push operations
    else if mnemonic == "push" {
        delta = 8; // x64: 8 bytes per push
        op_type = Some(StackOpType::Push);
    }
    
    // Pop operations
    else if mnemonic == "pop" {
        delta = -8; // x64: 8 bytes per pop
        op_type = Some(StackOpType::Pop);
    }
    
    // Function calls (use stack for return address)
    else if instr.is_call {
        delta = 8; // Return address on stack
        op_type = Some(StackOpType::Call);
    }
    
    // Function epilogue: mov rsp, rbp; pop rbp
    else if mnemonic == "mov" && text.contains("rsp") && text.contains("rbp") {
        // This is part of epilogue, but we track it when we see the pop
        op_type = Some(StackOpType::Epilogue);
    }
    else if mnemonic == "pop" && text.contains("rbp") && *has_prologue {
        // Epilogue: restore rbp
        delta = -8;
        op_type = Some(StackOpType::Epilogue);
    }
    
    // Add operation to list if we detected something
    if let Some(op_type_val) = op_type {
        stack_operations.push(StackOperation {
            address: instr.address,
            instruction: instr.text.clone(),
            operation_type: op_type_val,
            stack_delta: delta,
            current_stack_usage: 0, // Will be updated by caller
        });
    }
    
    delta
}

/// Extract immediate value from instruction text
/// Handles formats like "sub rsp, 0x20" or "sub rsp, 32"
fn extract_immediate_value(text: &str) -> Option<u64> {
    // Look for patterns like "sub rsp, 0x20" or "sub rsp, 32"
    // Find the comma and extract what comes after
    if let Some(comma_pos) = text.find(',') {
        let after_comma = &text[comma_pos + 1..].trim();
        
        // Try hex format (0x...)
        if after_comma.starts_with("0x") || after_comma.starts_with("0X") {
            if let Ok(val) = u64::from_str_radix(&after_comma[2..], 16) {
                return Some(val);
            }
        }
        
        // Try decimal format
        if let Ok(val) = after_comma.parse::<u64>() {
            return Some(val);
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::utils::disasm::DisassemblyResult;
    
    #[test]
    fn test_extract_immediate_value() {
        assert_eq!(extract_immediate_value("sub rsp, 0x20"), Some(0x20));
        assert_eq!(extract_immediate_value("sub rsp, 32"), Some(32));
        assert_eq!(extract_immediate_value("add rsp, 0x100"), Some(0x100));
        assert_eq!(extract_immediate_value("mov rax, rbx"), None);
    }
}

