//! BOF execution module

pub mod loader;
pub mod symbols;
pub mod beacon_api;
pub mod arguments;
pub mod relocations;
pub mod sandbox;
pub mod tracer;

use crate::core::models::bof::BofFile;
use crate::core::models::report::{ExecutionResult, OutputMessage, OutputType};
use crate::core::parser;
use anyhow::{Result, Context};
use std::time::{Duration, Instant};
use loader::{MemoryRegion, load_sections};
use symbols::SymbolResolver;
use beacon_api::{BeaconApi, global_output, clear_global_output};
use sandbox::init_sandbox;
use tracer::{init_tracer, get_api_calls, clear_tracer};

/// Execute a BOF
pub fn execute(
    bof: &BofFile,
    args: &[u8],
    sandbox: bool,
    trace: bool,
    timeout: Duration,
) -> Result<ExecutionResult> {
    let start = Instant::now();
    clear_global_output();
    clear_tracer();
    
    // Initialize sandbox and tracer
    init_sandbox(sandbox);
    init_tracer(trace);
    
    // Calculate total memory needed
    let total_size: usize = bof.sections.iter()
        .map(|s| loader::align_to_page(s.raw_size as usize))
        .sum();
    
    // Allocate memory
    let memory = MemoryRegion::allocate(total_size)
        .context("Failed to allocate memory for BOF")?;
    
    // Load sections
    let section_mappings = load_sections(bof, &memory)
        .context("Failed to load sections")?;
    
    // Resolve symbols
    let mut resolver = SymbolResolver::new();
    
    // Register Beacon API functions
    let _beacon_api = BeaconApi::new();
    // Note: Function pointer casts are safe, but the functions themselves will be called from unsafe code
    // Output APIs
    resolver.set_beacon_api("BeaconPrintf", BeaconApi::beacon_printf as usize);
        resolver.set_beacon_api("BeaconOutput", BeaconApi::beacon_output as usize);
        
        // Data parsing APIs
        resolver.set_beacon_api("BeaconDataParse", BeaconApi::beacon_data_parse as usize);
        resolver.set_beacon_api("BeaconDataInt", BeaconApi::beacon_data_int as usize);
        resolver.set_beacon_api("BeaconDataShort", BeaconApi::beacon_data_short as usize);
        resolver.set_beacon_api("BeaconDataLength", BeaconApi::beacon_data_length as usize);
        resolver.set_beacon_api("BeaconDataExtract", BeaconApi::beacon_data_extract as usize);
        
        // Token APIs
        resolver.set_beacon_api("BeaconUseToken", BeaconApi::beacon_use_token as usize);
        resolver.set_beacon_api("BeaconRevertToken", BeaconApi::beacon_revert_token as usize);
        resolver.set_beacon_api("BeaconIsAdmin", BeaconApi::beacon_is_admin as usize);
        
        // Process APIs
        resolver.set_beacon_api("BeaconGetSpawnTo", BeaconApi::beacon_get_spawn_to as usize);
        resolver.set_beacon_api("BeaconSpawnTemporaryProcess", BeaconApi::beacon_spawn_temporary_process as usize);
        resolver.set_beacon_api("BeaconInjectProcess", BeaconApi::beacon_inject_process as usize);
        resolver.set_beacon_api("BeaconInjectTemporaryProcess", BeaconApi::beacon_inject_temporary_process as usize);
        resolver.set_beacon_api("BeaconCleanupProcess", BeaconApi::beacon_cleanup_process as usize);
        
        // Format APIs
        resolver.set_beacon_api("BeaconFormatAlloc", BeaconApi::beacon_format_alloc as usize);
        resolver.set_beacon_api("BeaconFormatReset", BeaconApi::beacon_format_reset as usize);
        resolver.set_beacon_api("BeaconFormatFree", BeaconApi::beacon_format_free as usize);
        resolver.set_beacon_api("BeaconFormatAppend", BeaconApi::beacon_format_append as usize);
        resolver.set_beacon_api("BeaconFormatPrintf", BeaconApi::beacon_format_printf as usize);
        resolver.set_beacon_api("BeaconFormatToString", BeaconApi::beacon_format_to_string as usize);
        resolver.set_beacon_api("BeaconFormatInt", BeaconApi::beacon_format_int as usize);
        
        // Memory APIs
        resolver.set_beacon_api("BeaconVirtualAlloc", BeaconApi::beacon_virtual_alloc as usize);
        resolver.set_beacon_api("BeaconVirtualFree", BeaconApi::beacon_virtual_free as usize);
    
    // Resolve all imports and build symbol map
    let mut resolved_symbols: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    
    for (idx, import) in bof.imports.iter().enumerate() {
        let addr = resolver.resolve(import)
            .with_context(|| format!("Failed to resolve symbol: {}", import.symbol_name))?;
        resolved_symbols.insert(idx, addr);
    }
    
    // Also resolve internal symbols
    for (idx, symbol) in bof.symbols.iter().enumerate() {
        if !symbol.is_external {
            // Find section for symbol
            if let Some(section_idx) = symbol.section {
                if let Some(section_mapping) = section_mappings.get(section_idx) {
                    let addr = section_mapping.virtual_address + symbol.value as usize;
                    resolved_symbols.insert(idx, addr);
                }
            }
        }
    }
    
    // Apply relocations (if any)
    if !bof.relocations.is_empty() {
        relocations::apply_relocations(
            &bof.relocations,
            &memory,
            &section_mappings,
            &resolved_symbols,
            memory.base() as usize,
        )?;
    }
    
    // Find entry point
    let entry_point = bof.entry_point.as_ref()
        .ok_or_else(|| anyhow::anyhow!("No entry point found"))?;
    
    // Find .text section for entry point
    let text_section = section_mappings.iter()
        .find(|m| m.name == ".text")
        .ok_or_else(|| anyhow::anyhow!("No .text section found"))?;
    
    let entry_addr = text_section.virtual_address + entry_point.value as usize;
    
    // Call entry point
    // Signature: void go(char* args, int len)
    type GoFunc = unsafe extern "C" fn(*const u8, i32);
    let go_func: GoFunc = unsafe { std::mem::transmute(entry_addr) };
    
    // Execute (timeout is checked after execution completes)
    // Note: Actual timeout termination would require more complex threading,
    // so we check execution time against timeout limit instead
    let execution_start = Instant::now();
    let execution_result = std::panic::catch_unwind(|| {
        unsafe {
            go_func(args.as_ptr(), args.len() as i32);
        }
    });
    let execution_duration = execution_start.elapsed();
    
    // Check if execution exceeded timeout
    let timed_out = timeout.as_secs() > 0 && execution_duration > timeout;
    
    let execution_time = start.elapsed();
    
    // Collect output
    let output_entries = global_output().get_entries();
    let output: Vec<OutputMessage> = output_entries.iter().map(|entry| {
        OutputMessage {
            timestamp: chrono::Utc::now().to_rfc3339(),
            message_type: match entry.callback_type {
                0x00 => OutputType::Output,
                0x0d => OutputType::Error,
                _ => OutputType::Custom,
            },
            content: String::from_utf8_lossy(&entry.data).to_string(),
        }
    }).collect();
    
    // Collect API calls if tracing was enabled
    let api_calls = get_api_calls();
    
    let (success, error) = if timed_out {
        (false, Some("BOF execution exceeded timeout".to_string()))
    } else {
        match execution_result {
            Ok(_) => (true, None),
            Err(_) => (false, Some("BOF execution panicked".to_string())),
        }
    };
    
    Ok(ExecutionResult {
        success,
        output,
        execution_time,
        error,
        api_calls,
    })
}

/// Test a BOF (execute without arguments)
pub fn test_bof(path: &std::path::PathBuf, _continue_on_error: bool) -> Result<ExecutionResult> {
    // Load and parse BOF
    let bof = parser::load_bof(path)?;
    
    // Execute without arguments
    execute(&bof, &[], false, false, Duration::from_secs(30))
}

