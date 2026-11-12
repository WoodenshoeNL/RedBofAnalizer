//! BOF execution module
//!
//! On Windows: full in-process BOF execution (memory loader, symbol resolution,
//! Beacon API emulation, exception handling).
//! On non-Windows: only the argument parser, relocations, sandbox, tracer, and
//! printf submodules are available. The execute/test functions return an error.

pub mod argspec;
pub mod arguments;
pub mod capture;
#[cfg(windows)]
pub mod pe_exec;
pub mod printf;
pub mod relocations;
pub mod sandbox;
pub mod task;
pub mod tracer;

#[cfg(windows)]
pub mod beacon_api;
#[cfg(windows)]
pub mod loader;
#[cfg(windows)]
pub mod symbols;

use std::sync::atomic::{AtomicBool, Ordering};

/// Global debug mode flag
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

/// Set debug mode for executor output
pub fn set_debug_mode(enabled: bool) {
    DEBUG_MODE.store(enabled, Ordering::SeqCst);
}

/// Check if debug mode is enabled
pub fn is_debug_mode() -> bool {
    DEBUG_MODE.load(Ordering::SeqCst)
}

#[cfg(windows)]
use crate::core::models::bof::{BofFile, Import, MachineType};
#[cfg(windows)]
use crate::core::models::report::{ExecutionResult, OutputMessage, OutputType};
#[cfg(windows)]
use crate::core::parser;
#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use beacon_api::{clear_global_output, global_output, BeaconApi};
#[cfg(windows)]
use loader::{load_sections, MemoryRegion};
#[cfg(windows)]
use sandbox::init_sandbox;
#[cfg(windows)]
use std::time::{Duration, Instant};
#[cfg(windows)]
use symbols::SymbolResolver;
#[cfg(windows)]
use tracer::{clear_tracer, get_api_calls, init_tracer};

// Non-Windows: minimal imports for the stub functions below
#[cfg(not(windows))]
use crate::core::models::bof::BofFile;
#[cfg(not(windows))]
use crate::core::models::report::ExecutionResult;
#[cfg(not(windows))]
use anyhow::Result;
#[cfg(not(windows))]
use std::time::Duration;

#[cfg(windows)]
use windows::Win32::Foundation::EXCEPTION_ACCESS_VIOLATION;
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS,
};
#[cfg(windows)]
use windows::Win32::System::Threading::GetCurrentProcess;

#[cfg(windows)]
pub(crate) static mut CRASH_INFO: Option<(u64, u64)> = None; // (crash_address, instruction_pointer)

#[cfg(windows)]
pub(crate) unsafe extern "system" fn exception_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

    if let Some(info) = exception_info.as_ref() {
        if let Some(record) = info.ExceptionRecord.as_ref() {
            if record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION {
                let access_addr = if record.NumberParameters >= 2 {
                    record.ExceptionInformation[1] as u64
                } else {
                    0
                };
                let instruction_addr = record.ExceptionAddress as u64;
                CRASH_INFO = Some((access_addr, instruction_addr));
                eprintln!(
                    "[BOF] ACCESS VIOLATION at instruction 0x{:x}, accessing address 0x{:x}",
                    instruction_addr, access_addr
                );
            }
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}

/// Execute a BOF
#[cfg(windows)]
pub fn execute(
    bof: &BofFile,
    args: &[u8],
    sandbox: bool,
    trace: bool,
    timeout: Duration,
    emulate_beacon_info: bool,
) -> Result<ExecutionResult> {
    execute_with_entry_point(
        bof,
        args,
        sandbox,
        trace,
        timeout,
        None,
        emulate_beacon_info,
    )
}

/// Execute a BOF (non-Windows stub)
#[cfg(not(windows))]
pub fn execute(
    _bof: &BofFile,
    _args: &[u8],
    _sandbox: bool,
    _trace: bool,
    _timeout: Duration,
    _emulate_beacon_info: bool,
) -> Result<ExecutionResult> {
    anyhow::bail!("BOF execution is only supported on Windows. Use a Windows loader (RedLoader, COFFLoader) on the target VM instead.")
}

/// How long to keep waiting after signaling the stop event before giving up
/// on an async task (matches RedLoader's verified contract).
const ASYNC_STOP_GRACE: Duration = Duration::from_secs(10);

/// Drain/poll interval while an async task runs.
const ASYNC_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Execute a BOF asynchronously: worker thread + per-task output sink +
/// OC2 stop-event contract.
///
/// - While the BOF runs, output entries are drained every 50 ms; each is
///   passed to `on_output` (if given) for live streaming, and all are
///   included in the final [`ExecutionResult`].
/// - If `async_timeout` elapses (or the overall `timeout` does), the stop
///   event is signaled — a well-behaved BOF sees it through
///   `BeaconGetStopJobEvent()` and returns promptly.
/// - A BOF that ignores the stop event gets [`ASYNC_STOP_GRACE`] (10 s),
///   after which the loader *detaches*: the result reports failure with a
///   "detached" error and the worker thread is left running (it cannot be
///   safely killed).
#[cfg(windows)]
pub fn execute_async(
    bof: &BofFile,
    args: &[u8],
    sandbox: bool,
    trace: bool,
    timeout: Duration,
    emulate_beacon_info: bool,
    async_timeout: Option<Duration>,
    mut on_output: Option<&mut dyn FnMut(&crate::core::executor::capture::OutputEntry)>,
) -> Result<ExecutionResult> {
    use crate::core::executor::capture::OutputEntry;
    use std::sync::{Arc, Mutex};

    let start = Instant::now();
    clear_global_output();
    clear_tracer();

    let bof_owned = bof.clone();
    let args_owned = args.to_vec();
    let inner_result: Arc<Mutex<Option<ExecutionResult>>> = Arc::new(Mutex::new(None));

    let result_slot = Arc::clone(&inner_result);
    let job = crate::core::executor::task::spawn_task(move |_ctx| {
        let r = execute_with_entry_point(
            &bof_owned,
            &args_owned,
            sandbox,
            trace,
            timeout,
            None,
            emulate_beacon_info,
        );
        match r {
            Ok(res) => {
                *result_slot.lock().unwrap() = Some(res);
                Ok(())
            }
            Err(e) => Err(format!("{e:#}")),
        }
    });

    let mut all_output: Vec<OutputEntry> = Vec::new();
    let mut stop_signaled = false;
    let mut stop_deadline: Option<Instant> = None;

    loop {
        // Drain whatever the BOF produced since the last poll.
        for entry in job.drain_output() {
            if let Some(cb) = on_output.as_deref_mut() {
                cb(&entry);
            }
            all_output.push(entry);
        }

        if !job.is_running() {
            break;
        }

        let elapsed = start.elapsed();
        if !stop_signaled {
            let should_stop = async_timeout.map(|t| elapsed >= t).unwrap_or(false)
                || (timeout.as_secs() > 0 && elapsed >= timeout);
            if should_stop {
                let reason = async_timeout
                    .filter(|t| elapsed >= *t)
                    .map(|t| format!("async timeout ({:.1?})", t))
                    .unwrap_or_else(|| format!("overall timeout ({:.1?})", timeout));
                eprintln!("[async] {reason}: signaling stop event");
                job.stop();
                stop_signaled = true;
                stop_deadline = Some(Instant::now() + ASYNC_STOP_GRACE);
            }
        } else if let Some(deadline) = stop_deadline {
            if Instant::now() >= deadline {
                eprintln!(
                    "[async] BOF ignored the stop event for {}s; detaching (thread left running)",
                    ASYNC_STOP_GRACE.as_secs()
                );
                let execution_time = start.elapsed();
                return Ok(ExecutionResult {
                    success: false,
                    output: messages_from_entries(&all_output),
                    execution_time,
                    error: Some(format!(
                        "BOF ignored the stop event; loader detached after {}s grace",
                        ASYNC_STOP_GRACE.as_secs()
                    )),
                    api_calls: get_api_calls(),
                    resolved_imports: Default::default(),
                    code_base_address: None,
                });
            }
        }

        std::thread::sleep(ASYNC_POLL_INTERVAL);
    }

    // Final drain + join.
    for entry in job.drain_output() {
        if let Some(cb) = on_output.as_deref_mut() {
            cb(&entry);
        }
        all_output.push(entry);
    }
    let join = job.join();

    let execution_time = start.elapsed();
    let inner = inner_result.lock().unwrap().take();
    let api_calls = get_api_calls();

    match (join, inner) {
        (Ok(()), Some(inner)) => {
            // The inner run captured nothing in `.output` (writes went to
            // the task sink), so rebuild output from the drained entries.
            Ok(ExecutionResult {
                output: messages_from_entries(&all_output),
                api_calls,
                ..inner
            })
        }
        (Err(msg), _) => Ok(ExecutionResult {
            success: false,
            output: messages_from_entries(&all_output),
            execution_time,
            error: Some(msg),
            api_calls,
            resolved_imports: Default::default(),
            code_base_address: None,
        }),
        (Ok(()), None) => Ok(ExecutionResult {
            success: false,
            output: messages_from_entries(&all_output),
            execution_time,
            error: Some("async task finished without a result".to_string()),
            api_calls,
            resolved_imports: Default::default(),
            code_base_address: None,
        }),
    }
}

/// Convert captured output entries into report messages.
#[cfg(windows)]
fn messages_from_entries(
    entries: &[crate::core::executor::capture::OutputEntry],
) -> Vec<OutputMessage> {
    entries
        .iter()
        .map(|entry| OutputMessage {
            timestamp: chrono::Utc::now().to_rfc3339(),
            message_type: match entry.callback_type {
                0x00 => OutputType::Output,
                0x0d => OutputType::Error,
                _ => OutputType::Custom,
            },
            content: String::from_utf8_lossy(&entry.data).to_string(),
        })
        .collect()
}

/// Execute a BOF asynchronously (non-Windows stub)
#[cfg(not(windows))]
pub fn execute_async(
    _bof: &BofFile,
    _args: &[u8],
    _sandbox: bool,
    _trace: bool,
    _timeout: Duration,
    _emulate_beacon_info: bool,
    _async_timeout: Option<Duration>,
    _on_output: Option<&mut dyn FnMut(&crate::core::executor::capture::OutputEntry)>,
) -> Result<ExecutionResult> {
    anyhow::bail!("BOF execution is only supported on Windows. Use a Windows loader (RedLoader, COFFLoader) on the target VM instead.")
}

/// Register every Beacon API implementation on the resolver (shared by
/// the COFF path and the BOF-PE mapper).
#[cfg(windows)]
pub(crate) fn register_all_beacon_apis(resolver: &mut SymbolResolver) {
    // Output APIs
    resolver.set_beacon_api("BeaconPrintf", BeaconApi::beacon_printf as usize);
    resolver.set_beacon_api("BeaconOutput", BeaconApi::beacon_output as usize);
    resolver.set_beacon_api("BeaconDownload", BeaconApi::beacon_download as usize);

    // Async contract APIs (OC2 style)
    resolver.set_beacon_api(
        "BeaconGetStopJobEvent",
        BeaconApi::beacon_get_stop_job_event as usize,
    );
    resolver.set_beacon_api("BeaconWakeup", BeaconApi::beacon_wakeup as usize);

    // Data parsing APIs
    resolver.set_beacon_api("BeaconDataParse", BeaconApi::beacon_data_parse as usize);
    resolver.set_beacon_api("BeaconDataPtr", BeaconApi::beacon_data_ptr as usize);
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
    resolver.set_beacon_api(
        "BeaconSpawnTemporaryProcess",
        BeaconApi::beacon_spawn_temporary_process as usize,
    );
    resolver.set_beacon_api(
        "BeaconInjectProcess",
        BeaconApi::beacon_inject_process as usize,
    );
    resolver.set_beacon_api(
        "BeaconInjectTemporaryProcess",
        BeaconApi::beacon_inject_temporary_process as usize,
    );
    resolver.set_beacon_api(
        "BeaconCleanupProcess",
        BeaconApi::beacon_cleanup_process as usize,
    );

    // Format APIs
    resolver.set_beacon_api("BeaconFormatAlloc", BeaconApi::beacon_format_alloc as usize);
    resolver.set_beacon_api("BeaconFormatReset", BeaconApi::beacon_format_reset as usize);
    resolver.set_beacon_api("BeaconFormatFree", BeaconApi::beacon_format_free as usize);
    resolver.set_beacon_api(
        "BeaconFormatAppend",
        BeaconApi::beacon_format_append as usize,
    );
    resolver.set_beacon_api(
        "BeaconFormatPrintf",
        BeaconApi::beacon_format_printf as usize,
    );
    resolver.set_beacon_api(
        "BeaconFormatToString",
        BeaconApi::beacon_format_to_string as usize,
    );
    resolver.set_beacon_api("BeaconFormatInt", BeaconApi::beacon_format_int as usize);
    resolver.set_beacon_api("BeaconFormatShort", BeaconApi::beacon_format_short as usize);
    resolver.set_beacon_api(
        "BeaconFormatLength",
        BeaconApi::beacon_format_length as usize,
    );

    // Memory APIs
    resolver.set_beacon_api(
        "BeaconVirtualAlloc",
        BeaconApi::beacon_virtual_alloc as usize,
    );
    resolver.set_beacon_api(
        "BeaconVirtualAllocEx",
        BeaconApi::beacon_virtual_alloc_ex as usize,
    );
    resolver.set_beacon_api("BeaconVirtualFree", BeaconApi::beacon_virtual_free as usize);
    resolver.set_beacon_api(
        "BeaconVirtualProtect",
        BeaconApi::beacon_virtual_protect as usize,
    );
    resolver.set_beacon_api(
        "BeaconVirtualProtectEx",
        BeaconApi::beacon_virtual_protect_ex as usize,
    );

    // Utility APIs
    resolver.set_beacon_api("toWideChar", BeaconApi::to_wide_char as usize);

    // Information APIs
    resolver.set_beacon_api("BeaconInformation", BeaconApi::beacon_information as usize);
    resolver.set_beacon_api(
        "BeaconGetSyscallInformation",
        BeaconApi::beacon_get_syscall_information as usize,
    );

    // Key/Value Store APIs
    resolver.set_beacon_api("BeaconAddValue", BeaconApi::beacon_add_value as usize);
    resolver.set_beacon_api("BeaconGetValue", BeaconApi::beacon_get_value as usize);
    resolver.set_beacon_api("BeaconRemoveValue", BeaconApi::beacon_remove_value as usize);
    resolver.set_beacon_api(
        "BeaconGetIntValue",
        BeaconApi::beacon_get_int_value as usize,
    );
    resolver.set_beacon_api(
        "BeaconGetShortValue",
        BeaconApi::beacon_get_short_value as usize,
    );
    resolver.set_beacon_api(
        "BeaconGetCharValue",
        BeaconApi::beacon_get_char_value as usize,
    );
    resolver.set_beacon_api(
        "BeaconGetPtrValue",
        BeaconApi::beacon_get_ptr_value as usize,
    );
    resolver.set_beacon_api(
        "BeaconGetSizeValue",
        BeaconApi::beacon_get_size_value as usize,
    );
    resolver.set_beacon_api(
        "BeaconGetDataValue",
        BeaconApi::beacon_get_data_value as usize,
    );

    // Data Store APIs
    resolver.set_beacon_api(
        "BeaconDataStoreAlloc",
        BeaconApi::beacon_data_store_alloc as usize,
    );
    resolver.set_beacon_api(
        "BeaconDataStoreReset",
        BeaconApi::beacon_data_store_reset as usize,
    );
    resolver.set_beacon_api(
        "BeaconDataStoreFree",
        BeaconApi::beacon_data_store_free as usize,
    );
    resolver.set_beacon_api(
        "BeaconDataStoreAdd",
        BeaconApi::beacon_data_store_add as usize,
    );
    resolver.set_beacon_api(
        "BeaconDataStoreGet",
        BeaconApi::beacon_data_store_get as usize,
    );
    resolver.set_beacon_api(
        "BeaconDataStoreRemove",
        BeaconApi::beacon_data_store_remove as usize,
    );
    resolver.set_beacon_api(
        "BeaconDataStoreSize",
        BeaconApi::beacon_data_store_size as usize,
    );
    resolver.set_beacon_api(
        "BeaconDataStoreGetItem",
        BeaconApi::beacon_data_store_get_item as usize,
    );
    resolver.set_beacon_api(
        "BeaconDataStoreProtectItem",
        BeaconApi::beacon_data_store_protect_item as usize,
    );
    resolver.set_beacon_api(
        "BeaconDataStoreUnprotectItem",
        BeaconApi::beacon_data_store_unprotect_item as usize,
    );
    resolver.set_beacon_api(
        "BeaconDataStoreMaxEntries",
        BeaconApi::beacon_data_store_max_entries as usize,
    );

    // User Data APIs
    resolver.set_beacon_api(
        "BeaconGetCustomUserData",
        BeaconApi::beacon_get_custom_user_data as usize,
    );
    resolver.set_beacon_api(
        "BeaconGetUserData",
        BeaconApi::beacon_get_user_data as usize,
    );

    // Thread/Process APIs
    resolver.set_beacon_api(
        "BeaconGetThreadContext",
        BeaconApi::beacon_get_thread_context as usize,
    );
    resolver.set_beacon_api(
        "BeaconSetThreadContext",
        BeaconApi::beacon_set_thread_context as usize,
    );
    resolver.set_beacon_api(
        "BeaconResumeThread",
        BeaconApi::beacon_resume_thread as usize,
    );
    resolver.set_beacon_api("BeaconOpenProcess", BeaconApi::beacon_open_process as usize);
    resolver.set_beacon_api("BeaconOpenThread", BeaconApi::beacon_open_thread as usize);
    resolver.set_beacon_api("BeaconCloseHandle", BeaconApi::beacon_close_handle as usize);
    resolver.set_beacon_api(
        "BeaconUnmapViewOfFile",
        BeaconApi::beacon_unmap_view_of_file as usize,
    );
    resolver.set_beacon_api(
        "BeaconVirtualQuery",
        BeaconApi::beacon_virtual_query as usize,
    );
    resolver.set_beacon_api(
        "BeaconDuplicateHandle",
        BeaconApi::beacon_duplicate_handle as usize,
    );
    resolver.set_beacon_api(
        "BeaconReadProcessMemory",
        BeaconApi::beacon_read_process_memory as usize,
    );
    resolver.set_beacon_api(
        "BeaconWriteProcessMemory",
        BeaconApi::beacon_write_process_memory as usize,
    );

    // Beacon Gate APIs
    resolver.set_beacon_api(
        "BeaconDisableBeaconGate",
        BeaconApi::beacon_disable_beacon_gate as usize,
    );
    resolver.set_beacon_api(
        "BeaconEnableBeaconGate",
        BeaconApi::beacon_enable_beacon_gate as usize,
    );
    resolver.set_beacon_api(
        "BeaconDisableBeaconGateMasking",
        BeaconApi::beacon_disable_beacon_gate_masking as usize,
    );
    resolver.set_beacon_api(
        "BeaconEnableBeaconGateMasking",
        BeaconApi::beacon_enable_beacon_gate_masking as usize,
    );
}

/// Execute a BOF with a specific entry point
#[cfg(windows)]
pub fn execute_with_entry_point(
    bof: &BofFile,
    args: &[u8],
    sandbox: bool,
    trace: bool,
    timeout: Duration,
    entry_point_name: Option<&str>,
    emulate_beacon_info: bool,
) -> Result<ExecutionResult> {
    let start = Instant::now();
    clear_global_output();
    clear_tracer();

    // ---------------------------------------------------------------------
    // Architecture compatibility check
    // ---------------------------------------------------------------------
    //
    // BOF code runs directly inside this process, so the BOF machine type
    // must match the process architecture. If it does not, we refuse to
    // execute and return a clear error instead of crashing.
    #[cfg(target_pointer_width = "64")]
    let process_arch_bits: u32 = 64;
    #[cfg(target_pointer_width = "32")]
    let process_arch_bits: u32 = 32;

    let bof_arch_bits: u32 = match bof.header.machine {
        MachineType::X64 => 64,
        MachineType::X86 => 32,
        MachineType::Unknown(val) => {
            return Err(anyhow::anyhow!(
                "Cannot execute BOF with unknown or unsupported architecture (machine = 0x{:04X})",
                val
            ));
        }
    };

    if bof_arch_bits != process_arch_bits {
        let bof_arch_str = if bof_arch_bits == 64 { "x64" } else { "x86" };
        let proc_arch_str = if process_arch_bits == 64 {
            "x64"
        } else {
            "x86"
        };

        return Err(anyhow::anyhow!(
            "BOF architecture is not compatible with this redbofanalyzer build.\n\
             - BOF architecture: {}\n\
             - Process/tool architecture: {}\n\
             This build can only execute BOFs that match the process architecture.\n\
             Use a 32-bit build to execute x86 BOFs, or a 64-bit build to execute x64 BOFs.",
            bof_arch_str,
            proc_arch_str
        ));
    }

    // Initialize sandbox and tracer
    init_sandbox(sandbox);
    init_tracer(trace);

    // BOF-PE images take a separate manual-mapping path: headers, sections
    // and IAT live at their RVAs and imports bind through the PE import
    // tables, so the flat COFF section copy below does not apply.
    #[cfg(windows)]
    {
        let bytes = std::fs::read(&bof.path)
            .with_context(|| format!("cannot read BOF image {}", bof.path.display()))?;
        if crate::core::parser::pe::is_pe_image(&bytes) {
            {
                let mut pe_resolver = SymbolResolver::new();
                register_all_beacon_apis(&mut pe_resolver);
                let entry_name = entry_point_name.unwrap_or("go").to_string();
                // Same crash containment as the COFF path: vectored handler
                // around the go() call, and a panic inside BOF-PE code is
                // reported as a failed result instead of taking the process.
                #[cfg(windows)]
                let pe_exception_handler = unsafe {
                    CRASH_INFO = None;
                    AddVectoredExceptionHandler(1, Some(exception_handler))
                };
                let pe_run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::core::executor::pe_exec::execute_pe(
                        &bytes,
                        args,
                        &pe_resolver,
                        &entry_name,
                    )
                }));
                #[cfg(windows)]
                unsafe {
                    if !pe_exception_handler.is_null() {
                        RemoveVectoredExceptionHandler(pe_exception_handler);
                    }
                    if let Some((access_addr, instr_addr)) = CRASH_INFO {
                        eprintln!(
                            "[BOF-PE] Crash details - Instruction: 0x{:x}, Access: 0x{:x}",
                            instr_addr, access_addr
                        );
                    }
                }
                let code_base = match pe_run {
                    Ok(Ok(base)) => base,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        let execution_time = start.elapsed();
                        return Ok(ExecutionResult {
                            success: false,
                            output: global_output()
                                .get_entries()
                                .iter()
                                .map(|entry| OutputMessage {
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                    message_type: match entry.callback_type {
                                        0x00 => OutputType::Output,
                                        0x0d => OutputType::Error,
                                        _ => OutputType::Custom,
                                    },
                                    content: String::from_utf8_lossy(&entry.data).to_string(),
                                })
                                .collect(),
                            execution_time,
                            error: Some("BOF-PE execution panicked".to_string()),
                            api_calls: get_api_calls(),
                            resolved_imports: Default::default(),
                            code_base_address: None,
                        });
                    }
                };
                let execution_time = start.elapsed();
                let output_entries = global_output().get_entries();
                let output: Vec<OutputMessage> = output_entries
                    .iter()
                    .map(|entry| OutputMessage {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        message_type: match entry.callback_type {
                            0x00 => OutputType::Output,
                            0x0d => OutputType::Error,
                            _ => OutputType::Custom,
                        },
                        content: String::from_utf8_lossy(&entry.data).to_string(),
                    })
                    .collect();
                return Ok(ExecutionResult {
                    success: true,
                    output,
                    execution_time,
                    error: None,
                    api_calls: get_api_calls(),
                    resolved_imports: Default::default(),
                    code_base_address: Some(code_base as u64),
                });
            }
        }
    }

    // Calculate total memory needed
    let total_size: usize = bof
        .sections
        .iter()
        .map(|s| loader::align_to_page(s.raw_size as usize))
        .sum();

    // Allocate memory
    let memory = MemoryRegion::allocate(total_size).with_context(|| {
        format!(
            "Failed to allocate {} bytes of memory for BOF. This may indicate:\n\
             - Insufficient system memory\n\
             - Memory allocation failure",
            total_size
        )
    })?;

    // Load sections
    let section_mappings = load_sections(bof, &memory).context("Failed to load sections")?;

    // Initialize BeaconInformation and syscall information emulation (if enabled)
    #[cfg(windows)]
    crate::core::executor::beacon_api::initialize_beacon_information_emulation(
        memory.base(),
        total_size,
        &section_mappings,
        emulate_beacon_info,
    );
    #[cfg(windows)]
    crate::core::executor::beacon_api::set_syscall_os_emulation_enabled(emulate_beacon_info);
    #[cfg(windows)]
    crate::core::executor::beacon_api::set_syscall_trace_enabled(trace);

    // Resolve symbols
    let mut resolver = SymbolResolver::new();

    // Register Beacon API functions
    let _beacon_api = BeaconApi::new();
    // Note: Function pointer casts are safe, but the functions themselves will be called from unsafe code

    register_all_beacon_apis(&mut resolver);

    // Resolve all symbols and build symbol map
    // Key: COFF symbol table index, Value: resolved address
    let mut resolved_symbols: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::new();

    // Track resolved import addresses for reporting (symbol_name -> function address)
    let mut resolved_imports: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();

    // For __imp_ symbols, we need to store the function address in memory
    // and use the memory address as the symbol value (indirect addressing)
    // Allocate space for import address table (IAT)
    let import_count = bof.imports.len();
    let iat_size = import_count * std::mem::size_of::<usize>();
    let iat_memory = if iat_size > 0 {
        Some(loader::MemoryRegion::allocate(iat_size).context("Failed to allocate IAT memory")?)
    } else {
        None
    };

    // Track which IAT slot we're using
    let mut iat_index = 0usize;

    if is_debug_mode() {
        eprintln!(
            "[BOF] Resolving {} symbols (IAT size: {} bytes for {} imports)...",
            bof.symbols.len(),
            iat_size,
            import_count
        );
    }

    // Build a map of symbol names to their imports for quick lookup
    let import_map: std::collections::HashMap<String, &Import> = bof
        .imports
        .iter()
        .map(|imp| (imp.symbol_name.clone(), imp))
        .collect();

    // Resolve all symbols by their COFF symbol table index
    for symbol in &bof.symbols {
        let coff_idx = symbol.coff_index;

        if symbol.is_external {
            // External symbol - look up in imports and resolve
            if let Some(import) = import_map.get(&symbol.name) {
                match resolver.resolve(import) {
                    Ok(func_addr) => {
                        // Track resolved import for reporting
                        resolved_imports.insert(symbol.name.clone(), func_addr as u64);

                        // For __imp_ symbols, we need indirect addressing:
                        // Store the function address in the IAT and return the IAT slot address
                        if symbol.name.starts_with("__imp_") {
                            if let Some(ref iat) = iat_memory {
                                let iat_slot_offset = iat_index * std::mem::size_of::<usize>();
                                let iat_slot_addr = iat.base() as usize + iat_slot_offset;

                                // Write the function address to the IAT slot
                                let addr_bytes = (func_addr as u64).to_le_bytes();
                                iat.write_at(iat_slot_offset, &addr_bytes)?;

                                log::debug!("Resolved import '{}' (coff_idx={}): func=0x{:x} -> IAT[{}]=0x{:x}",
                                    symbol.name, coff_idx, func_addr, iat_index, iat_slot_addr);

                                resolved_symbols.insert(coff_idx, iat_slot_addr);
                                iat_index += 1;
                            }
                        } else {
                            // Direct symbol - use function address directly
                            log::debug!(
                                "Resolved external symbol '{}' (coff_idx={}) -> 0x{:x}",
                                symbol.name,
                                coff_idx,
                                func_addr
                            );
                            resolved_symbols.insert(coff_idx, func_addr);
                        }
                    }
                    Err(e) => {
                        // Log warning but continue - some symbols may not be used
                        log::warn!("Could not resolve symbol {}: {}", symbol.name, e);
                    }
                }
            } else {
                // Try to resolve as a Beacon API or Win32 API directly by name
                // Some symbols may be referenced differently (e.g., Beacon APIs without __imp_ prefix)
                if let Ok(func_addr) = resolver.resolve_symbol_by_name(&symbol.name) {
                    // Track resolved import for reporting
                    resolved_imports.insert(symbol.name.clone(), func_addr as u64);

                    if symbol.name.starts_with("__imp_") {
                        if let Some(ref iat) = iat_memory {
                            let iat_slot_offset = iat_index * std::mem::size_of::<usize>();
                            let iat_slot_addr = iat.base() as usize + iat_slot_offset;

                            let addr_bytes = (func_addr as u64).to_le_bytes();
                            iat.write_at(iat_slot_offset, &addr_bytes)?;

                            log::debug!("Resolved import '{}' (coff_idx={}) via fallback: func=0x{:x} -> IAT[{}]=0x{:x}",
                                symbol.name, coff_idx, func_addr, iat_index, iat_slot_addr);

                            resolved_symbols.insert(coff_idx, iat_slot_addr);
                            iat_index += 1;
                        }
                    } else {
                        log::debug!(
                            "Resolved external symbol '{}' (coff_idx={}) via fallback -> 0x{:x}",
                            symbol.name,
                            coff_idx,
                            func_addr
                        );
                        resolved_symbols.insert(coff_idx, func_addr);
                    }
                } else {
                    log::warn!(
                        "Unresolved external symbol '{}' (coff_idx={}) - not in imports",
                        symbol.name,
                        coff_idx
                    );
                }
            }
        } else {
            // Internal symbol - calculate address from section
            if let Some(section_idx) = symbol.section {
                // Note: section_idx from object crate's SectionIndex should be 0-based
                // and match our section_mappings array indexing
                if let Some(section_mapping) = section_mappings.get(section_idx) {
                    let addr = section_mapping.virtual_address + symbol.value as usize;
                    log::debug!(
                        "Resolved internal symbol '{}' (coff_idx={}) in section {} ({}) at 0x{:x}",
                        symbol.name,
                        coff_idx,
                        section_idx,
                        section_mapping.name,
                        addr
                    );
                    resolved_symbols.insert(coff_idx, addr);
                } else {
                    log::warn!(
                        "Internal symbol '{}' references section {} but only {} sections exist",
                        symbol.name,
                        section_idx,
                        section_mappings.len()
                    );
                }
            }
        }
    }

    if is_debug_mode() {
        eprintln!(
            "[BOF] Resolved {} symbols (used {} IAT slots)",
            resolved_symbols.len(),
            iat_index
        );

        // Print resolved symbols for debugging
        for (coff_idx, addr) in resolved_symbols.iter() {
            // Find the symbol name
            if let Some(sym) = bof.symbols.iter().find(|s| s.coff_index == *coff_idx) {
                eprintln!("[BOF]   Symbol {}: {} -> 0x{:x}", coff_idx, sym.name, addr);
            }
        }

        // Keep reference to IAT to prevent it from being dropped during execution
        if let Some(ref iat) = iat_memory {
            eprintln!(
                "[BOF] IAT at 0x{:x}, dumping first {} slots:",
                iat.base() as usize,
                iat_index.min(5)
            );
            for i in 0..iat_index.min(5) {
                let slot_offset = i * 8;
                let slot_addr = iat.base() as usize + slot_offset;
                unsafe {
                    let func_ptr = *(slot_addr as *const u64);
                    eprintln!("[BOF]   IAT[{}] at 0x{:x} = 0x{:x}", i, slot_addr, func_ptr);
                }
            }
        }
    }
    let _iat_guard = iat_memory;

    // Pre-execution validation: Check for unresolved symbols referenced by relocations
    let mut unresolved_in_relocations = std::collections::HashSet::new();
    for reloc in &bof.relocations {
        if let crate::core::models::bof::RelocationTarget::Symbol(sym_idx) = &reloc.target {
            if !resolved_symbols.contains_key(&(*sym_idx as usize)) {
                if let Some(sym) = bof
                    .symbols
                    .iter()
                    .find(|s| s.coff_index == *sym_idx as usize)
                {
                    unresolved_in_relocations.insert((*sym_idx, sym.name.clone()));
                }
            }
        }
    }

    if !unresolved_in_relocations.is_empty() {
        let mut error_msg = format!("\n[BOF] PRE-EXECUTION VALIDATION FAILED: {} unresolved symbol(s) referenced by relocations:\n", unresolved_in_relocations.len());
        for (sym_idx, sym_name) in unresolved_in_relocations.iter() {
            error_msg.push_str(&format!(
                "  - Symbol '{}' (coff_idx: {})\n",
                sym_name, sym_idx
            ));

            // Check if it's a known pattern and provide suggestions
            if sym_name.contains("$") {
                let parts: Vec<&str> = sym_name.split('$').collect();
                if parts.len() >= 2 {
                    let lib = parts[0];
                    let func = parts[1].split('@').next().unwrap_or(parts[1]);
                    error_msg.push_str(&format!("    → Looks like: {}${}()\n", lib, func));
                    error_msg.push_str(&format!(
                        "    → Add to beacon.h: WINBASEAPI ... WINAPI {}${}();\n",
                        lib, func
                    ));
                }
            } else if !sym_name.starts_with("__imp_") {
                error_msg.push_str(&format!(
                    "    → Add to beacon.h: extern void __cdecl {}();\n",
                    sym_name
                ));
            }
        }
        error_msg.push_str("\nThis BOF will likely crash if executed. Fix the missing declarations and recompile.\n");
        error_msg.push_str("Check the Lints tab for BOF009 errors with detailed suggestions.\n");

        if is_debug_mode() {
            eprintln!("{}", error_msg);
        }
        log::error!("{}", error_msg);
    }

    // Apply relocations (if any)
    if !bof.relocations.is_empty() {
        if is_debug_mode() {
            eprintln!(
                "[BOF] Applying {} relocations across {} section mappings",
                bof.relocations.len(),
                section_mappings.len()
            );
            for (i, mapping) in section_mappings.iter().enumerate() {
                eprintln!(
                    "[BOF]   Section {}: {} at 0x{:x} (offset 0x{:x}, size {})",
                    i, mapping.name, mapping.virtual_address, mapping.offset, mapping.size
                );
            }
        }
        relocations::apply_relocations(
            &bof.relocations,
            &memory,
            &section_mappings,
            &resolved_symbols,
            memory.base() as usize,
            Some(&bof.symbols),
        )?;

        if is_debug_mode() {
            eprintln!("[BOF] Relocations applied successfully");

            // Dump bytes in internal_printf (0x86-0x1F4) to see the code
            unsafe {
                let area = memory.base().add(0x180);
                let mut bytes = Vec::new();
                for i in 0..48 {
                    bytes.push(*area.add(i));
                }
                eprintln!("[BOF] Bytes at 0x180-0x1B0: {:02x?}", bytes);
            }
        }

        // Flush instruction cache after modifying code
        #[cfg(windows)]
        unsafe {
            let _ = FlushInstructionCache(
                GetCurrentProcess(),
                Some(memory.base() as *const _),
                total_size,
            );
            if is_debug_mode() {
                eprintln!("[BOF] Instruction cache flushed");
            }
        }
    } else if is_debug_mode() {
        eprintln!("[BOF] No relocations to apply");
    }

    // Find entry point
    let entry_point = if let Some(ep_name) = entry_point_name {
        // Use specified entry point name
        bof.symbols
            .iter()
            .find(|s| s.name == ep_name && s.section.is_some() && !s.is_external)
            .ok_or_else(|| {
                let available: Vec<String> = bof
                    .symbols
                    .iter()
                    .filter(|s| s.section.is_some() && !s.is_external)
                    .map(|s| s.name.clone())
                    .take(5)
                    .collect();
                anyhow::anyhow!(
                    "Entry point '{}' not found in BOF.\n\
                     Available symbols: {}\n\
                     BOFs typically use 'go' as the entry point name.",
                    ep_name,
                    if available.is_empty() {
                        "none".to_string()
                    } else {
                        available.join(", ")
                    }
                )
            })?
    } else {
        // Use default entry point (go) or fallback to first available function
        bof.entry_point
            .as_ref()
            .or_else(|| {
                // Fallback: find any symbol in an executable section
                // Use the same logic as find_potential_entry_points but just get the first one
                for symbol in &bof.symbols {
                    if symbol.section.is_some() && !symbol.is_external {
                        if let Some(section_idx) = symbol.section {
                            if let Some(section) = bof.sections.get(section_idx) {
                                let is_executable = (section.characteristics & 0x20000000) != 0;
                                let is_code = (section.characteristics & 0x00000020) != 0;
                                let is_text_section =
                                    section.name == ".text" || section.name.starts_with(".text");

                                if is_executable || is_code || is_text_section {
                                    let name = &symbol.name;
                                    if !name.starts_with('$')
                                        && !name.starts_with('.')
                                        && name != "main"
                                        && !name.starts_with("__")
                                        && !name.contains("$unwind$")
                                        && !name.contains("$pdata$")
                                    {
                                        return Some(symbol);
                                    }
                                }
                            }
                        }
                    }
                }
                None
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No entry point found in BOF.\n\
                 BOFs must have a 'go' function as the entry point.\n\
                 Check if the BOF was compiled correctly and includes the entry point function."
                )
            })?
    };

    log::info!(
        "Entry point '{}' found with value 0x{:x}, section {:?}",
        entry_point.name,
        entry_point.value,
        entry_point.section
    );

    // Find the section containing the entry point
    let entry_section = if let Some(section_idx) = entry_point.section {
        section_mappings
            .get(section_idx)
            .ok_or_else(|| anyhow::anyhow!("Entry point section {} not found", section_idx))?
    } else {
        // Fallback to .text if no section specified
        section_mappings
            .iter()
            .find(|m| m.name == ".text")
            .ok_or_else(|| anyhow::anyhow!("No .text section found"))?
    };

    let entry_addr = entry_section.virtual_address + entry_point.value as usize;

    if is_debug_mode() {
        eprintln!(
            "[BOF] Entry point in section '{}' at 0x{:x}",
            entry_section.name, entry_addr
        );
    }

    log::info!(
        "Calling entry point at 0x{:x} (section {} base 0x{:x} + offset 0x{:x})",
        entry_addr,
        entry_section.name,
        entry_section.virtual_address,
        entry_point.value
    );
    log::info!("Args: {} bytes at {:p}", args.len(), args.as_ptr());

    if is_debug_mode() {
        if args.is_empty() {
            eprintln!("[BOF] No arguments provided to entry point");
        } else {
            eprintln!(
                "[BOF] Passing {} bytes of argument data to entry point",
                args.len()
            );
            eprintln!(
                "[BOF] Argument buffer preview (first 64 bytes): {}",
                args.iter()
                    .take(64)
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
    }

    // Verify the entry point is within our allocated memory
    let memory_base = memory.base() as usize;
    let memory_end = memory_base + total_size;
    if entry_addr < memory_base || entry_addr >= memory_end {
        anyhow::bail!(
            "Entry point 0x{:x} is outside allocated memory region 0x{:x}-0x{:x}",
            entry_addr,
            memory_base,
            memory_end
        );
    }

    // Call entry point
    // Signature: void go(char* args, int len)
    type GoFunc = unsafe extern "C" fn(*const u8, i32);
    let go_func: GoFunc = unsafe { std::mem::transmute(entry_addr) };

    // Execute (timeout is checked after execution completes)
    // Note: Actual timeout termination would require more complex threading,
    // so we check execution time against timeout limit instead
    let execution_start = Instant::now();

    // For BOFs, pass null pointer when no args, otherwise a valid pointer
    let (args_ptr, args_len) = if args.is_empty() {
        (std::ptr::null(), 0i32)
    } else {
        (args.as_ptr(), args.len() as i32)
    };

    if is_debug_mode() {
        eprintln!("[BOF] Executing at 0x{:x}...", entry_addr);

        // Dump first 32 bytes at entry point for debugging
        unsafe {
            let code_ptr = entry_addr as *const u8;
            let mut bytes = Vec::new();
            for i in 0..32 {
                bytes.push(*code_ptr.add(i));
            }
            eprintln!("[BOF] Entry point bytes: {:02x?}", bytes);
        }

        eprintln!("[BOF] Calling go({:p}, {})", args_ptr, args_len);
    }

    // Install exception handler to catch access violations
    #[cfg(windows)]
    let exception_handler_handle = unsafe {
        CRASH_INFO = None;
        AddVectoredExceptionHandler(1, Some(exception_handler))
    };

    let execution_result = std::panic::catch_unwind(|| unsafe {
        go_func(args_ptr, args_len);
    });

    // Remove exception handler
    #[cfg(windows)]
    unsafe {
        if !exception_handler_handle.is_null() {
            RemoveVectoredExceptionHandler(exception_handler_handle);
        }
        // Always show crash details - this is important diagnostic info
        if let Some((access_addr, instr_addr)) = CRASH_INFO {
            eprintln!(
                "[BOF] Crash details - Instruction: 0x{:x}, Access: 0x{:x}",
                instr_addr, access_addr
            );
            let code_base = memory.base() as u64;
            if instr_addr >= code_base && instr_addr < code_base + total_size as u64 {
                eprintln!(
                    "[BOF]   Crash at code offset: 0x{:x}",
                    instr_addr - code_base
                );
            }
        }
    }
    let execution_duration = execution_start.elapsed();

    // Check if execution exceeded timeout
    let timed_out = timeout.as_secs() > 0 && execution_duration > timeout;

    let execution_time = start.elapsed();

    // Collect output
    let output_entries = global_output().get_entries();
    let output: Vec<OutputMessage> = output_entries
        .iter()
        .map(|entry| OutputMessage {
            timestamp: chrono::Utc::now().to_rfc3339(),
            message_type: match entry.callback_type {
                0x00 => OutputType::Output,
                0x0d => OutputType::Error,
                _ => OutputType::Custom,
            },
            content: String::from_utf8_lossy(&entry.data).to_string(),
        })
        .collect();

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
        resolved_imports,
        code_base_address: Some(memory.base() as u64),
    })
}

/// Test a BOF (execute without arguments)
#[cfg(windows)]
pub fn test_bof(path: &std::path::PathBuf, _continue_on_error: bool) -> Result<ExecutionResult> {
    // Load and parse BOF
    let bof = parser::load_bof(path)?;

    // Execute without arguments
    execute(&bof, &[], false, false, Duration::from_secs(30), false)
}

/// Test a BOF (non-Windows stub)
#[cfg(not(windows))]
pub fn test_bof(_path: &std::path::PathBuf, _continue_on_error: bool) -> Result<ExecutionResult> {
    anyhow::bail!("BOF execution is only supported on Windows. Use a Windows loader (RedLoader, COFFLoader) on the target VM instead.")
}
