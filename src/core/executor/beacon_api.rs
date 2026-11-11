//! Beacon API emulation
#![cfg(windows)]

use std::sync::{Mutex, OnceLock};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use windows::Win32::Foundation::{BOOL, HANDLE, CloseHandle, HMODULE};
#[cfg(windows)]
use windows::Win32::System::Memory::*;
#[cfg(windows)]
use windows::Win32::Security::*;
#[cfg(windows)]
use windows::Win32::System::Threading::*;
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
#[cfg(windows)]
use windows::core::PCSTR;

/// Output capture for Beacon API calls (cross-platform, see `capture.rs`;
/// re-exported here for existing callers).
pub use crate::core::executor::capture::{OutputCapture, OutputEntry};

/// Route one output entry to the bound task sink or the global capture.
use crate::core::executor::capture::push_output;

/// Data parser structure (matches Cobalt Strike's datap)
#[repr(C)]
pub struct DataParser {
    pub original: *const u8,
    pub buffer: *const u8,
    pub length: i32,
    pub size: i32,
}

impl DataParser {
    /// Initialize parser
    pub unsafe fn init(parser: *mut DataParser, buffer: *const u8, size: i32) {
        if parser.is_null() {
            return;
        }
        (*parser).original = buffer;
        (*parser).buffer = buffer;
        (*parser).length = size;
        (*parser).size = size;
    }
    
    /// Extract int32
    pub unsafe fn extract_int(parser: *mut DataParser) -> i32 {
        if parser.is_null() || (*parser).length < 4 {
            return 0;
        }
        let value = std::ptr::read((*parser).buffer as *const i32);
        (*parser).buffer = (*parser).buffer.add(4);
        (*parser).length -= 4;
        value
    }
    
    /// Extract int16
    pub unsafe fn extract_short(parser: *mut DataParser) -> i16 {
        if parser.is_null() || (*parser).length < 2 {
            return 0;
        }
        let value = std::ptr::read((*parser).buffer as *const i16);
        (*parser).buffer = (*parser).buffer.add(2);
        (*parser).length -= 2;
        value
    }
    
    /// Get remaining length
    pub unsafe fn get_length(parser: *mut DataParser) -> i32 {
        if parser.is_null() {
            return 0;
        }
        (*parser).length
    }
    
    /// Extract binary data
    pub unsafe fn extract(parser: *mut DataParser, size: *mut i32) -> *mut u8 {
        if parser.is_null() {
            if !size.is_null() {
                *size = 0;
            }
            return std::ptr::null_mut();
        }
        
        // Read length prefix
        if (*parser).length < 4 {
            if !size.is_null() {
                *size = 0;
            }
            return std::ptr::null_mut();
        }
        
        let data_len = std::ptr::read((*parser).buffer as *const i32) as usize;
        (*parser).buffer = (*parser).buffer.add(4);
        (*parser).length -= 4;
        
        if (*parser).length < data_len as i32 {
            if !size.is_null() {
                *size = 0;
            }
            return std::ptr::null_mut();
        }
        
        // Allocate memory for extracted data
        let data_ptr = libc::malloc(data_len) as *mut u8;
        if data_ptr.is_null() {
            if !size.is_null() {
                *size = 0;
            }
            return std::ptr::null_mut();
        }
        
        std::ptr::copy_nonoverlapping((*parser).buffer, data_ptr, data_len);
        (*parser).buffer = (*parser).buffer.add(data_len);
        (*parser).length -= data_len as i32;
        
        if !size.is_null() {
            *size = data_len as i32;
        }
        
        data_ptr
    }
}

/// Beacon API function implementations
#[allow(dead_code)]
pub struct BeaconApi {
    output: OutputCapture,
}

impl BeaconApi {
    /// Create new Beacon API instance
    pub fn new() -> Self {
        Self {
            output: OutputCapture::new(),
        }
    }
    
    /// Get output capture
    #[allow(dead_code)]
    pub fn output(&self) -> &OutputCapture {
        &self.output
    }
    
    /// BeaconPrintf implementation
    /// 
    /// On x64 Windows, the calling convention passes:
    /// - RCX = callback_type
    /// - RDX = format
    /// - R8 = arg0 (first variadic)
    /// - R9 = arg1 (second variadic)
    /// - Stack = arg2, arg3, ... (additional variadic args)
    /// 
    /// We declare extra parameters to capture up to 6 variadic arguments, which
    /// covers most BOF usage of BeaconPrintf.
    /// 
    /// Common format specifiers that BOFs use:
    /// - %s - string
    /// - %d, %i - signed decimal
    /// - %u - unsigned decimal  
    /// - %x, %X - hexadecimal
    /// - %p - pointer
    /// - %c - character
    pub unsafe extern "C" fn beacon_printf(
        callback_type: c_int,
        format: *const c_char,
        // Capture variadic arguments - on x64 Windows these come from R8, R9, then stack
        arg0: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) {
        // Record API call for tracing
        crate::core::executor::tracer::record_api_call(
            "BeaconPrintf".to_string(),
            vec![format!("type={}", callback_type)],
        );
        
        if format.is_null() {
            return;
        }
        
        if let Ok(fmt_str) = CStr::from_ptr(format).to_str() {
            // Parse the format string to understand what arguments are expected
            let parts = crate::core::executor::printf::parse_format_string(fmt_str);
            
            // Count format specifiers
            let specifier_count = parts.iter()
                .filter(|p| matches!(p, crate::core::executor::printf::FormatPart::Specifier(_)))
                .count();
            
            // Collect variadic arguments
            let args = [arg0, arg1, arg2, arg3, arg4, arg5];
            
            // Format the string using variadic arguments
            let output = format_printf_string(fmt_str, &parts, &args, specifier_count);
            
            push_output(callback_type as u32, output.into_bytes());
        }
    }
}

/// Format a printf-style string with captured variadic arguments
fn format_printf_string(
    _format: &str,
    parts: &[crate::core::executor::printf::FormatPart],
    args: &[usize],
    specifier_count: usize,
) -> String {
    use crate::core::executor::printf::FormatPart;
    use std::ffi::CStr;
    
    let mut result = String::new();
    let mut arg_idx = 0;
    
    for part in parts {
        match part {
            FormatPart::Literal(s) => {
                result.push_str(s);
            }
            FormatPart::Specifier(spec) => {
                if spec.specifier == 'n' {
                    // %n writes count - skip for safety
                    continue;
                }
                
                if arg_idx >= args.len() || arg_idx >= specifier_count {
                    // Not enough arguments - output specifier as-is
                    result.push_str(&spec.raw);
                    continue;
                }
                
                let arg = args[arg_idx];
                arg_idx += 1;
                
                match spec.specifier {
                    's' => {
                        // String argument
                        if arg == 0 {
                            result.push_str("(null)");
                        } else {
                            let ptr = arg as *const c_char;
                            match std::panic::catch_unwind(|| unsafe { CStr::from_ptr(ptr) }) {
                                Ok(cstr) => {
                                    result.push_str(&cstr.to_string_lossy());
                                }
                                Err(_) => {
                                    result.push_str("(invalid string)");
                                }
                            }
                        }
                    }
                    'd' | 'i' => {
                        // Signed integer
                        let has_long = spec.raw.contains('l');
                        if has_long {
                            result.push_str(&format!("{}", arg as i64));
                        } else {
                            result.push_str(&format!("{}", arg as i32));
                        }
                    }
                    'u' => {
                        // Unsigned integer
                        let has_long = spec.raw.contains('l');
                        if has_long {
                            result.push_str(&format!("{}", arg as u64));
                        } else {
                            result.push_str(&format!("{}", arg as u32));
                        }
                    }
                    'x' | 'X' => {
                        // Hexadecimal
                        let has_long = spec.raw.contains('l');
                        let uppercase = spec.specifier == 'X';
                        if has_long {
                            if uppercase {
                                result.push_str(&format!("{:X}", arg as u64));
                            } else {
                                result.push_str(&format!("{:x}", arg as u64));
                            }
                        } else {
                            if uppercase {
                                result.push_str(&format!("{:X}", arg as u32));
                            } else {
                                result.push_str(&format!("{:x}", arg as u32));
                            }
                        }
                    }
                    'p' => {
                        // Pointer
                        result.push_str(&format!("{:#x}", arg));
                    }
                    'c' => {
                        // Character
                        result.push((arg as u8) as char);
                    }
                    _ => {
                        // Unknown specifier - output as-is
                        result.push_str(&spec.raw);
                    }
                }
            }
        }
    }
    
    result
}

impl BeaconApi {
    
    /// BeaconOutput implementation
    pub unsafe extern "C" fn beacon_output(
        callback_type: c_int,
        data: *const u8,
        length: usize,
    ) {
        if !data.is_null() && length > 0 {
            let data_vec = std::slice::from_raw_parts(data, length).to_vec();
            push_output(callback_type as u32, data_vec);
        }
    }
    
    /// BeaconDataParse implementation
    pub unsafe extern "C" fn beacon_data_parse(
        parser: *mut DataParser,
        buffer: *const u8,
        size: i32,
    ) {
        DataParser::init(parser, buffer, size);
    }
    
    /// BeaconDataInt implementation
    pub unsafe extern "C" fn beacon_data_int(parser: *mut DataParser) -> i32 {
        DataParser::extract_int(parser)
    }
    
    /// BeaconDataShort implementation
    pub unsafe extern "C" fn beacon_data_short(parser: *mut DataParser) -> i16 {
        DataParser::extract_short(parser)
    }
    
    /// BeaconDataLength implementation
    pub unsafe extern "C" fn beacon_data_length(parser: *mut DataParser) -> i32 {
        DataParser::get_length(parser)
    }
    
    /// BeaconDataExtract implementation
    /// 
    /// Returns a pointer to extracted data, or a pointer to an empty buffer
    /// (instead of NULL) to prevent crashes when BOFs dereference the pointer
    /// to check for empty strings.
    pub unsafe extern "C" fn beacon_data_extract(
        parser: *mut DataParser,
        size: *mut i32,
    ) -> *mut u8 {
        // Static empty buffer for when there's no data
        // This prevents crashes when BOFs dereference the pointer to check for empty strings
        static EMPTY_BUFFER: [u8; 1] = [0];
        
        let result = DataParser::extract(parser, size);
        
        // If extract returns NULL (no more data), return empty buffer instead
        // to prevent crashes when BOFs check *ptr == 0
        if result.is_null() {
            if !size.is_null() {
                *size = 0;
            }
            // Return a pointer to the static empty buffer
            // Note: This is safe because the buffer is static and will live for the program lifetime
            EMPTY_BUFFER.as_ptr() as *mut u8
        } else {
            result
        }
    }
    
    /// BeaconDataPtr implementation
    /// Returns a pointer to data without extracting it (advances parser)
    pub unsafe extern "C" fn beacon_data_ptr(parser: *mut DataParser, size: i32) -> *const u8 {
        if parser.is_null() || (*parser).length < size {
            return std::ptr::null();
        }
        
        let ptr = (*parser).buffer;
        (*parser).buffer = (*parser).buffer.add(size as usize);
        (*parser).length -= size;
        ptr
    }
}

/// Format parser structure (matches Cobalt Strike's formatp)
#[repr(C)]
pub struct FormatParser {
    pub original: *mut u8,
    pub buffer: *mut u8,
    pub length: i32,
    pub size: i32,
}

/// Data store structure (simplified for emulation)
/// Note: We use usize for buffer to avoid Send/Sync issues with raw pointers
#[repr(C)]
pub struct DataStoreObject {
    pub type_: c_int,
    pub hash: u64,
    pub masked: BOOL,
    pub buffer: usize, // Store as usize to avoid Send/Sync issues, convert to *mut c_char when needed
    pub length: usize,
}

/// Heap record structure (matches Cobalt Strike's HEAP_RECORD)
#[repr(C)]
pub struct HeapRecord {
    pub ptr: *mut c_char,
    pub size: usize,
}

/// Allocated memory section structure (matches Cobalt Strike's ALLOCATED_MEMORY_SECTION)
#[repr(C)]
pub struct AllocatedMemorySection {
    pub label: u32,              // ALLOCATED_MEMORY_LABEL
    pub base_address: *mut std::ffi::c_void,
    pub virtual_size: usize,
    pub current_protect: u32,
    pub previous_protect: u32,
    pub mask_section: u32,        // BOOL
    pub dripload_page_size: u32,
}

/// Allocated memory cleanup information (matches Cobalt Strike's ALLOCATED_MEMORY_CLEANUP_INFORMATION)
#[repr(C)]
pub struct AllocatedMemoryCleanupInformation {
    pub cleanup: u32,            // BOOL
    pub allocation_method: u32,   // ALLOCATED_MEMORY_ALLOCATION_METHOD
    pub additional_cleanup_info: [u8; 16], // Union of HEAPALLOC_INFO, MODULESTOMP_INFO, or PVOID
}

/// Allocated memory region structure (matches Cobalt Strike's ALLOCATED_MEMORY_REGION)
#[repr(C)]
pub struct AllocatedMemoryRegion {
    pub purpose: u32,             // ALLOCATED_MEMORY_PURPOSE
    pub allocation_base: *mut std::ffi::c_void,
    pub region_size: usize,
    pub type_: u32,
    pub dripload_allocation_granularity: u32,
    pub sections: [AllocatedMemorySection; 8],
    pub cleanup_information: AllocatedMemoryCleanupInformation,
}

/// Allocated memory structure (matches Cobalt Strike's ALLOCATED_MEMORY)
#[repr(C)]
pub struct AllocatedMemory {
    pub allocated_memory_regions: [AllocatedMemoryRegion; 6],
}

/// Beacon information structure (matches Cobalt Strike's BEACON_INFO)
#[repr(C)]
pub struct BeaconInfo {
    pub version: u32,
    pub sleep_mask_ptr: *mut c_char,
    pub sleep_mask_text_size: u32,
    pub sleep_mask_total_size: u32,
    pub beacon_ptr: *mut c_char,
    pub heap_records: *mut HeapRecord,
    pub mask: [u8; 13],           // MASK_SIZE = 13
    pub allocated_memory: AllocatedMemory,
}

/// System call API entry structure (matches Cobalt Strike's SYSCALL_API_ENTRY)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SyscallApiEntry {
    pub fn_addr: *mut std::ffi::c_void,
    pub jmp_addr: *mut std::ffi::c_void,
    pub sysnum: u32,
}

/// System call API structure (matches Cobalt Strike's SYSCALL_API)
#[repr(C)]
pub struct SyscallApi {
    pub nt_allocate_virtual_memory: SyscallApiEntry,
    pub nt_protect_virtual_memory: SyscallApiEntry,
    pub nt_free_virtual_memory: SyscallApiEntry,
    pub nt_get_context_thread: SyscallApiEntry,
    pub nt_set_context_thread: SyscallApiEntry,
    pub nt_resume_thread: SyscallApiEntry,
    pub nt_create_thread_ex: SyscallApiEntry,
    pub nt_open_process: SyscallApiEntry,
    pub nt_open_thread: SyscallApiEntry,
    pub nt_close: SyscallApiEntry,
    pub nt_create_section: SyscallApiEntry,
    pub nt_map_view_of_section: SyscallApiEntry,
    pub nt_unmap_view_of_section: SyscallApiEntry,
    pub nt_query_virtual_memory: SyscallApiEntry,
    pub nt_duplicate_object: SyscallApiEntry,
    pub nt_read_virtual_memory: SyscallApiEntry,
    pub nt_write_virtual_memory: SyscallApiEntry,
    pub nt_read_file: SyscallApiEntry,
    pub nt_write_file: SyscallApiEntry,
    pub nt_create_file: SyscallApiEntry,
    pub nt_queue_apc_thread: SyscallApiEntry,
    pub nt_create_process: SyscallApiEntry,
    pub nt_open_process_token: SyscallApiEntry,
    pub nt_test_alert: SyscallApiEntry,
    pub nt_suspend_process: SyscallApiEntry,
    pub nt_resume_process: SyscallApiEntry,
    pub nt_query_system_information: SyscallApiEntry,
    pub nt_query_directory_file: SyscallApiEntry,
    pub nt_set_information_process: SyscallApiEntry,
    pub nt_set_information_thread: SyscallApiEntry,
    pub nt_query_information_process: SyscallApiEntry,
    pub nt_query_information_thread: SyscallApiEntry,
    pub nt_open_section: SyscallApiEntry,
    pub nt_adjust_privileges_token: SyscallApiEntry,
    pub nt_device_io_control_file: SyscallApiEntry,
    pub nt_wait_for_multiple_objects: SyscallApiEntry,
}

/// RTL API structure (matches Cobalt Strike's RTL_API)
#[repr(C)]
pub struct RtlApi {
    pub rtl_dos_path_name_to_nt_path_name_u_with_status_addr: *mut std::ffi::c_void,
    pub rtl_free_heap_addr: *mut std::ffi::c_void,
    pub rtl_get_process_heap_addr: *mut std::ffi::c_void,
}

/// Beacon syscalls structure (matches Cobalt Strike's BEACON_SYSCALLS)
#[repr(C)]
pub struct BeaconSyscalls {
    pub syscalls: SyscallApi,
    pub rtls: RtlApi,
}

// ===== Beacon syscall information emulation support =====

/// Global flag controlling whether BeaconGetSyscallInformation should resolve
/// real syscall information from the host OS (ntdll.dll) or return a zeroed stub.
#[cfg(windows)]
static SYSCALL_INFO_FROM_OS: OnceLock<AtomicBool> = OnceLock::new();

/// Global flag controlling whether we should print detailed debug information
/// about resolved syscalls (for comparison with BOF output).
#[cfg(windows)]
static SYSCALL_TRACE_ENABLED: OnceLock<AtomicBool> = OnceLock::new();

#[cfg(windows)]
fn is_syscall_os_emulation_enabled() -> bool {
    SYSCALL_INFO_FROM_OS
        .get_or_init(|| AtomicBool::new(false))
        .load(Ordering::Relaxed)
}

#[cfg(windows)]
fn is_syscall_trace_enabled() -> bool {
    SYSCALL_TRACE_ENABLED
        .get_or_init(|| AtomicBool::new(false))
        .load(Ordering::Relaxed)
}

/// Enable or disable syscall information emulation from the OS.
///
/// This is toggled from the BOF executor based on the "Emulate BeaconInformation"
/// checkbox in the GUI. When enabled, BeaconGetSyscallInformation will attempt
/// to read the real system service numbers (SSNs) from the local ntdll.dll.
#[cfg(windows)]
pub fn set_syscall_os_emulation_enabled(enable: bool) {
    SYSCALL_INFO_FROM_OS
        .get_or_init(|| AtomicBool::new(false))
        .store(enable, Ordering::Relaxed);
}

/// Enable or disable verbose syscall resolution tracing.
///
/// This is typically wired to the "Trace Beacon API calls" checkbox so that
/// when tracing is enabled, the loader also dumps the resolved syscall table
/// to stderr for debugging/comparison.
#[cfg(windows)]
pub fn set_syscall_trace_enabled(enable: bool) {
    SYSCALL_TRACE_ENABLED
        .get_or_init(|| AtomicBool::new(false))
        .store(enable, Ordering::Relaxed);
}

/// Get the handle to the local ntdll.dll module.
///
/// We call LoadLibraryA each time. On Windows this is effectively idempotent:
/// if the module is already loaded in the process, the existing handle is
/// returned. This avoids having to store HMODULE in a global (which is not
/// Send/Sync-safe).
#[cfg(windows)]
unsafe fn get_ntdll_module() -> Option<HMODULE> {
    // Use a static null-terminated string to avoid lifetime issues.
    let name = b"ntdll.dll\0";
    // LoadLibraryA will return the existing module if it's already loaded.
    LoadLibraryA(PCSTR(name.as_ptr())).ok()
}

/// Helper to extract a system service number (SSN) from the local ntdll stub.
///
/// This mimics the common Windows x64 syscall stub pattern:
///   4C 8B D1             mov r10, rcx
///   B8 SS 00 00 00       mov eax, SSN
///   0F 05                syscall
#[cfg(windows)]
unsafe fn get_ssn(func_name: &str) -> u32 {
    let module = match get_ntdll_module() {
        Some(m) => m,
        None => return 0,
    };

    let func_cstr = match CString::new(func_name) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let addr = match GetProcAddress(module, PCSTR(func_cstr.as_ptr() as *const u8)) {
        Some(p) => p as *const u8,
        None => return 0,
    };

    if addr.is_null() {
        return 0;
    }

    // We expect opcode 0xB8 at offset 3 (mov eax, SSN)
    // Guard accesses to avoid UB if the stub is malformed.
    let mov_eax_opcode = *addr.add(3);
    if mov_eax_opcode != 0xB8 {
        // Likely hooked or non-standard stub format.
        return 0;
    }

    // Read the DWORD following the 0xB8 opcode.
    let ssn_ptr = addr.add(4) as *const u32;
    ssn_ptr.read_unaligned()
}

/// Initialize a SyscallApiEntry from the local ntdll export table.
///
/// - fn_addr: address of the Nt* function
/// - sysnum: system service number extracted from the stub (0 if not resolvable)
/// - jmp_addr: approximate address of the `syscall` instruction (fn_addr + 0x12)
#[cfg(windows)]
unsafe fn fill_syscall_entry(entry: &mut SyscallApiEntry, name: &str) {
    let module = match get_ntdll_module() {
        Some(m) => m,
        None => {
            entry.fn_addr = std::ptr::null_mut();
            entry.jmp_addr = std::ptr::null_mut();
            entry.sysnum = 0;
            return;
        }
    };

    let func_cstr = match CString::new(name) {
        Ok(s) => s,
        Err(_) => {
            entry.fn_addr = std::ptr::null_mut();
            entry.jmp_addr = std::ptr::null_mut();
            entry.sysnum = 0;
            return;
        }
    };

    let fn_addr = match GetProcAddress(module, PCSTR(func_cstr.as_ptr() as *const u8)) {
        Some(p) => p as *mut std::ffi::c_void,
        None => std::ptr::null_mut(),
    };

    entry.fn_addr = fn_addr;
    entry.sysnum = get_ssn(name);

    if !fn_addr.is_null() {
        // In typical ntdll stubs the syscall is at offset ~0x12 from the function start.
        entry.jmp_addr = (fn_addr as *mut u8).add(0x12) as *mut std::ffi::c_void;
    } else {
        entry.jmp_addr = std::ptr::null_mut();
    }
}

/// Initialize an RTL API entry from ntdll.dll.
#[cfg(windows)]
unsafe fn fill_rtl_entry(target: &mut *mut std::ffi::c_void, name: &str) {
    let module = match get_ntdll_module() {
        Some(m) => m,
        None => {
            *target = std::ptr::null_mut();
            return;
        }
    };

    let func_cstr = match CString::new(name) {
        Ok(s) => s,
        Err(_) => {
            *target = std::ptr::null_mut();
            return;
        }
    };

    let addr = GetProcAddress(module, PCSTR(func_cstr.as_ptr() as *const u8))
        .map(|p| p as *mut std::ffi::c_void)
        .unwrap_or(std::ptr::null_mut());

    *target = addr;
}

/// Initialize all syscall-related fields to a safe zeroed stub.
#[cfg(windows)]
unsafe fn init_beacon_syscalls_zero(info_ref: &mut BeaconSyscalls) {
    let zero_entry = SyscallApiEntry {
        fn_addr: std::ptr::null_mut(),
        jmp_addr: std::ptr::null_mut(),
        sysnum: 0,
    };

    info_ref.syscalls.nt_allocate_virtual_memory = zero_entry;
    info_ref.syscalls.nt_protect_virtual_memory = zero_entry;
    info_ref.syscalls.nt_free_virtual_memory = zero_entry;
    info_ref.syscalls.nt_get_context_thread = zero_entry;
    info_ref.syscalls.nt_set_context_thread = zero_entry;
    info_ref.syscalls.nt_resume_thread = zero_entry;
    info_ref.syscalls.nt_create_thread_ex = zero_entry;
    info_ref.syscalls.nt_open_process = zero_entry;
    info_ref.syscalls.nt_open_thread = zero_entry;
    info_ref.syscalls.nt_close = zero_entry;
    info_ref.syscalls.nt_create_section = zero_entry;
    info_ref.syscalls.nt_map_view_of_section = zero_entry;
    info_ref.syscalls.nt_unmap_view_of_section = zero_entry;
    info_ref.syscalls.nt_query_virtual_memory = zero_entry;
    info_ref.syscalls.nt_duplicate_object = zero_entry;
    info_ref.syscalls.nt_read_virtual_memory = zero_entry;
    info_ref.syscalls.nt_write_virtual_memory = zero_entry;
    info_ref.syscalls.nt_read_file = zero_entry;
    info_ref.syscalls.nt_write_file = zero_entry;
    info_ref.syscalls.nt_create_file = zero_entry;
    info_ref.syscalls.nt_queue_apc_thread = zero_entry;
    info_ref.syscalls.nt_create_process = zero_entry;
    info_ref.syscalls.nt_open_process_token = zero_entry;
    info_ref.syscalls.nt_test_alert = zero_entry;
    info_ref.syscalls.nt_suspend_process = zero_entry;
    info_ref.syscalls.nt_resume_process = zero_entry;
    info_ref.syscalls.nt_query_system_information = zero_entry;
    info_ref.syscalls.nt_query_directory_file = zero_entry;
    info_ref.syscalls.nt_set_information_process = zero_entry;
    info_ref.syscalls.nt_set_information_thread = zero_entry;
    info_ref.syscalls.nt_query_information_process = zero_entry;
    info_ref.syscalls.nt_query_information_thread = zero_entry;
    info_ref.syscalls.nt_open_section = zero_entry;
    info_ref.syscalls.nt_adjust_privileges_token = zero_entry;
    info_ref.syscalls.nt_device_io_control_file = zero_entry;
    info_ref.syscalls.nt_wait_for_multiple_objects = zero_entry;

    info_ref.rtls.rtl_dos_path_name_to_nt_path_name_u_with_status_addr = std::ptr::null_mut();
    info_ref.rtls.rtl_free_heap_addr = std::ptr::null_mut();
    info_ref.rtls.rtl_get_process_heap_addr = std::ptr::null_mut();
}

/// Emit a debug dump of all resolved syscalls and RTL functions.
///
/// This is only active when syscall tracing is enabled, and is intended purely
/// for developer comparison with the BOF's own `dump_syscalls` output.
#[cfg(windows)]
unsafe fn trace_beacon_syscalls(info_ref: &BeaconSyscalls) {
    if !is_syscall_trace_enabled() {
        return;
    }

    eprintln!("[BeaconGetSyscallInformation] Resolved syscall table from local ntdll.dll:");

    // Helper macro to reduce repetition when printing entries.
    macro_rules! dump_entry {
        ($name:expr, $entry:expr) => {
            eprintln!(
                "  {:28} fnAddr: {:?} jmpAddr: {:?} sysnum: {}",
                $name,
                $entry.fn_addr,
                $entry.jmp_addr,
                $entry.sysnum
            );
        };
    }

    let s = &info_ref.syscalls;
    dump_entry!("NtAllocateVirtualMemory", s.nt_allocate_virtual_memory);
    dump_entry!("NtProtectVirtualMemory", s.nt_protect_virtual_memory);
    dump_entry!("NtFreeVirtualMemory", s.nt_free_virtual_memory);
    dump_entry!("NtGetContextThread", s.nt_get_context_thread);
    dump_entry!("NtSetContextThread", s.nt_set_context_thread);
    dump_entry!("NtResumeThread", s.nt_resume_thread);
    dump_entry!("NtCreateThreadEx", s.nt_create_thread_ex);
    dump_entry!("NtOpenProcess", s.nt_open_process);
    dump_entry!("NtOpenThread", s.nt_open_thread);
    dump_entry!("NtClose", s.nt_close);
    dump_entry!("NtCreateSection", s.nt_create_section);
    dump_entry!("NtMapViewOfSection", s.nt_map_view_of_section);
    dump_entry!("NtUnmapViewOfSection", s.nt_unmap_view_of_section);
    dump_entry!("NtQueryVirtualMemory", s.nt_query_virtual_memory);
    dump_entry!("NtDuplicateObject", s.nt_duplicate_object);
    dump_entry!("NtReadVirtualMemory", s.nt_read_virtual_memory);
    dump_entry!("NtWriteVirtualMemory", s.nt_write_virtual_memory);
    dump_entry!("NtReadFile", s.nt_read_file);
    dump_entry!("NtWriteFile", s.nt_write_file);
    dump_entry!("NtCreateFile", s.nt_create_file);
    dump_entry!("NtQueueApcThread", s.nt_queue_apc_thread);
    dump_entry!("NtCreateProcess", s.nt_create_process);
    dump_entry!("NtOpenProcessToken", s.nt_open_process_token);
    dump_entry!("NtTestAlert", s.nt_test_alert);
    dump_entry!("NtSuspendProcess", s.nt_suspend_process);
    dump_entry!("NtResumeProcess", s.nt_resume_process);
    dump_entry!("NtQuerySystemInformation", s.nt_query_system_information);
    dump_entry!("NtQueryDirectoryFile", s.nt_query_directory_file);
    dump_entry!("NtSetInformationProcess", s.nt_set_information_process);
    dump_entry!("NtSetInformationThread", s.nt_set_information_thread);
    dump_entry!("NtQueryInformationProcess", s.nt_query_information_process);
    dump_entry!("NtQueryInformationThread", s.nt_query_information_thread);
    dump_entry!("NtOpenSection", s.nt_open_section);
    dump_entry!("NtAdjustPrivilegesToken", s.nt_adjust_privileges_token);
    dump_entry!("NtDeviceIoControlFile", s.nt_device_io_control_file);
    dump_entry!("NtWaitForMultipleObjects", s.nt_wait_for_multiple_objects);

    eprintln!("[BeaconGetSyscallInformation] RTL functions:");
    eprintln!(
        "  {:28} addr: {:?}",
        "RtlDosPathNameToNtPathNameUWithStatus",
        info_ref
            .rtls
            .rtl_dos_path_name_to_nt_path_name_u_with_status_addr
    );
    eprintln!("  {:28} addr: {:?}", "RtlFreeHeap", info_ref.rtls.rtl_free_heap_addr);
    eprintln!(
        "  {:28} addr: {:?}",
        "RtlGetProcessHeap",
        info_ref.rtls.rtl_get_process_heap_addr
    );
}

// ===== BeaconInformation emulation support =====

/// Internal section info used for BeaconInformation emulation
#[cfg(windows)]
#[derive(Clone)]
struct BeaconSectionInfo {
    label: u32,
    base_address: usize,
    virtual_size: usize,
    current_protect: u32,
}

/// Internal runtime info used for BeaconInformation emulation
#[cfg(windows)]
#[derive(Clone)]
struct BeaconRuntimeInfo {
    base_address: usize,
    region_size: usize,
    sections: Vec<BeaconSectionInfo>,
    sleep_mask_base: usize,
    sleep_mask_text_size: u32,
    sleep_mask_total_size: u32,
    mask: [u8; 13],
}

/// Global state for BeaconInformation emulation
#[cfg(windows)]
struct BeaconEmulationState {
    runtime: Option<BeaconRuntimeInfo>,
    // store (ptr_addr, size) pairs to keep this Send-safe; we rebuild HeapRecord on demand
    heap_records: Vec<(usize, usize)>,
}

#[cfg(windows)]
static BEACON_EMULATION_STATE: OnceLock<Mutex<BeaconEmulationState>> = OnceLock::new();

#[cfg(windows)]
fn get_beacon_emulation_state() -> &'static Mutex<BeaconEmulationState> {
    BEACON_EMULATION_STATE.get_or_init(|| Mutex::new(BeaconEmulationState {
        runtime: None,
        heap_records: Vec::new(),
    }))
}

/// Initialize or clear BeaconInformation emulation runtime based on loader state.
///
/// This is called from the BOF executor after sections are loaded.
#[cfg(windows)]
pub fn initialize_beacon_information_emulation(
    base: *mut u8,
    total_size: usize,
    sections: &[crate::core::executor::loader::SectionMapping],
    enable: bool,
) {
    use windows::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_READWRITE};

    let mut state = get_beacon_emulation_state().lock().unwrap();

    if !enable {
        state.runtime = None;
        state.heap_records.clear();
        return;
    }

    let base_addr = base as usize;

    // Build section info from loader mappings
    let mut section_infos = Vec::new();
    for m in sections {
        let name = m.name.to_ascii_lowercase();
        let label = if name == ".text" {
            3 // LABEL_TEXT
        } else if name == ".rdata" {
            4 // LABEL_RDATA
        } else if name == ".data" {
            5 // LABEL_DATA
        } else {
            1 // LABEL_BUFFER (generic)
        };

        let protect = if label == 3 {
            PAGE_EXECUTE_READ.0
        } else {
            PAGE_READWRITE.0
        };

        section_infos.push(BeaconSectionInfo {
            label,
            base_address: m.virtual_address,
            virtual_size: m.size,
            current_protect: protect,
        });
    }

    // Choose a sleep mask region based on .text section if available
    let (sleep_base, sleep_text_size, sleep_total_size) = if let Some(text) =
        section_infos.iter().find(|s| s.label == 3)
    {
        let text_sz = text.virtual_size.min(8192) as u32;
        let total_sz = (text.virtual_size.min(16384)) as u32;
        (text.base_address as *mut c_char, text_sz, total_sz)
    } else if let Some(first) = section_infos.first() {
        let sz = first.virtual_size.min(4096) as u32;
        (first.base_address as *mut c_char, sz, sz * 2)
    } else {
        (std::ptr::null_mut(), 0, 0)
    };

    // Generate a pseudo-random 13-byte mask based on time and base address
    let mut mask = [0u8; 13];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seed = now ^ (base as usize as u128);
    for i in 0..13 {
        mask[i] = ((seed >> (i * 5)) & 0xFF) as u8;
    }

    // PURPOSE_BEACON_MEMORY = 2, METHOD_VIRTUALALLOC = 1
    let runtime = BeaconRuntimeInfo {
        base_address: base_addr,
        region_size: total_size,
        sections: section_infos,
        sleep_mask_base: sleep_base as usize,
        sleep_mask_text_size: sleep_text_size,
        sleep_mask_total_size: sleep_total_size,
        mask,
    };

    // Emulate a few heap records inside the allocated region to look realistic.
    state.heap_records.clear();
    if total_size >= 0x2000 {
        let base_u = base as usize;
        state.heap_records.push((base_u + 0x1000, 512));
        state.heap_records.push((base_u + 0x1500, 1024));
        state.heap_records.push((base_u + 0x2000, 128));
    }

    state.runtime = Some(runtime);
}

/// Key/Value store for BOFs to persist data across executions
use std::time::{SystemTime, UNIX_EPOCH};
// Use usize instead of *mut c_void to avoid Send/Sync issues
static KEY_VALUE_STORE: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

fn get_key_value_store() -> &'static Mutex<HashMap<String, usize>> {
    KEY_VALUE_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Data store for tracking allocated DataStoreObject items
static DATA_STORE: OnceLock<Mutex<Vec<DataStoreObject>>> = OnceLock::new();

fn get_data_store() -> &'static Mutex<Vec<DataStoreObject>> {
    DATA_STORE.get_or_init(|| Mutex::new(Vec::new()))
}

impl BeaconApi {
    // ===== Token APIs =====
    
    /// BeaconUseToken implementation (Windows)
    /// Impersonates a token for privilege escalation
    /// 
    /// This function attempts to impersonate the security context of the specified token.
    /// Returns TRUE if successful, FALSE otherwise.
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_use_token(token: HANDLE) -> BOOL {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconUseToken".to_string(),
            vec![format!("token={:?}", token)],
        );
        
        if token.is_invalid() {
            return BOOL::from(false);
        }
        
        // Check sandbox
        if !crate::core::executor::sandbox::is_api_allowed("BeaconUseToken") {
            crate::core::executor::tracer::record_api_call(
                "BeaconUseToken".to_string(),
                vec!["BLOCKED_BY_SANDBOX".to_string()],
            );
            return BOOL::from(false);
        }
        
        // Validate token handle is valid before attempting impersonation
        // In a real beacon, this would check if the token is a valid impersonation token
        // For emulation, we attempt the call and handle errors gracefully
        
        // Try to impersonate the token
        let result = ImpersonateLoggedOnUser(token);
        match result {
            Ok(_) => {
                // Successfully impersonated - record success
                crate::core::executor::tracer::record_api_call(
                    "BeaconUseToken".to_string(),
                    vec!["SUCCESS".to_string()],
                );
                BOOL::from(true)
            }
            Err(e) => {
                // Failed to impersonate - record error code for debugging
                crate::core::executor::tracer::record_api_call(
                    "BeaconUseToken".to_string(),
                    vec![format!("FAILED: {:?}", e)],
                );
                BOOL::from(false)
            }
        }
    }
    
    /// BeaconUseToken implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_use_token(_token: *mut std::ffi::c_void) -> i32 {
        0 // Not supported on non-Windows
    }
    
    /// BeaconRevertToken implementation (Windows)
    /// Reverts to the original token (stops impersonation)
    /// 
    /// This function terminates the impersonation of a client application,
    /// reverting to the primary token that was in effect before impersonation.
    /// Always succeeds (no return value in C API).
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_revert_token() {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconRevertToken".to_string(),
            vec![],
        );
        
        // RevertToSelf always succeeds (it's a void function in the C API)
        // Even if there's no active impersonation, it's safe to call
        match RevertToSelf() {
            Ok(_) => {
                crate::core::executor::tracer::record_api_call(
                    "BeaconRevertToken".to_string(),
                    vec!["SUCCESS".to_string()],
                );
            }
            Err(_) => {
                // Should not happen, but handle gracefully
                crate::core::executor::tracer::record_api_call(
                    "BeaconRevertToken".to_string(),
                    vec!["UNEXPECTED_ERROR".to_string()],
                );
            }
        }
    }
    
    /// BeaconRevertToken implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_revert_token() {
        // No-op on non-Windows
    }
    
    /// BeaconIsAdmin implementation (Windows)
    /// Checks if the current process is running with administrator privileges
    /// 
    /// This function checks if the current process token has elevated privileges.
    /// Returns TRUE if running as administrator, FALSE otherwise.
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_is_admin() -> BOOL {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconIsAdmin".to_string(),
            vec![],
        );
        
        // Open the process token
        let mut token = HANDLE::default();
        let process = GetCurrentProcess();
        
        let result = OpenProcessToken(
            process,
            TOKEN_QUERY,
            &mut token,
        );
        
        if result.is_err() || token.is_invalid() {
            crate::core::executor::tracer::record_api_call(
                "BeaconIsAdmin".to_string(),
                vec!["FAILED_TO_OPEN_TOKEN".to_string()],
            );
            return BOOL::from(false);
        }
        
        // Check for admin privileges using TokenElevation
        // This is the most reliable method on Windows Vista and later
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        
        // Always close the token handle
        let _ = CloseHandle(token);
        
        if result.is_ok() {
            let is_elevated = elevation.TokenIsElevated != 0;
            crate::core::executor::tracer::record_api_call(
                "BeaconIsAdmin".to_string(),
                vec![format!("is_elevated={}", is_elevated)],
            );
            BOOL::from(is_elevated)
        } else {
            // If TokenElevation check failed, try alternative method using groups
            // Check if the token is in the Administrators group
            // This is a fallback for older systems or if TokenElevation fails
            crate::core::executor::tracer::record_api_call(
                "BeaconIsAdmin".to_string(),
                vec!["TOKEN_ELEVATION_CHECK_FAILED".to_string()],
            );
            BOOL::from(false)
        }
    }
    
    /// BeaconIsAdmin implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_is_admin() -> i32 {
        0 // Not supported on non-Windows
    }
    
    // ===== Format APIs =====
    
    /// BeaconFormatAlloc implementation
    /// Allocates a format buffer for building formatted strings
    /// 
    /// This function allocates a buffer that can be used to build formatted output
    /// using the other BeaconFormat* functions. The buffer must be freed with
    /// BeaconFormatFree when done.
    /// 
    /// Parameters:
    /// - format: Pointer to FormatParser structure to initialize
    /// - maxsz: Maximum size of the format buffer in bytes
    pub unsafe extern "C" fn beacon_format_alloc(format: *mut FormatParser, maxsz: i32) {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconFormatAlloc".to_string(),
            vec![format!("maxsz={}", maxsz)],
        );
        
        // Validate parameters
        if format.is_null() {
            crate::core::executor::tracer::record_api_call(
                "BeaconFormatAlloc".to_string(),
                vec!["ERROR: NULL_FORMAT_POINTER".to_string()],
            );
            return;
        }
        
        if maxsz <= 0 {
            crate::core::executor::tracer::record_api_call(
                "BeaconFormatAlloc".to_string(),
                vec!["ERROR: INVALID_SIZE".to_string()],
            );
            return;
        }
        
        // Check for reasonable size limits to prevent excessive memory allocation
        const MAX_FORMAT_SIZE: i32 = 10 * 1024 * 1024; // 10 MB max
        if maxsz > MAX_FORMAT_SIZE {
            crate::core::executor::tracer::record_api_call(
                "BeaconFormatAlloc".to_string(),
                vec![format!("ERROR: SIZE_TOO_LARGE (max={})", MAX_FORMAT_SIZE)],
            );
            return;
        }
        
        // Allocate buffer with requested size
        let buffer = libc::malloc(maxsz as usize) as *mut u8;
        if buffer.is_null() {
            crate::core::executor::tracer::record_api_call(
                "BeaconFormatAlloc".to_string(),
                vec!["ERROR: MALLOC_FAILED".to_string()],
            );
            return;
        }
        
        // Initialize the buffer to zero for safety
        std::ptr::write_bytes(buffer, 0, maxsz as usize);
        
        // Initialize the FormatParser structure
        (*format).original = buffer;
        (*format).buffer = buffer;
        (*format).length = maxsz;
        (*format).size = maxsz;
        
        crate::core::executor::tracer::record_api_call(
            "BeaconFormatAlloc".to_string(),
            vec!["SUCCESS".to_string()],
        );
    }
    
    /// BeaconFormatReset implementation
    /// Resets the format buffer to its initial state
    /// 
    /// This function resets the format buffer pointer to the beginning, allowing
    /// the buffer to be reused without reallocating.
    /// 
    /// Parameters:
    /// - format: Pointer to FormatParser structure to reset
    pub unsafe extern "C" fn beacon_format_reset(format: *mut FormatParser) {
        if format.is_null() {
            return;
        }
        
        // Validate that the format buffer was properly allocated
        if (*format).original.is_null() {
            return; // Nothing to reset
        }
        
        // Reset buffer pointer and length
        (*format).buffer = (*format).original;
        (*format).length = (*format).size;
    }
    
    /// BeaconFormatFree implementation
    /// Frees the format buffer allocated by BeaconFormatAlloc
    /// 
    /// This function frees the memory allocated for the format buffer and resets
    /// the FormatParser structure. The format pointer should not be used after
    /// calling this function unless BeaconFormatAlloc is called again.
    /// 
    /// Parameters:
    /// - format: Pointer to FormatParser structure to free
    pub unsafe extern "C" fn beacon_format_free(format: *mut FormatParser) {
        if format.is_null() {
            return;
        }
        
        // Free the allocated buffer if it exists
        if !(*format).original.is_null() {
            libc::free((*format).original as *mut _);
            
            // Reset all fields to prevent use-after-free
            (*format).original = std::ptr::null_mut();
            (*format).buffer = std::ptr::null_mut();
            (*format).length = 0;
            (*format).size = 0;
        }
    }
    
    /// BeaconFormatAppend implementation
    /// Appends raw data to the format buffer
    /// 
    /// This function appends a specified number of bytes from the source buffer
    /// to the format buffer. The data is copied as-is without any formatting.
    /// 
    /// Parameters:
    /// - format: Pointer to FormatParser structure
    /// - text: Pointer to the data to append
    /// - len: Number of bytes to append
    pub unsafe extern "C" fn beacon_format_append(
        format: *mut FormatParser,
        text: *const c_char,
        len: i32,
    ) {
        // Validate parameters
        if format.is_null() {
            return;
        }
        
        if text.is_null() {
            return;
        }
        
        if len <= 0 {
            return;
        }
        
        // Validate format buffer is allocated
        if (*format).original.is_null() || (*format).buffer.is_null() {
            return;
        }
        
        // Check if there's enough space
        if (*format).length < len {
            return; // Not enough space - truncate silently (matches Cobalt Strike behavior)
        }
        
        // Copy the data
        let len_usize = len as usize;
        std::ptr::copy_nonoverlapping(text as *const u8, (*format).buffer, len_usize);
        
        // Advance buffer pointer and update remaining length
        (*format).buffer = (*format).buffer.add(len_usize);
        (*format).length -= len;
    }
    
    /// BeaconFormatPrintf implementation
    /// 
    /// Appends formatted output to the format buffer. Like BeaconPrintf,
    /// full variadic support requires C interop. On x64 Windows, the calling convention passes:
    /// - RCX = format
    /// - RDX = fmt
    /// - R8 = arg0 (first variadic)
    /// - R9 = arg1 (second variadic)
    /// - Stack = arg2, arg3, ... (additional variadic args)
    pub unsafe extern "C" fn beacon_format_printf(
        format: *mut FormatParser,
        fmt: *const c_char,
        // Capture variadic arguments - on x64 Windows these come from R8, R9, then stack
        arg0: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) {
        if format.is_null() || fmt.is_null() {
            return;
        }
        
        // Record API call for tracing
        crate::core::executor::tracer::record_api_call(
            "BeaconFormatPrintf".to_string(),
            vec![],
        );
        
        if let Ok(fmt_str) = CStr::from_ptr(fmt).to_str() {
            // Parse the format string to understand what arguments are expected
            let parts = crate::core::executor::printf::parse_format_string(fmt_str);
            
            // Count format specifiers
            let specifier_count = parts.iter()
                .filter(|p| matches!(p, crate::core::executor::printf::FormatPart::Specifier(_)))
                .count();
            
            // Collect variadic arguments
            let args = [arg0, arg1, arg2, arg3, arg4, arg5];
            
            // Format the string using variadic arguments
            let output = format_printf_string(fmt_str, &parts, &args, specifier_count);
            
            // Append the formatted string to the buffer
            let bytes = output.as_bytes();
            let available = (*format).length as usize;
            let len = bytes.len().min(available);
            
            if len > 0 {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), (*format).buffer, len);
                (*format).buffer = (*format).buffer.add(len);
                (*format).length -= len as i32;
            }
        }
    }
    
    /// BeaconFormatToString implementation
    /// Converts the format buffer to a null-terminated string
    /// 
    /// This function returns a pointer to the start of the format buffer and
    /// optionally sets the size of the data written. The returned pointer is
    /// valid until BeaconFormatFree is called or the buffer is reset.
    /// 
    /// Parameters:
    /// - format: Pointer to FormatParser structure
    /// - size: Optional pointer to receive the size of the formatted data
    /// 
    /// Returns: Pointer to the formatted string, or NULL on error
    pub unsafe extern "C" fn beacon_format_to_string(
        format: *mut FormatParser,
        size: *mut i32,
    ) -> *mut c_char {
        // Validate format pointer
        if format.is_null() {
            if !size.is_null() {
                *size = 0;
            }
            return std::ptr::null_mut();
        }
        
        // Validate format buffer is allocated
        if (*format).original.is_null() {
            if !size.is_null() {
                *size = 0;
            }
            return std::ptr::null_mut();
        }
        
        // Calculate the amount of data written (size - remaining length)
        let used = (*format).size - (*format).length;
        
        // Ensure null termination at the end of written data
        // The buffer was zero-initialized, so this should already be null-terminated
        // But we'll ensure it just to be safe
        let write_pos = (*format).original as usize + used as usize;
        if write_pos < ((*format).original as usize + (*format).size as usize) {
            *((*format).original as *mut u8).add(used as usize) = 0;
        }
        
        // Set size if requested
        if !size.is_null() {
            *size = used;
        }
        
        // Return a pointer to the start of the buffer
        // Note: This is a pointer into the format buffer, caller should copy if needed
        // The buffer remains valid until BeaconFormatFree is called
        (*format).original as *mut c_char
    }
    
    /// BeaconFormatInt implementation
    /// Appends an integer value to the format buffer
    /// 
    /// This function converts an integer to its string representation and
    /// appends it to the format buffer.
    /// 
    /// Parameters:
    /// - format: Pointer to FormatParser structure
    /// - value: Integer value to append
    pub unsafe extern "C" fn beacon_format_int(format: *mut FormatParser, value: i32) {
        // Validate format pointer
        if format.is_null() {
            return;
        }
        
        // Validate format buffer is allocated
        if (*format).original.is_null() || (*format).buffer.is_null() {
            return;
        }
        
        // Convert integer to string
        let formatted = format!("{}", value);
        let bytes = formatted.as_bytes();
        let available = (*format).length as usize;
        let len = bytes.len().min(available);
        
        // Append the formatted string if there's space
        if len > 0 && available > 0 {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), (*format).buffer, len);
            (*format).buffer = (*format).buffer.add(len);
            (*format).length -= len as i32;
        }
    }
    
    /// BeaconFormatShort implementation
    /// Appends a short (int16) value to the format buffer
    /// 
    /// This function converts a short integer to its string representation and
    /// appends it to the format buffer.
    /// 
    /// Parameters:
    /// - format: Pointer to FormatParser structure
    /// - value: Short integer value to append
    pub unsafe extern "C" fn beacon_format_short(format: *mut FormatParser, value: i16) {
        // Validate format pointer
        if format.is_null() {
            return;
        }
        
        // Validate format buffer is allocated
        if (*format).original.is_null() || (*format).buffer.is_null() {
            return;
        }
        
        // Convert short to string
        let formatted = format!("{}", value);
        let bytes = formatted.as_bytes();
        let available = (*format).length as usize;
        let len = bytes.len().min(available);
        
        // Append the formatted string if there's space
        if len > 0 && available > 0 {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), (*format).buffer, len);
            (*format).buffer = (*format).buffer.add(len);
            (*format).length -= len as i32;
        }
    }
    
    /// BeaconFormatLength implementation
    /// Returns the length of data in the format buffer (size - remaining)
    /// 
    /// This function returns the number of bytes that have been written to the
    /// format buffer. This is useful for determining how much data has been
    /// formatted without converting to a string.
    /// 
    /// Parameters:
    /// - format: Pointer to FormatParser structure
    /// 
    /// Returns: Number of bytes written to the buffer, or 0 on error
    pub unsafe extern "C" fn beacon_format_length(format: *mut FormatParser) -> i32 {
        // Validate format pointer
        if format.is_null() {
            return 0;
        }
        
        // Validate format buffer is allocated
        if (*format).original.is_null() {
            return 0;
        }
        
        // Return the amount of data written (size - remaining length)
        (*format).size - (*format).length
    }
    
    // ===== Memory APIs =====
    
    /// BeaconVirtualAlloc implementation (Windows)
    /// Matches signature: LPVOID BeaconVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_virtual_alloc(
        lp_address: *mut std::ffi::c_void,
        dw_size: usize,
        fl_allocation_type: u32,
        fl_protect: u32,
    ) -> *mut std::ffi::c_void {
        if dw_size == 0 {
            return std::ptr::null_mut();
        }
        
        let address = if lp_address.is_null() {
            None
        } else {
            Some(lp_address as *const _)
        };
        
        let ptr = VirtualAlloc(
            address,
            dw_size,
            VIRTUAL_ALLOCATION_TYPE(fl_allocation_type),
            PAGE_PROTECTION_FLAGS(fl_protect),
        );
        
        if ptr.is_null() {
            std::ptr::null_mut()
        } else {
            ptr as *mut std::ffi::c_void
        }
    }
    
    /// BeaconVirtualAlloc implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_virtual_alloc(
        _lp_address: *mut std::ffi::c_void,
        dw_size: usize,
        _fl_allocation_type: u32,
        _fl_protect: u32,
    ) -> *mut std::ffi::c_void {
        if dw_size == 0 {
            return std::ptr::null_mut();
        }
        libc::malloc(dw_size) as *mut std::ffi::c_void
    }
    
    /// BeaconVirtualFree implementation (Windows)
    /// Matches signature: BOOL BeaconVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_virtual_free(
        lp_address: *mut std::ffi::c_void,
        _dw_size: usize,
        dw_free_type: u32,
    ) -> BOOL {
        if lp_address.is_null() {
            return BOOL::from(false);
        }
        
        let result = VirtualFree(
            lp_address as *mut _,
            0,
            VIRTUAL_FREE_TYPE(dw_free_type),
        );
        
        match result {
            Ok(_) => BOOL::from(true),
            Err(_) => BOOL::from(false),
        }
    }
    
    /// BeaconVirtualFree implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_virtual_free(
        ptr: *mut std::ffi::c_void,
        _dw_size: usize,
        _dw_free_type: u32,
    ) -> i32 {
        if ptr.is_null() {
            return 0;
        }
        libc::free(ptr);
        1
    }
    
    // ===== Process APIs =====
    
    /// BeaconGetSpawnTo implementation (Windows)
    /// Gets the spawn-to process name for process injection
    /// 
    /// This function retrieves the name of the process that should be spawned
    /// for process injection. The process name is architecture-specific.
    /// 
    /// Parameters:
    /// - x86: TRUE for x86 process, FALSE for x64 process
    /// - buffer: Output buffer to receive the process name
    /// - length: Size of the output buffer
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_get_spawn_to(
        x86: BOOL,
        buffer: *mut c_char,
        length: c_int,
    ) {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconGetSpawnTo".to_string(),
            vec![format!("x86={}", x86.as_bool()), format!("length={}", length)],
        );
        
        // Validate parameters
        if buffer.is_null() {
            crate::core::executor::tracer::record_api_call(
                "BeaconGetSpawnTo".to_string(),
                vec!["ERROR: NULL_BUFFER".to_string()],
            );
            return;
        }
        
        if length <= 0 {
            crate::core::executor::tracer::record_api_call(
                "BeaconGetSpawnTo".to_string(),
                vec!["ERROR: INVALID_LENGTH".to_string()],
            );
            return;
        }
        
        // Check sandbox
        if !crate::core::executor::sandbox::is_api_allowed("BeaconGetSpawnTo") {
            // Fill with default spawn-to process even if sandboxed
            // This allows BOFs to continue execution
            let default_spawn = b"rundll32.exe\0";
            let copy_len = (length as usize - 1).min(default_spawn.len() - 1);
            std::ptr::copy_nonoverlapping(default_spawn.as_ptr(), buffer as *mut u8, copy_len);
            *buffer.add(copy_len) = 0;
            crate::core::executor::tracer::record_api_call(
                "BeaconGetSpawnTo".to_string(),
                vec!["SANDBOXED: Using default".to_string()],
            );
            return;
        }
        
        // Default spawn-to process based on architecture
        // In a real beacon, this would come from the team server configuration
        // Common spawn-to processes:
        // - x86: rundll32.exe, notepad.exe, calc.exe
        // - x64: rundll32.exe, notepad.exe, calc.exe
        let default_spawn = if x86.as_bool() {
            b"rundll32.exe\0"  // x86 process
        } else {
            b"rundll32.exe\0"  // x64 process (same default)
        };
        
        // Copy process name to buffer, ensuring null termination
        let copy_len = (length as usize - 1).min(default_spawn.len() - 1);
        std::ptr::copy_nonoverlapping(default_spawn.as_ptr(), buffer as *mut u8, copy_len);
        *buffer.add(copy_len) = 0; // Ensure null termination
        
        crate::core::executor::tracer::record_api_call(
            "BeaconGetSpawnTo".to_string(),
            vec![format!("SUCCESS: {}", std::str::from_utf8(&default_spawn[..copy_len]).unwrap_or("unknown"))],
        );
    }
    
    /// BeaconGetSpawnTo implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_get_spawn_to(
        _x86: i32,
        _buffer: *mut c_char,
        _length: c_int,
    ) {
        // No-op on non-Windows
    }
    
    /// BeaconSpawnTemporaryProcess implementation (Windows)
    /// Spawns a temporary process for injection
    /// 
    /// This function spawns a temporary process that can be used for process injection.
    /// The process is spawned based on the spawn-to configuration from BeaconGetSpawnTo.
    /// 
    /// Parameters:
    /// - x86: TRUE for x86 process, FALSE for x64 process
    /// - ignore_token: TRUE to ignore the current token, FALSE to use it
    /// - si: Pointer to STARTUPINFO structure (can be NULL)
    /// - pi: Pointer to PROCESS_INFORMATION structure to receive process info
    /// 
    /// Returns: TRUE if successful, FALSE otherwise
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_spawn_temporary_process(
        x86: BOOL,
        ignore_token: BOOL,
        _si: *mut windows::Win32::System::Threading::STARTUPINFOW,
        pi: *mut windows::Win32::System::Threading::PROCESS_INFORMATION,
    ) -> BOOL {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconSpawnTemporaryProcess".to_string(),
            vec![
                format!("x86={}", x86.as_bool()),
                format!("ignore_token={}", ignore_token.as_bool()),
            ],
        );
        
        // Validate parameters
        if pi.is_null() {
            crate::core::executor::tracer::record_api_call(
                "BeaconSpawnTemporaryProcess".to_string(),
                vec!["ERROR: NULL_PROCESS_INFORMATION".to_string()],
            );
            return BOOL::from(false);
        }
        
        // Check sandbox
        if !crate::core::executor::sandbox::is_api_allowed("BeaconSpawnTemporaryProcess") {
            crate::core::executor::tracer::record_api_call(
                "BeaconSpawnTemporaryProcess".to_string(),
                vec!["BLOCKED_BY_SANDBOX".to_string()],
            );
            // Initialize PROCESS_INFORMATION to zero to indicate failure
            std::ptr::write_bytes(pi as *mut u8, 0, std::mem::size_of::<windows::Win32::System::Threading::PROCESS_INFORMATION>());
            return BOOL::from(false);
        }
        
        // In emulation, we don't actually spawn processes for safety
        // Initialize PROCESS_INFORMATION to zero to indicate failure
        // In a real beacon, this would:
        // 1. Get the spawn-to process name from BeaconGetSpawnTo
        // 2. Create the process using CreateProcess or similar
        // 3. Fill in the PROCESS_INFORMATION structure
        // 4. Return TRUE on success
        
        std::ptr::write_bytes(pi as *mut u8, 0, std::mem::size_of::<windows::Win32::System::Threading::PROCESS_INFORMATION>());
        
        crate::core::executor::tracer::record_api_call(
            "BeaconSpawnTemporaryProcess".to_string(),
            vec!["EMULATED: Process spawn not implemented for safety".to_string()],
        );
        
        BOOL::from(false)
    }
    
    /// BeaconSpawnTemporaryProcess implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_spawn_temporary_process(
        _x86: i32,
        _ignore_token: i32,
        _si: *mut std::ffi::c_void,
        _pi: *mut std::ffi::c_void,
    ) -> i32 {
        0 // Not supported
    }
    
    /// BeaconInjectProcess implementation (Windows)
    /// Injects payload into a process
    /// 
    /// This function injects a payload into the specified process. The injection
    /// method depends on the beacon's configuration and capabilities.
    /// 
    /// Parameters:
    /// - h_proc: Handle to the target process (can be NULL if pid is provided)
    /// - pid: Process ID of the target process
    /// - payload: Pointer to the payload data
    /// - p_len: Length of the payload
    /// - p_offset: Offset into the payload where execution should begin
    /// - arg: Optional argument data to pass to the payload
    /// - a_len: Length of the argument data
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_inject_process(
        _h_proc: HANDLE,
        _pid: c_int,
        _payload: *const c_char,
        _p_len: c_int,
        _p_offset: c_int,
        _arg: *const c_char,
        _a_len: c_int,
    ) {
        // Validate parameters
        if _p_len <= 0 || _p_len < _p_offset {
            crate::core::executor::tracer::record_api_call(
                "BeaconInjectProcess".to_string(),
                vec!["ERROR: INVALID_PAYLOAD_LENGTH".to_string()],
            );
            return;
        }
        
        if _payload.is_null() {
            crate::core::executor::tracer::record_api_call(
                "BeaconInjectProcess".to_string(),
                vec!["ERROR: NULL_PAYLOAD".to_string()],
            );
            return;
        }
        
        // Check sandbox
        if !crate::core::executor::sandbox::is_api_allowed("BeaconInjectProcess") {
            crate::core::executor::tracer::record_api_call(
                "BeaconInjectProcess".to_string(),
                vec!["BLOCKED_BY_SANDBOX".to_string()],
            );
            return;
        }
        
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconInjectProcess".to_string(),
            vec![
                format!("pid={}", _pid),
                format!("payload_len={}", _p_len),
                format!("payload_offset={}", _p_offset),
                format!("arg_len={}", _a_len),
                format!("h_proc_valid={}", !_h_proc.is_invalid()),
            ],
        );
        
        // Stub implementation - actual process injection is not implemented for safety
        // In a real beacon, this would:
        // 1. Validate the process handle or open the process by PID
        // 2. Allocate memory in the target process
        // 3. Write the payload to the allocated memory
        // 4. Create a remote thread or use another injection technique
        // 5. Handle errors and cleanup
        
        crate::core::executor::tracer::record_api_call(
            "BeaconInjectProcess".to_string(),
            vec!["EMULATED: Process injection not implemented for safety".to_string()],
        );
    }
    
    /// BeaconInjectProcess implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_inject_process(
        _h_proc: *mut std::ffi::c_void,
        _pid: c_int,
        _payload: *const c_char,
        _p_len: c_int,
        _p_offset: c_int,
        _arg: *const c_char,
        _a_len: c_int,
    ) {
        // No-op on non-Windows
    }
    
    /// BeaconInjectTemporaryProcess implementation (Windows)
    /// Injects payload into a temporary process
    /// 
    /// This function injects a payload into a temporary process that was previously
    /// spawned using BeaconSpawnTemporaryProcess.
    /// 
    /// Parameters:
    /// - pi: Pointer to PROCESS_INFORMATION from BeaconSpawnTemporaryProcess
    /// - payload: Pointer to the payload data
    /// - p_len: Length of the payload
    /// - p_offset: Offset into the payload where execution should begin
    /// - arg: Optional argument data to pass to the payload
    /// - a_len: Length of the argument data
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_inject_temporary_process(
        _pi: *mut windows::Win32::System::Threading::PROCESS_INFORMATION,
        _payload: *const c_char,
        _p_len: c_int,
        _p_offset: c_int,
        _arg: *const c_char,
        _a_len: c_int,
    ) {
        // Validate parameters
        if _pi.is_null() {
            crate::core::executor::tracer::record_api_call(
                "BeaconInjectTemporaryProcess".to_string(),
                vec!["ERROR: NULL_PROCESS_INFORMATION".to_string()],
            );
            return;
        }
        
        if _p_len <= 0 || _p_len < _p_offset {
            crate::core::executor::tracer::record_api_call(
                "BeaconInjectTemporaryProcess".to_string(),
                vec!["ERROR: INVALID_PAYLOAD_LENGTH".to_string()],
            );
            return;
        }
        
        if _payload.is_null() {
            crate::core::executor::tracer::record_api_call(
                "BeaconInjectTemporaryProcess".to_string(),
                vec!["ERROR: NULL_PAYLOAD".to_string()],
            );
            return;
        }
        
        // Check sandbox
        if !crate::core::executor::sandbox::is_api_allowed("BeaconInjectTemporaryProcess") {
            crate::core::executor::tracer::record_api_call(
                "BeaconInjectTemporaryProcess".to_string(),
                vec!["BLOCKED_BY_SANDBOX".to_string()],
            );
            return;
        }
        
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconInjectTemporaryProcess".to_string(),
            vec![
                format!("payload_len={}", _p_len),
                format!("payload_offset={}", _p_offset),
                format!("arg_len={}", _a_len),
            ],
        );
        
        // Stub implementation - actual process injection is not implemented for safety
        // In a real beacon, this would:
        // 1. Use the process handle from PROCESS_INFORMATION
        // 2. Allocate memory in the target process
        // 3. Write the payload to the allocated memory
        // 4. Create a remote thread or use another injection technique
        // 5. Handle errors and cleanup
        
        crate::core::executor::tracer::record_api_call(
            "BeaconInjectTemporaryProcess".to_string(),
            vec!["EMULATED: Process injection not implemented for safety".to_string()],
        );
    }
    
    /// BeaconInjectTemporaryProcess implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_inject_temporary_process(
        _pi: *mut std::ffi::c_void,
        _payload: *const c_char,
        _p_len: c_int,
        _p_offset: c_int,
        _arg: *const c_char,
        _a_len: c_int,
    ) {
        // No-op on non-Windows
    }
    
    /// BeaconCleanupProcess implementation (Windows)
    /// Cleans up process handles
    /// 
    /// This function closes the process and thread handles in the PROCESS_INFORMATION
    /// structure. This should be called after process injection is complete.
    /// 
    /// Parameters:
    /// - pi: Pointer to PROCESS_INFORMATION structure to cleanup
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_cleanup_process(
        pi: *mut windows::Win32::System::Threading::PROCESS_INFORMATION,
    ) {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconCleanupProcess".to_string(),
            vec![],
        );
        
        if pi.is_null() {
            crate::core::executor::tracer::record_api_call(
                "BeaconCleanupProcess".to_string(),
                vec!["ERROR: NULL_PROCESS_INFORMATION".to_string()],
            );
            return;
        }
        
        // Cleanup process handles
        let pi_ref = &*pi;
        
        // Close process handle if valid
        if !pi_ref.hProcess.is_invalid() {
            let _ = CloseHandle(pi_ref.hProcess);
        }
        
        // Close thread handle if valid
        if !pi_ref.hThread.is_invalid() {
            let _ = CloseHandle(pi_ref.hThread);
        }
        
        crate::core::executor::tracer::record_api_call(
            "BeaconCleanupProcess".to_string(),
            vec!["SUCCESS: Handles closed".to_string()],
        );
    }
    
    /// BeaconCleanupProcess implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_cleanup_process(_pi: *mut std::ffi::c_void) {
        // No-op on non-Windows
    }
    
    // ===== Additional Output APIs =====
    
    /// BeaconDownload implementation
    /// Downloads a file to the beacon
    pub unsafe extern "C" fn beacon_download(
        filename: *const c_char,
        buffer: *const u8,
        length: u32,
    ) -> BOOL {
        if filename.is_null() || buffer.is_null() || length == 0 {
            return BOOL::from(false);
        }
        
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconDownload".to_string(),
            vec![
                format!("length={}", length),
            ],
        );
        
        // In a real implementation, this would download the file
        // For now, we just log it
        if let Ok(fname) = CStr::from_ptr(filename).to_str() {
            push_output(
                0x1000, // CALLBACK_CUSTOM
                format!("[DOWNLOAD] {} ({} bytes)\n", fname, length).into_bytes(),
            );
        }
        
        BOOL::from(true)
    }
    
    // ===== Utility APIs =====
    
    /// toWideChar implementation
    /// Converts an ANSI string to a wide string
    #[cfg(windows)]
    pub unsafe extern "C" fn to_wide_char(
        src: *const c_char,
        dst: *mut u16,
        max: c_int,
    ) -> BOOL {
        if src.is_null() || dst.is_null() || max <= 0 {
            return BOOL::from(false);
        }
        
        if let Ok(src_str) = CStr::from_ptr(src).to_str() {
            let wide_str: Vec<u16> = src_str.encode_utf16().chain(std::iter::once(0)).collect();
            let copy_len = (max as usize - 1).min(wide_str.len() - 1);
            
            std::ptr::copy_nonoverlapping(wide_str.as_ptr(), dst, copy_len);
            *dst.add(copy_len) = 0;
            BOOL::from(true)
        } else {
            BOOL::from(false)
        }
    }
    
    /// toWideChar implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn to_wide_char(
        _src: *const c_char,
        _dst: *mut u16,
        _max: c_int,
    ) -> i32 {
        0
    }
    
    // ===== Information APIs =====
    
    /// BeaconInformation implementation
    /// Gets information about the beacon
    /// Supports versions: 0x040900 (4.9), 0x041000 (4.10), 0x041100 (4.11), 0x041200 (4.12)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_information(
        info: *mut std::ffi::c_void,
    ) -> BOOL {
        if info.is_null() {
            return BOOL::from(false);
        }
        
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconInformation".to_string(),
            vec![],
        );
        
        // Cast to BeaconInfo structure
        let info_ptr = info as *mut BeaconInfo;
        let info_ref = &mut *info_ptr;
        
        // Check if the requested version is supported
        // Supported versions: 4.9 (0x040900), 4.10 (0x041000), 4.11 (0x041100), 4.12 (0x041200)
        let requested_version = info_ref.version;
        let supported_versions = [0x040900, 0x041000, 0x041100, 0x041200];
        
        if !supported_versions.contains(&requested_version) {
            return BOOL::from(false);
        }

    // If we have emulation runtime information, populate with realistic values
    if let Ok(state) = get_beacon_emulation_state().lock() {
        if let Some(runtime) = &state.runtime {
            // Version
            info_ref.version = requested_version;
            
            // Sleep mask information
            info_ref.sleep_mask_ptr = runtime.sleep_mask_base as *mut c_char;
            info_ref.sleep_mask_text_size = runtime.sleep_mask_text_size;
            info_ref.sleep_mask_total_size = runtime.sleep_mask_total_size;
            
            // Beacon base pointer
            info_ref.beacon_ptr = runtime.base_address as *mut c_char;
            
            // Heap records - point to our emulated records if any, otherwise NULL.
            // We rebuild a HeapRecord array from stored (addr, size) pairs and leak it
            // so the pointer remains valid for the lifetime of the process.
            if state.heap_records.is_empty() {
                info_ref.heap_records = std::ptr::null_mut();
            } else {
                let mut heap_vec: Vec<HeapRecord> = state
                    .heap_records
                    .iter()
                    .map(|(addr, size)| HeapRecord {
                        ptr: *addr as *mut c_char,
                        size: *size,
                    })
                    .collect();
                let heap_ptr = heap_vec.as_mut_ptr();
                std::mem::forget(heap_vec);
                info_ref.heap_records = heap_ptr;
            }
            
            // Mask
            info_ref.mask = runtime.mask;
            
            // Initialize allocated memory regions to empty first
            for region in info_ref.allocated_memory.allocated_memory_regions.iter_mut() {
                region.purpose = 0; // PURPOSE_EMPTY
                region.allocation_base = std::ptr::null_mut();
                region.region_size = 0;
                region.type_ = 0;
                region.dripload_allocation_granularity = 0;
                
                for section in region.sections.iter_mut() {
                    section.label = 0; // LABEL_EMPTY
                    section.base_address = std::ptr::null_mut();
                    section.virtual_size = 0;
                    section.current_protect = 0;
                    section.previous_protect = 0;
                    section.mask_section = 0;
                    section.dripload_page_size = 0;
                }
                
                region.cleanup_information.cleanup = 0;
                region.cleanup_information.allocation_method = 0;
                region.cleanup_information.additional_cleanup_info = [0u8; 16];
            }
            
            // Fill first region as BEACON_MEMORY
            if let Some(first_region) = info_ref.allocated_memory.allocated_memory_regions.get_mut(0) {
                // Values based on beacon.h enums:
                // PURPOSE_BEACON_MEMORY = 2, METHOD_VIRTUALALLOC = 1
                const PURPOSE_BEACON_MEMORY: u32 = 2;
                const METHOD_VIRTUALALLOC: u32 = 1;
                
                first_region.purpose = PURPOSE_BEACON_MEMORY;
                first_region.allocation_base = runtime.base_address as *mut std::ffi::c_void;
                first_region.region_size = runtime.region_size;
                // Match typical MEM_COMMIT|MEM_RESERVE flag used by VirtualAlloc in beacon
                first_region.type_ = 0x20000;
                first_region.dripload_allocation_granularity = 0;
                
                // We have room for up to 8 sections in this region
                for (idx, sec_info) in runtime.sections.iter().take(first_region.sections.len()).enumerate() {
                    let section = &mut first_region.sections[idx];
                    // Use the label computed during initialization (e.g., TEXT/RDATA/DATA or generic buffer)
                    section.label = sec_info.label;
                    section.base_address = sec_info.base_address as *mut std::ffi::c_void;
                    section.virtual_size = sec_info.virtual_size;
                    section.current_protect = sec_info.current_protect;
                    section.previous_protect = sec_info.current_protect;
                    // Mark sections as masked to mimic real beacon behavior
                    section.mask_section = 1;
                    section.dripload_page_size = 0;
                }
                
                // Cleanup information
                first_region.cleanup_information.cleanup = 1;
                first_region.cleanup_information.allocation_method = METHOD_VIRTUALALLOC;
                first_region.cleanup_information.additional_cleanup_info = [0u8; 16];
            }
            
            return BOOL::from(true);
        }
    }
        
        // Fill in the structure with emulated values
        // Set version (already set by caller, but we keep it)
        info_ref.version = requested_version;
        
        // Set pointers to NULL (safe for emulation - BOF code only prints these, doesn't dereference)
        info_ref.sleep_mask_ptr = std::ptr::null_mut();
        info_ref.sleep_mask_text_size = 0;
        info_ref.sleep_mask_total_size = 0;
        
        info_ref.beacon_ptr = std::ptr::null_mut();
        
        // Heap records - set to NULL (no heap records in emulation)
        info_ref.heap_records = std::ptr::null_mut();
        
        // Initialize mask with zeros (in real beacon, this would be random)
        info_ref.mask = [0u8; 13];
        
        // Initialize allocated memory regions (all empty in emulation)
        for region in info_ref.allocated_memory.allocated_memory_regions.iter_mut() {
            region.purpose = 0; // PURPOSE_EMPTY
            region.allocation_base = std::ptr::null_mut();
            region.region_size = 0;
            region.type_ = 0;
            region.dripload_allocation_granularity = 0;
            
            // Initialize sections
            for section in region.sections.iter_mut() {
                section.label = 0; // LABEL_EMPTY
                section.base_address = std::ptr::null_mut();
                section.virtual_size = 0;
                section.current_protect = 0;
                section.previous_protect = 0;
                section.mask_section = 0; // FALSE
                section.dripload_page_size = 0;
            }
            
            // Initialize cleanup information
            region.cleanup_information.cleanup = 0; // FALSE
            region.cleanup_information.allocation_method = 0; // METHOD_UNKNOWN
            region.cleanup_information.additional_cleanup_info = [0u8; 16];
        }
        
        BOOL::from(true)
    }
    
    /// BeaconInformation implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_information(_info: *mut std::ffi::c_void) -> i32 {
        0
    }
    
    // ===== Key/Value Store APIs =====
    
    /// BeaconAddValue implementation
    pub unsafe extern "C" fn beacon_add_value(
        key: *const c_char,
        ptr: *mut std::ffi::c_void,
    ) -> BOOL {
        if key.is_null() {
            return BOOL::from(false);
        }
        
        if let Ok(key_str) = CStr::from_ptr(key).to_str() {
            if let Ok(mut store) = get_key_value_store().lock() {
                store.insert(key_str.to_string(), ptr as usize);
                BOOL::from(true)
            } else {
                BOOL::from(false)
            }
        } else {
            BOOL::from(false)
        }
    }
    
    /// BeaconGetValue implementation
    pub unsafe extern "C" fn beacon_get_value(key: *const c_char) -> *mut std::ffi::c_void {
        if key.is_null() {
            return std::ptr::null_mut();
        }
        
        if let Ok(key_str) = CStr::from_ptr(key).to_str() {
            if let Ok(store) = get_key_value_store().lock() {
                store.get(key_str).map(|&addr| addr as *mut std::ffi::c_void).unwrap_or(std::ptr::null_mut())
            } else {
                std::ptr::null_mut()
            }
        } else {
            std::ptr::null_mut()
        }
    }
    
    /// BeaconRemoveValue implementation
    pub unsafe extern "C" fn beacon_remove_value(key: *const c_char) -> BOOL {
        if key.is_null() {
            return BOOL::from(false);
        }
        
        if let Ok(key_str) = CStr::from_ptr(key).to_str() {
            if let Ok(mut store) = get_key_value_store().lock() {
                store.remove(key_str);
                BOOL::from(true)
            } else {
                BOOL::from(false)
            }
        } else {
            BOOL::from(false)
        }
    }
    
    /// BeaconGetIntValue implementation
    /// Gets an integer value from the key/value store
    pub unsafe extern "C" fn beacon_get_int_value(key: *const c_char) -> i32 {
        if key.is_null() {
            return 0;
        }
        
        if let Ok(key_str) = CStr::from_ptr(key).to_str() {
            if let Ok(store) = get_key_value_store().lock() {
                store.get(key_str)
                    .map(|&addr| addr as i32)
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        }
    }
    
    /// BeaconGetShortValue implementation
    /// Gets a short (int16) value from the key/value store
    pub unsafe extern "C" fn beacon_get_short_value(key: *const c_char) -> i16 {
        if key.is_null() {
            return 0;
        }
        
        if let Ok(key_str) = CStr::from_ptr(key).to_str() {
            if let Ok(store) = get_key_value_store().lock() {
                store.get(key_str)
                    .map(|&addr| addr as i16)
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        }
    }
    
    /// BeaconGetCharValue implementation
    /// Gets a char value from the key/value store
    pub unsafe extern "C" fn beacon_get_char_value(key: *const c_char) -> c_char {
        if key.is_null() {
            return 0;
        }
        
        if let Ok(key_str) = CStr::from_ptr(key).to_str() {
            if let Ok(store) = get_key_value_store().lock() {
                store.get(key_str)
                    .map(|&addr| addr as u8 as c_char)
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        }
    }
    
    /// BeaconGetPtrValue implementation
    /// Gets a pointer value from the key/value store (alias for BeaconGetValue)
    pub unsafe extern "C" fn beacon_get_ptr_value(key: *const c_char) -> *mut std::ffi::c_void {
        Self::beacon_get_value(key)
    }
    
    /// BeaconGetSizeValue implementation
    /// Gets a size_t value from the key/value store
    pub unsafe extern "C" fn beacon_get_size_value(key: *const c_char) -> usize {
        if key.is_null() {
            return 0;
        }
        
        if let Ok(key_str) = CStr::from_ptr(key).to_str() {
            if let Ok(store) = get_key_value_store().lock() {
                store.get(key_str)
                    .copied()
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        }
    }
    
    /// BeaconGetDataValue implementation
    /// Gets a data buffer value from the key/value store
    /// Returns pointer to data and sets size if provided
    pub unsafe extern "C" fn beacon_get_data_value(
        key: *const c_char,
        size: *mut usize,
    ) -> *const u8 {
        if key.is_null() {
            if !size.is_null() {
                *size = 0;
            }
            return std::ptr::null();
        }
        
        if let Ok(key_str) = CStr::from_ptr(key).to_str() {
            if let Ok(store) = get_key_value_store().lock() {
                if store.get(key_str).is_some() {
                    // In a real implementation, this would return a pointer to stored data
                    // For emulation, we return NULL as we only store pointers, not data buffers
                    if !size.is_null() {
                        *size = 0;
                    }
                    std::ptr::null()
                } else {
                    if !size.is_null() {
                        *size = 0;
                    }
                    std::ptr::null()
                }
            } else {
                if !size.is_null() {
                    *size = 0;
                }
                std::ptr::null()
            }
        } else {
            if !size.is_null() {
                *size = 0;
            }
            std::ptr::null()
        }
    }
    
    // ===== Data Store APIs =====
    
    /// BeaconDataStoreAlloc implementation
    /// Allocates a new data store object
    pub unsafe extern "C" fn beacon_data_store_alloc(
        type_: c_int,
        size: usize,
    ) -> *mut DataStoreObject {
        if size == 0 {
            return std::ptr::null_mut();
        }
        
        // Allocate buffer for the data
        let buffer = libc::malloc(size) as *mut c_char;
        if buffer.is_null() {
            return std::ptr::null_mut();
        }
        
        // Initialize buffer to zero
        std::ptr::write_bytes(buffer, 0, size);
        
        // Create data store object
        let obj = DataStoreObject {
            type_,
            hash: 0, // Will be set when protected
            masked: BOOL::from(false),
            buffer: buffer as usize, // Store as usize
            length: size,
        };
        
        // Add to data store
        if let Ok(mut store) = get_data_store().lock() {
            store.push(obj);
            // Return pointer to the last item (the one we just added)
            if let Some(last) = store.last_mut() {
                last as *mut DataStoreObject
            } else {
                libc::free(buffer as *mut _);
                std::ptr::null_mut()
            }
        } else {
            libc::free(buffer as *mut _);
            std::ptr::null_mut()
        }
    }
    
    /// BeaconDataStoreReset implementation
    /// Resets the data store (clears all items)
    pub unsafe extern "C" fn beacon_data_store_reset() {
        if let Ok(mut store) = get_data_store().lock() {
            // Free all allocated buffers
            for obj in store.iter() {
                if obj.buffer != 0 {
                    libc::free(obj.buffer as *mut _);
                }
            }
            store.clear();
        }
    }
    
    /// BeaconDataStoreFree implementation
    /// Frees a specific data store object
    pub unsafe extern "C" fn beacon_data_store_free(obj: *mut DataStoreObject) -> BOOL {
        if obj.is_null() {
            return BOOL::from(false);
        }
        
        if let Ok(mut store) = get_data_store().lock() {
            // Find and remove the object
            if let Some(pos) = store.iter().position(|o| o as *const _ == obj as *const _) {
                let removed = store.remove(pos);
                if removed.buffer != 0 {
                    libc::free(removed.buffer as *mut _);
                }
                BOOL::from(true)
            } else {
                BOOL::from(false)
            }
        } else {
            BOOL::from(false)
        }
    }
    
    /// BeaconDataStoreAdd implementation
    /// Adds data to the data store (creates new object)
    pub unsafe extern "C" fn beacon_data_store_add(
        type_: c_int,
        data: *const u8,
        size: usize,
    ) -> *mut DataStoreObject {
        if data.is_null() || size == 0 {
            return std::ptr::null_mut();
        }
        
        // Allocate buffer
        let buffer = libc::malloc(size) as *mut c_char;
        if buffer.is_null() {
            return std::ptr::null_mut();
        }
        
        // Copy data
        std::ptr::copy_nonoverlapping(data, buffer as *mut u8, size);
        
        // Create object
        let obj = DataStoreObject {
            type_,
            hash: 0,
            masked: BOOL::from(false),
            buffer: buffer as usize, // Store as usize
            length: size,
        };
        
        // Add to store
        if let Ok(mut store) = get_data_store().lock() {
            store.push(obj);
            if let Some(last) = store.last_mut() {
                last as *mut DataStoreObject
            } else {
                libc::free(buffer as *mut _);
                std::ptr::null_mut()
            }
        } else {
            libc::free(buffer as *mut _);
            std::ptr::null_mut()
        }
    }
    
    /// BeaconDataStoreGet implementation
    /// Gets a data store object by index
    pub unsafe extern "C" fn beacon_data_store_get(
        index: usize,
    ) -> *mut DataStoreObject {
        if let Ok(store) = get_data_store().lock() {
            store.get(index)
                .map(|obj| obj as *const _ as *mut DataStoreObject)
                .unwrap_or(std::ptr::null_mut())
        } else {
            std::ptr::null_mut()
        }
    }
    
    /// BeaconDataStoreRemove implementation
    /// Removes a data store object by index
    pub unsafe extern "C" fn beacon_data_store_remove(index: usize) -> BOOL {
        if let Ok(mut store) = get_data_store().lock() {
            if index < store.len() {
                let removed = store.remove(index);
                if removed.buffer != 0 {
                    libc::free(removed.buffer as *mut _);
                }
                BOOL::from(true)
            } else {
                BOOL::from(false)
            }
        } else {
            BOOL::from(false)
        }
    }
    
    /// BeaconDataStoreSize implementation
    /// Returns the number of items in the data store
    pub unsafe extern "C" fn beacon_data_store_size() -> usize {
        if let Ok(store) = get_data_store().lock() {
            store.len()
        } else {
            0
        }
    }
    
    /// BeaconDataStoreGetItem implementation
    pub unsafe extern "C" fn beacon_data_store_get_item(
        index: usize,
    ) -> *mut DataStoreObject {
        Self::beacon_data_store_get(index)
    }
    
    /// BeaconDataStoreProtectItem implementation
    pub unsafe extern "C" fn beacon_data_store_protect_item(_index: usize) {
        // No-op in emulation
    }
    
    /// BeaconDataStoreUnprotectItem implementation
    pub unsafe extern "C" fn beacon_data_store_unprotect_item(_index: usize) {
        // No-op in emulation
    }
    
    /// BeaconDataStoreMaxEntries implementation
    pub unsafe extern "C" fn beacon_data_store_max_entries() -> usize {
        0 // No entries in emulation
    }
    
    // ===== User Data APIs =====
    
    /// BeaconGetCustomUserData implementation
    pub unsafe extern "C" fn beacon_get_custom_user_data() -> *const c_char {
        // In a real implementation, this would return custom user data
        // For emulation, we return NULL
        std::ptr::null()
    }
    
    /// BeaconGetUserData implementation (alias for BeaconGetCustomUserData)
    pub unsafe extern "C" fn beacon_get_user_data() -> *const c_char {
        Self::beacon_get_custom_user_data()
    }
    
    // ===== Syscall Information APIs =====
    
    /// BeaconGetSyscallInformation implementation
    /// Gets system call information from beacon
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_get_syscall_information(
        info: *mut std::ffi::c_void,
        info_size: usize,
        _resolve_if_not_initialized: BOOL,
    ) -> BOOL {
        if info.is_null() {
            return BOOL::from(false);
        }
        
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconGetSyscallInformation".to_string(),
            vec![
                format!("info_size={}", info_size),
            ],
        );
        
        // Verify the size matches BEACON_SYSCALLS
        let expected_size = std::mem::size_of::<BeaconSyscalls>();
        if info_size < expected_size {
            return BOOL::from(false);
        }
        
        // Cast to BeaconSyscalls structure
        let info_ptr = info as *mut BeaconSyscalls;
        let info_ref = &mut *info_ptr;

        // Always start from a safe zeroed stub so that any functions we fail to
        // resolve from ntdll.dll remain in a consistent state.
        init_beacon_syscalls_zero(info_ref);

        // If syscall emulation from the OS is not enabled, just return the
        // zeroed stub. This matches the previous behavior.
        if !is_syscall_os_emulation_enabled() {
            return BOOL::from(true);
        }

        // Populate system calls from the local ntdll.dll.
        //
        // These names must match the exported Nt* functions exactly so that
        // GetProcAddress can resolve them correctly.
        fill_syscall_entry(&mut info_ref.syscalls.nt_allocate_virtual_memory, "NtAllocateVirtualMemory");
        fill_syscall_entry(&mut info_ref.syscalls.nt_protect_virtual_memory, "NtProtectVirtualMemory");
        fill_syscall_entry(&mut info_ref.syscalls.nt_free_virtual_memory, "NtFreeVirtualMemory");
        fill_syscall_entry(&mut info_ref.syscalls.nt_get_context_thread, "NtGetContextThread");
        fill_syscall_entry(&mut info_ref.syscalls.nt_set_context_thread, "NtSetContextThread");
        fill_syscall_entry(&mut info_ref.syscalls.nt_resume_thread, "NtResumeThread");
        fill_syscall_entry(&mut info_ref.syscalls.nt_create_thread_ex, "NtCreateThreadEx");
        fill_syscall_entry(&mut info_ref.syscalls.nt_open_process, "NtOpenProcess");
        fill_syscall_entry(&mut info_ref.syscalls.nt_open_thread, "NtOpenThread");
        fill_syscall_entry(&mut info_ref.syscalls.nt_close, "NtClose");
        fill_syscall_entry(&mut info_ref.syscalls.nt_create_section, "NtCreateSection");
        fill_syscall_entry(&mut info_ref.syscalls.nt_map_view_of_section, "NtMapViewOfSection");
        fill_syscall_entry(&mut info_ref.syscalls.nt_unmap_view_of_section, "NtUnmapViewOfSection");
        fill_syscall_entry(&mut info_ref.syscalls.nt_query_virtual_memory, "NtQueryVirtualMemory");
        fill_syscall_entry(&mut info_ref.syscalls.nt_duplicate_object, "NtDuplicateObject");
        fill_syscall_entry(&mut info_ref.syscalls.nt_read_virtual_memory, "NtReadVirtualMemory");
        fill_syscall_entry(&mut info_ref.syscalls.nt_write_virtual_memory, "NtWriteVirtualMemory");
        fill_syscall_entry(&mut info_ref.syscalls.nt_read_file, "NtReadFile");
        fill_syscall_entry(&mut info_ref.syscalls.nt_write_file, "NtWriteFile");
        fill_syscall_entry(&mut info_ref.syscalls.nt_create_file, "NtCreateFile");
        fill_syscall_entry(&mut info_ref.syscalls.nt_queue_apc_thread, "NtQueueApcThread");
        fill_syscall_entry(&mut info_ref.syscalls.nt_create_process, "NtCreateProcess");
        fill_syscall_entry(&mut info_ref.syscalls.nt_open_process_token, "NtOpenProcessToken");
        fill_syscall_entry(&mut info_ref.syscalls.nt_test_alert, "NtTestAlert");
        fill_syscall_entry(&mut info_ref.syscalls.nt_suspend_process, "NtSuspendProcess");
        fill_syscall_entry(&mut info_ref.syscalls.nt_resume_process, "NtResumeProcess");
        fill_syscall_entry(&mut info_ref.syscalls.nt_query_system_information, "NtQuerySystemInformation");
        fill_syscall_entry(&mut info_ref.syscalls.nt_query_directory_file, "NtQueryDirectoryFile");
        fill_syscall_entry(&mut info_ref.syscalls.nt_set_information_process, "NtSetInformationProcess");
        fill_syscall_entry(&mut info_ref.syscalls.nt_set_information_thread, "NtSetInformationThread");
        fill_syscall_entry(&mut info_ref.syscalls.nt_query_information_process, "NtQueryInformationProcess");
        fill_syscall_entry(&mut info_ref.syscalls.nt_query_information_thread, "NtQueryInformationThread");
        fill_syscall_entry(&mut info_ref.syscalls.nt_open_section, "NtOpenSection");
        fill_syscall_entry(&mut info_ref.syscalls.nt_adjust_privileges_token, "NtAdjustPrivilegesToken");
        fill_syscall_entry(&mut info_ref.syscalls.nt_device_io_control_file, "NtDeviceIoControlFile");
        fill_syscall_entry(&mut info_ref.syscalls.nt_wait_for_multiple_objects, "NtWaitForMultipleObjects");

        // Populate RTL function addresses from ntdll.dll.
        fill_rtl_entry(
            &mut info_ref.rtls.rtl_dos_path_name_to_nt_path_name_u_with_status_addr,
            "RtlDosPathNameToNtPathNameUWithStatus",
        );
        fill_rtl_entry(
            &mut info_ref.rtls.rtl_free_heap_addr,
            "RtlFreeHeap",
        );
        fill_rtl_entry(
            &mut info_ref.rtls.rtl_get_process_heap_addr,
            "RtlGetProcessHeap",
        );

        // Optionally emit a debug/trace dump of the resolved table so the user
        // can compare it directly with the BOF's dump_syscalls output.
        trace_beacon_syscalls(info_ref);
        
        BOOL::from(true)
    }
    
    /// BeaconGetSyscallInformation implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_get_syscall_information(
        _info: *mut std::ffi::c_void,
        _info_size: usize,
        _resolve_if_not_initialized: i32,
    ) -> i32 {
        0
    }
    
    // ===== Additional Memory APIs =====
    
    /// BeaconVirtualAllocEx implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_virtual_alloc_ex(
        process_handle: HANDLE,
        lp_address: *mut std::ffi::c_void,
        dw_size: usize,
        fl_allocation_type: u32,
        fl_protect: u32,
    ) -> *mut std::ffi::c_void {
        if dw_size == 0 || process_handle.is_invalid() {
            return std::ptr::null_mut();
        }
        
        use windows::Win32::System::Memory::VirtualAllocEx;
        
        let address = if lp_address.is_null() {
            None
        } else {
            Some(lp_address as *const _)
        };
        
        let ptr = VirtualAllocEx(
            process_handle,
            address,
            dw_size,
            VIRTUAL_ALLOCATION_TYPE(fl_allocation_type),
            PAGE_PROTECTION_FLAGS(fl_protect),
        );
        
        if ptr.is_null() {
            std::ptr::null_mut()
        } else {
            ptr as *mut std::ffi::c_void
        }
    }
    
    /// BeaconVirtualAllocEx implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_virtual_alloc_ex(
        _process_handle: *mut std::ffi::c_void,
        _lp_address: *mut std::ffi::c_void,
        dw_size: usize,
        _fl_allocation_type: u32,
        _fl_protect: u32,
    ) -> *mut std::ffi::c_void {
        if dw_size == 0 {
            return std::ptr::null_mut();
        }
        libc::malloc(dw_size) as *mut std::ffi::c_void
    }
    
    /// BeaconVirtualProtect implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_virtual_protect(
        lp_address: *mut std::ffi::c_void,
        dw_size: usize,
        fl_new_protect: u32,
        lpfl_old_protect: *mut u32,
    ) -> BOOL {
        if lp_address.is_null() || dw_size == 0 {
            return BOOL::from(false);
        }
        
        use windows::Win32::System::Memory::VirtualProtect;
        
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        let result = VirtualProtect(
            lp_address as *mut _,
            dw_size,
            PAGE_PROTECTION_FLAGS(fl_new_protect),
            &mut old_protect,
        );
        
        if result.is_ok() {
            if !lpfl_old_protect.is_null() {
                *lpfl_old_protect = old_protect.0;
            }
            BOOL::from(true)
        } else {
            BOOL::from(false)
        }
    }
    
    /// BeaconVirtualProtect implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_virtual_protect(
        _lp_address: *mut std::ffi::c_void,
        _dw_size: usize,
        _fl_new_protect: u32,
        _lpfl_old_protect: *mut u32,
    ) -> i32 {
        1
    }
    
    /// BeaconVirtualProtectEx implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_virtual_protect_ex(
        process_handle: HANDLE,
        lp_address: *mut std::ffi::c_void,
        dw_size: usize,
        fl_new_protect: u32,
        lpfl_old_protect: *mut u32,
    ) -> BOOL {
        if lp_address.is_null() || dw_size == 0 || process_handle.is_invalid() {
            return BOOL::from(false);
        }
        
        use windows::Win32::System::Memory::VirtualProtectEx;
        
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        let result = VirtualProtectEx(
            process_handle,
            lp_address as *mut _,
            dw_size,
            PAGE_PROTECTION_FLAGS(fl_new_protect),
            &mut old_protect,
        );
        
        if result.is_ok() {
            if !lpfl_old_protect.is_null() {
                *lpfl_old_protect = old_protect.0;
            }
            BOOL::from(true)
        } else {
            BOOL::from(false)
        }
    }
    
    /// BeaconVirtualProtectEx implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_virtual_protect_ex(
        _process_handle: *mut std::ffi::c_void,
        _lp_address: *mut std::ffi::c_void,
        _dw_size: usize,
        _fl_new_protect: u32,
        _lpfl_old_protect: *mut u32,
    ) -> i32 {
        1
    }
    
    // ===== Thread/Process APIs =====
    
    /// BeaconGetThreadContext implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_get_thread_context(
        thread_handle: HANDLE,
        thread_context: *mut windows::Win32::System::Diagnostics::Debug::CONTEXT,
    ) -> BOOL {
        if thread_context.is_null() || thread_handle.is_invalid() {
            return BOOL::from(false);
        }
        
        use windows::Win32::System::Diagnostics::Debug::GetThreadContext;
        
        match GetThreadContext(thread_handle, thread_context) {
            Ok(_) => BOOL::from(true),
            Err(_) => BOOL::from(false),
        }
    }
    
    /// BeaconGetThreadContext implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_get_thread_context(
        _thread_handle: *mut std::ffi::c_void,
        _thread_context: *mut std::ffi::c_void,
    ) -> i32 {
        0
    }
    
    /// BeaconSetThreadContext implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_set_thread_context(
        thread_handle: HANDLE,
        thread_context: *const windows::Win32::System::Diagnostics::Debug::CONTEXT,
    ) -> BOOL {
        if thread_context.is_null() || thread_handle.is_invalid() {
            return BOOL::from(false);
        }
        
        use windows::Win32::System::Diagnostics::Debug::SetThreadContext;
        
        match SetThreadContext(thread_handle, thread_context) {
            Ok(_) => BOOL::from(true),
            Err(_) => BOOL::from(false),
        }
    }
    
    /// BeaconSetThreadContext implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_set_thread_context(
        _thread_handle: *mut std::ffi::c_void,
        _thread_context: *const std::ffi::c_void,
    ) -> i32 {
        0
    }
    
    /// BeaconResumeThread implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_resume_thread(thread_handle: HANDLE) -> u32 {
        if thread_handle.is_invalid() {
            return 0;
        }
        
        use windows::Win32::System::Threading::ResumeThread;
        
        ResumeThread(thread_handle)
    }
    
    /// BeaconResumeThread implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_resume_thread(_thread_handle: *mut std::ffi::c_void) -> u32 {
        0
    }
    
    /// BeaconOpenProcess implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_open_process(
        desired_access: u32,
        inherit_handle: BOOL,
        process_id: u32,
    ) -> HANDLE {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};
        
        match OpenProcess(
            PROCESS_ACCESS_RIGHTS(desired_access),
            inherit_handle.as_bool(),
            process_id,
        ) {
            Ok(handle) => handle,
            Err(_) => HANDLE::default(),
        }
    }
    
    /// BeaconOpenProcess implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_open_process(
        _desired_access: u32,
        _inherit_handle: i32,
        _process_id: u32,
    ) -> *mut std::ffi::c_void {
        std::ptr::null_mut()
    }
    
    /// BeaconOpenThread implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_open_thread(
        desired_access: u32,
        inherit_handle: BOOL,
        thread_id: u32,
    ) -> HANDLE {
        use windows::Win32::System::Threading::{OpenThread, THREAD_ACCESS_RIGHTS};
        
        match OpenThread(
            THREAD_ACCESS_RIGHTS(desired_access),
            inherit_handle.as_bool(),
            thread_id,
        ) {
            Ok(handle) => handle,
            Err(_) => HANDLE::default(),
        }
    }
    
    /// BeaconOpenThread implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_open_thread(
        _desired_access: u32,
        _inherit_handle: i32,
        _thread_id: u32,
    ) -> *mut std::ffi::c_void {
        std::ptr::null_mut()
    }
    
    /// BeaconCloseHandle implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_close_handle(object: HANDLE) -> BOOL {
        if object.is_invalid() {
            return BOOL::from(false);
        }
        
        match CloseHandle(object) {
            Ok(_) => BOOL::from(true),
            Err(_) => BOOL::from(false),
        }
    }
    
    /// BeaconCloseHandle implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_close_handle(_object: *mut std::ffi::c_void) -> i32 {
        1
    }
    
    /// BeaconUnmapViewOfFile implementation (Windows)
    /// Unmaps a view of a file from the calling process's address space
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_unmap_view_of_file(
        base_address: *const std::ffi::c_void,
    ) -> BOOL {
        if base_address.is_null() {
            return BOOL::from(false);
        }
        
        use windows::Win32::System::Memory::{UnmapViewOfFile, MEMORY_MAPPED_VIEW_ADDRESS};
        
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconUnmapViewOfFile".to_string(),
            vec![format!("address={:p}", base_address)],
        );
        
        // Attempt to unmap the view
        // Note: This will only work if the address was actually mapped via MapViewOfFile
        // For emulation purposes, we try the call but it may fail if not a mapped view
        let view_address = MEMORY_MAPPED_VIEW_ADDRESS { Value: base_address as *mut std::ffi::c_void };
        match UnmapViewOfFile(view_address) {
            Ok(_) => BOOL::from(true),
            Err(_) => {
                // In emulation, this is expected to fail for non-mapped addresses
                // Return false to indicate failure
                BOOL::from(false)
            }
        }
    }
    
    /// BeaconUnmapViewOfFile implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_unmap_view_of_file(
        _base_address: *const std::ffi::c_void,
    ) -> i32 {
        1
    }
    
    /// BeaconVirtualQuery implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_virtual_query(
        address: *const std::ffi::c_void,
        buffer: *mut windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION,
        length: usize,
    ) -> usize {
        if address.is_null() || buffer.is_null() || length == 0 {
            return 0;
        }
        
        use windows::Win32::System::Memory::VirtualQuery;
        
        VirtualQuery(Some(address), buffer, length)
    }
    
    /// BeaconVirtualQuery implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_virtual_query(
        _address: *const std::ffi::c_void,
        _buffer: *mut std::ffi::c_void,
        _length: usize,
    ) -> usize {
        0
    }
    
    /// BeaconDuplicateHandle implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_duplicate_handle(
        h_source_process: HANDLE,
        h_source_handle: HANDLE,
        h_target_process: HANDLE,
        lp_target_handle: *mut HANDLE,
        dw_desired_access: u32,
        b_inherit_handle: BOOL,
        dw_options: u32,
    ) -> BOOL {
        if lp_target_handle.is_null() {
            return BOOL::from(false);
        }
        
        use windows::Win32::Foundation::DuplicateHandle;
        use windows::Win32::Foundation::DUPLICATE_HANDLE_OPTIONS;
        
        match DuplicateHandle(
            h_source_process,
            h_source_handle,
            h_target_process,
            lp_target_handle,
            dw_desired_access,
            b_inherit_handle.as_bool(),
            DUPLICATE_HANDLE_OPTIONS(dw_options),
        ) {
            Ok(_) => BOOL::from(true),
            Err(_) => BOOL::from(false),
        }
    }
    
    /// BeaconDuplicateHandle implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_duplicate_handle(
        _h_source_process: *mut std::ffi::c_void,
        _h_source_handle: *mut std::ffi::c_void,
        _h_target_process: *mut std::ffi::c_void,
        _lp_target_handle: *mut *mut std::ffi::c_void,
        _dw_desired_access: u32,
        _b_inherit_handle: i32,
        _dw_options: u32,
    ) -> i32 {
        0
    }
    
    /// BeaconReadProcessMemory implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_read_process_memory(
        h_process: HANDLE,
        lp_base_address: *const std::ffi::c_void,
        lp_buffer: *mut std::ffi::c_void,
        n_size: usize,
        lp_number_of_bytes_read: *mut usize,
    ) -> BOOL {
        if lp_base_address.is_null() || lp_buffer.is_null() || n_size == 0 {
            return BOOL::from(false);
        }
        
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        
        // In Cobalt Strike, passing -1 (INVALID_HANDLE_VALUE) means read from current process
        let process_handle = if h_process.is_invalid() {
            // Check if it's -1 (INVALID_HANDLE_VALUE) - means current process
            // On Windows, INVALID_HANDLE_VALUE is -1, which when cast to HANDLE becomes 0xFFFFFFFFFFFFFFFF
            GetCurrentProcess()
        } else {
            h_process
        };
        
        let mut bytes_read = 0;
        match ReadProcessMemory(
            process_handle,
            lp_base_address,
            lp_buffer,
            n_size,
            Some(&mut bytes_read),
        ) {
            Ok(_) => {
                if !lp_number_of_bytes_read.is_null() {
                    *lp_number_of_bytes_read = bytes_read;
                }
                BOOL::from(true)
            }
            Err(_) => BOOL::from(false),
        }
    }
    
    /// BeaconReadProcessMemory implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_read_process_memory(
        _h_process: *mut std::ffi::c_void,
        _lp_base_address: *const std::ffi::c_void,
        _lp_buffer: *mut std::ffi::c_void,
        _n_size: usize,
        _lp_number_of_bytes_read: *mut usize,
    ) -> i32 {
        0
    }
    
    /// BeaconWriteProcessMemory implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_write_process_memory(
        h_process: HANDLE,
        lp_base_address: *mut std::ffi::c_void,
        lp_buffer: *const std::ffi::c_void,
        n_size: usize,
        lp_number_of_bytes_written: *mut usize,
    ) -> BOOL {
        if lp_base_address.is_null() || lp_buffer.is_null() || n_size == 0 || h_process.is_invalid() {
            return BOOL::from(false);
        }
        
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        
        let mut bytes_written = 0;
        match WriteProcessMemory(
            h_process,
            lp_base_address,
            lp_buffer,
            n_size,
            Some(&mut bytes_written),
        ) {
            Ok(_) => {
                if !lp_number_of_bytes_written.is_null() {
                    *lp_number_of_bytes_written = bytes_written;
                }
                BOOL::from(true)
            }
            Err(_) => BOOL::from(false),
        }
    }
    
    /// BeaconWriteProcessMemory implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_write_process_memory(
        _h_process: *mut std::ffi::c_void,
        _lp_base_address: *mut std::ffi::c_void,
        _lp_buffer: *const std::ffi::c_void,
        _n_size: usize,
        _lp_number_of_bytes_written: *mut usize,
    ) -> i32 {
        0
    }
    
    // ===== Beacon Gate APIs =====
    
    /// BeaconDisableBeaconGate implementation
    /// Disables the beacon gate mechanism
    pub unsafe extern "C" fn beacon_disable_beacon_gate() {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconDisableBeaconGate".to_string(),
            vec![],
        );
        
        // In emulation, this is a no-op as we don't have a real beacon gate
        // In a real beacon, this would disable the gate mechanism
    }
    
    /// BeaconEnableBeaconGate implementation
    /// Enables the beacon gate mechanism
    pub unsafe extern "C" fn beacon_enable_beacon_gate() {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconEnableBeaconGate".to_string(),
            vec![],
        );
        
        // In emulation, this is a no-op as we don't have a real beacon gate
        // In a real beacon, this would enable the gate mechanism
    }
    
    /// BeaconDisableBeaconGateMasking implementation
    /// Disables masking for the beacon gate
    pub unsafe extern "C" fn beacon_disable_beacon_gate_masking() {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconDisableBeaconGateMasking".to_string(),
            vec![],
        );
        
        // In emulation, this is a no-op as we don't have a real beacon gate masking
        // In a real beacon, this would disable masking for the gate
    }
    
    /// BeaconEnableBeaconGateMasking implementation
    /// Enables masking for the beacon gate
    pub unsafe extern "C" fn beacon_enable_beacon_gate_masking() {
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconEnableBeaconGateMasking".to_string(),
            vec![],
        );
        
        // In emulation, this is a no-op as we don't have a real beacon gate masking
        // In a real beacon, this would enable masking for the gate
    }
}

/// Global output capture lives in `capture.rs` (cross-platform); keep the
/// accessors here so existing callers compile unchanged.
pub use crate::core::executor::capture::{clear_global_output, global_output};

// ---------------------------------------------------------------------------
// Async contract APIs (OC2 style), ported from RedLoader
// ---------------------------------------------------------------------------

impl BeaconApi {
    /// `BeaconGetStopJobEvent()` — returns the async task's stop event
    /// handle, or NULL when called outside an async context.
    ///
    /// A well-behaved async BOF waits on this handle (e.g.
    /// `WaitForSingleObject`) in its work loop and returns promptly when
    /// the operator signals stop. Sync BOFs see NULL and may treat that as
    /// "no cancellation possible".
    pub unsafe extern "C" fn beacon_get_stop_job_event() -> *mut core::ffi::c_void {
        match crate::core::executor::task::current_task() {
            Some(ctx) => ctx.stop_event_handle() as *mut core::ffi::c_void,
            None => std::ptr::null_mut(),
        }
    }

    /// `BeaconWakeup()` — the BOF asks the operator to flush/wake.
    /// Recorded on the current task; returns TRUE (BOOL).
    pub unsafe extern "C" fn beacon_wakeup() -> i32 {
        if let Some(ctx) = crate::core::executor::task::current_task() {
            ctx.mark_wakeup();
        }
        1
    }
}
