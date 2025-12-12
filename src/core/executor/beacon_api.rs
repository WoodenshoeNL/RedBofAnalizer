//! Beacon API emulation

use std::sync::Mutex;
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
#[cfg(windows)]
use windows::Win32::Foundation::{BOOL, HANDLE, CloseHandle};
#[cfg(windows)]
use windows::Win32::System::Memory::*;
#[cfg(windows)]
use windows::Win32::Security::*;
#[cfg(windows)]
use windows::Win32::System::Threading::*;

/// Output capture for Beacon API calls
pub struct OutputCapture {
    entries: Mutex<Vec<OutputEntry>>,
}

/// Output entry
#[derive(Debug, Clone)]
pub struct OutputEntry {
    pub callback_type: u32,
    pub data: Vec<u8>,
}

impl OutputCapture {
    /// Create new output capture
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }
    
    /// Add output entry
    pub fn add(&self, callback_type: u32, data: Vec<u8>) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(OutputEntry {
                callback_type,
                data,
            });
        }
    }
    
    /// Get all entries
    pub fn get_entries(&self) -> Vec<OutputEntry> {
        self.entries.lock()
            .map(|e| e.clone())
            .unwrap_or_default()
    }
    
    /// Clear entries
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }
}

impl Default for OutputCapture {
    fn default() -> Self {
        Self::new()
    }
}

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
            
            GLOBAL_OUTPUT.add(callback_type as u32, output.into_bytes());
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
            GLOBAL_OUTPUT.add(callback_type as u32, data_vec);
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
#[repr(C)]
pub struct DataStoreObject {
    pub type_: c_int,
    pub hash: u64,
    pub masked: BOOL,
    pub buffer: *mut c_char,
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

/// Key/Value store for BOFs to persist data across executions
use std::sync::OnceLock;
// Use usize instead of *mut c_void to avoid Send/Sync issues
static KEY_VALUE_STORE: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

fn get_key_value_store() -> &'static Mutex<HashMap<String, usize>> {
    KEY_VALUE_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

impl BeaconApi {
    // ===== Token APIs =====
    
    /// BeaconUseToken implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_use_token(token: HANDLE) -> BOOL {
        if token.is_invalid() {
            return BOOL::from(false);
        }
        
        // Try to impersonate the token
        let result = ImpersonateLoggedOnUser(token);
        match result {
            Ok(_) => BOOL::from(true),
            Err(_) => BOOL::from(false),
        }
    }
    
    /// BeaconUseToken implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_use_token(_token: *mut std::ffi::c_void) -> i32 {
        0 // Not supported on non-Windows
    }
    
    /// BeaconRevertToken implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_revert_token() {
        let _ = RevertToSelf();
    }
    
    /// BeaconRevertToken implementation (non-Windows stub)
    #[cfg(not(windows))]
    pub unsafe extern "C" fn beacon_revert_token() {
        // No-op on non-Windows
    }
    
    /// BeaconIsAdmin implementation (Windows)
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_is_admin() -> BOOL {
        // Open the process token
        let mut token = HANDLE::default();
        let process = GetCurrentProcess();
        
        let result = OpenProcessToken(
            process,
            TOKEN_QUERY,
            &mut token,
        );
        
        if result.is_err() || token.is_invalid() {
            return BOOL::from(false);
        }
        
        // Check for admin privileges
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        
        let _ = CloseHandle(token);
        
        if result.is_ok() {
            BOOL::from(elevation.TokenIsElevated != 0)
        } else {
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
    pub unsafe extern "C" fn beacon_format_alloc(format: *mut FormatParser, maxsz: i32) {
        if format.is_null() || maxsz <= 0 {
            return;
        }
        
        let buffer = libc::malloc(maxsz as usize) as *mut u8;
        if buffer.is_null() {
            return;
        }
        
        (*format).original = buffer;
        (*format).buffer = buffer;
        (*format).length = maxsz;
        (*format).size = maxsz;
    }
    
    /// BeaconFormatReset implementation
    pub unsafe extern "C" fn beacon_format_reset(format: *mut FormatParser) {
        if format.is_null() {
            return;
        }
        
        (*format).buffer = (*format).original;
        (*format).length = (*format).size;
    }
    
    /// BeaconFormatFree implementation
    pub unsafe extern "C" fn beacon_format_free(format: *mut FormatParser) {
        if format.is_null() {
            return;
        }
        
        if !(*format).original.is_null() {
            libc::free((*format).original as *mut _);
            (*format).original = std::ptr::null_mut();
            (*format).buffer = std::ptr::null_mut();
            (*format).length = 0;
            (*format).size = 0;
        }
    }
    
    /// BeaconFormatAppend implementation
    pub unsafe extern "C" fn beacon_format_append(
        format: *mut FormatParser,
        text: *const c_char,
        len: i32,
    ) {
        if format.is_null() || text.is_null() || len <= 0 {
            return;
        }
        
        if (*format).length < len {
            return; // Not enough space
        }
        
        std::ptr::copy_nonoverlapping(text as *const u8, (*format).buffer, len as usize);
        (*format).buffer = (*format).buffer.add(len as usize);
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
    pub unsafe extern "C" fn beacon_format_to_string(
        format: *mut FormatParser,
        size: *mut i32,
    ) -> *mut c_char {
        if format.is_null() {
            if !size.is_null() {
                *size = 0;
            }
            return std::ptr::null_mut();
        }
        
        let used = (*format).size - (*format).length;
        if !size.is_null() {
            *size = used;
        }
        
        // Return a pointer to the start of the buffer
        // Note: This is a pointer into the format buffer, caller should copy if needed
        (*format).original as *mut c_char
    }
    
    /// BeaconFormatInt implementation
    pub unsafe extern "C" fn beacon_format_int(format: *mut FormatParser, value: i32) {
        if format.is_null() {
            return;
        }
        
        // Convert integer to string
        let buffer = [0u8; 32];
        let formatted = format!("{}", value);
        let bytes = formatted.as_bytes();
        let len = bytes.len().min((*format).length as usize).min(buffer.len());
        
        if len > 0 {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), (*format).buffer, len);
            (*format).buffer = (*format).buffer.add(len);
            (*format).length -= len as i32;
        }
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
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_get_spawn_to(
        _x86: BOOL,
        buffer: *mut c_char,
        length: c_int,
    ) {
        if buffer.is_null() || length <= 0 {
            return;
        }
        
        // Check sandbox
        if !crate::core::executor::sandbox::is_api_allowed("BeaconGetSpawnTo") {
            // Fill with default spawn-to process
            let default_spawn = b"rundll32.exe\0";
            let copy_len = (length as usize - 1).min(default_spawn.len() - 1);
            std::ptr::copy_nonoverlapping(default_spawn.as_ptr(), buffer as *mut u8, copy_len);
            *buffer.add(copy_len) = 0;
            return;
        }
        
        // Default spawn-to process
        let default_spawn = b"rundll32.exe\0";
        let copy_len = (length as usize - 1).min(default_spawn.len() - 1);
        std::ptr::copy_nonoverlapping(default_spawn.as_ptr(), buffer as *mut u8, copy_len);
        *buffer.add(copy_len) = 0;
        
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconGetSpawnTo".to_string(),
            vec![format!("x86={}", _x86.as_bool())],
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
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_spawn_temporary_process(
        _x86: BOOL,
        _ignore_token: BOOL,
        si: *mut windows::Win32::System::Threading::STARTUPINFOW,
        pi: *mut windows::Win32::System::Threading::PROCESS_INFORMATION,
    ) -> BOOL {
        if si.is_null() || pi.is_null() {
            return BOOL::from(false);
        }
        
        // Check sandbox
        if !crate::core::executor::sandbox::is_api_allowed("BeaconSpawnTemporaryProcess") {
            crate::core::executor::tracer::record_api_call(
                "BeaconSpawnTemporaryProcess".to_string(),
                vec!["BLOCKED_BY_SANDBOX".to_string()],
            );
            return BOOL::from(false);
        }
        
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconSpawnTemporaryProcess".to_string(),
            vec![
                format!("x86={}", _x86.as_bool()),
                format!("ignore_token={}", _ignore_token.as_bool()),
            ],
        );
        
        // Stub implementation - in a real scenario, this would spawn a process
        // For safety, we return FALSE to indicate failure
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
            ],
        );
        
        // Stub implementation - actual process injection is not implemented for safety
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
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_inject_temporary_process(
        _pi: *mut windows::Win32::System::Threading::PROCESS_INFORMATION,
        _payload: *const c_char,
        _p_len: c_int,
        _p_offset: c_int,
        _arg: *const c_char,
        _a_len: c_int,
    ) {
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
            vec![format!("payload_len={}", _p_len)],
        );
        
        // Stub implementation - actual process injection is not implemented for safety
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
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_cleanup_process(
        pi: *mut windows::Win32::System::Threading::PROCESS_INFORMATION,
    ) {
        if pi.is_null() {
            return;
        }
        
        // Record API call
        crate::core::executor::tracer::record_api_call(
            "BeaconCleanupProcess".to_string(),
            vec![],
        );
        
        // Cleanup process handles
        let pi_ref = &*pi;
        let _ = CloseHandle(pi_ref.hProcess);
        let _ = CloseHandle(pi_ref.hThread);
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
            GLOBAL_OUTPUT.add(
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
    
    // ===== Data Store APIs =====
    
    /// BeaconDataStoreGetItem implementation
    pub unsafe extern "C" fn beacon_data_store_get_item(
        _index: usize,
    ) -> *mut DataStoreObject {
        // In a real implementation, this would return items from beacon's data store
        // For emulation, we return NULL
        std::ptr::null_mut()
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
        
        // Initialize all syscall entries with NULL pointers and zero sysnums
        // This is safe for emulation - BOFs can still display the information
        let zero_entry = SyscallApiEntry {
            fn_addr: std::ptr::null_mut(),
            jmp_addr: std::ptr::null_mut(),
            sysnum: 0,
        };
        
        // Fill in all syscall entries
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
        
        // Initialize RTL API entries
        info_ref.rtls.rtl_dos_path_name_to_nt_path_name_u_with_status_addr = std::ptr::null_mut();
        info_ref.rtls.rtl_free_heap_addr = std::ptr::null_mut();
        info_ref.rtls.rtl_get_process_heap_addr = std::ptr::null_mut();
        
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
    /// Note: This is a stub implementation. Full implementation would require tracking
    /// mapped file views. For BOF execution, this is typically not needed.
    #[cfg(windows)]
    pub unsafe extern "C" fn beacon_unmap_view_of_file(
        _base_address: *const std::ffi::c_void,
    ) -> BOOL {
        // Stub implementation - UnmapViewOfFile requires tracking mapped views
        // which is complex. For BOF execution, this is rarely used.
        BOOL::from(false)
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
        if lp_base_address.is_null() || lp_buffer.is_null() || n_size == 0 || h_process.is_invalid() {
            return BOOL::from(false);
        }
        
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        
        let mut bytes_read = 0;
        match ReadProcessMemory(
            h_process,
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
}

/// Global output capture
static GLOBAL_OUTPUT: OutputCapture = OutputCapture {
    entries: Mutex::new(Vec::new()),
};

/// Get global output capture
pub fn global_output() -> &'static OutputCapture {
    &GLOBAL_OUTPUT
}

/// Clear global output
pub fn clear_global_output() {
    GLOBAL_OUTPUT.clear();
}
