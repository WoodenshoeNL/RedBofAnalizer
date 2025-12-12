//! Beacon API emulation

use std::sync::Mutex;
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
    pub fn output(&self) -> &OutputCapture {
        &self.output
    }
    
    /// BeaconPrintf implementation
    /// Note: This is a simplified version. Full printf with variadic args
    /// would require using libc::va_list or a C wrapper
    pub unsafe extern "C" fn beacon_printf(
        callback_type: c_int,
        format: *const c_char,
    ) {
        // For now, just capture the format string
        // TODO: Implement full printf with variadic arguments using a C wrapper
        if !format.is_null() {
            if let Ok(s) = CStr::from_ptr(format).to_str() {
                let output = format!("[BeaconPrintf] {}", s);
                GLOBAL_OUTPUT.add(callback_type as u32, output.into_bytes());
            }
        }
    }
    
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
    pub unsafe extern "C" fn beacon_data_extract(
        parser: *mut DataParser,
        size: *mut i32,
    ) -> *mut u8 {
        DataParser::extract(parser, size)
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
    /// Note: Simplified version - full printf would need va_list handling
    pub unsafe extern "C" fn beacon_format_printf(
        format: *mut FormatParser,
        fmt: *const c_char,
    ) {
        if format.is_null() || fmt.is_null() {
            return;
        }
        
        // For now, just append the format string
        // A full implementation would need to handle variadic arguments
        if let Ok(s) = CStr::from_ptr(fmt).to_str() {
            let bytes = s.as_bytes();
            let len = bytes.len().min((*format).length as usize);
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
