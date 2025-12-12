//! Symbol resolution for BOF execution

use crate::core::models::bof::Import;
use anyhow::{Result, Context};
use std::collections::HashMap;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::core::PCSTR;

/// Symbol resolver
pub struct SymbolResolver {
    library_cache: HashMap<String, windows::Win32::Foundation::HMODULE>,
    resolved_cache: HashMap<String, usize>,
    beacon_apis: HashMap<String, usize>,
}

impl SymbolResolver {
    /// Create new symbol resolver
    pub fn new() -> Self {
        let mut resolver = Self {
            library_cache: HashMap::new(),
            resolved_cache: HashMap::new(),
            beacon_apis: HashMap::new(),
        };
        
        // Register Beacon API stubs (will be replaced with actual implementations)
        resolver.register_beacon_apis();
        
        resolver
    }
    
    /// Register Beacon API stubs
    fn register_beacon_apis(&mut self) {
        // These will be replaced with actual function pointers during execution
        // For now, use placeholder addresses
        self.beacon_apis.insert("BeaconPrintf".to_string(), 0);
        self.beacon_apis.insert("BeaconOutput".to_string(), 0);
        self.beacon_apis.insert("BeaconDataParse".to_string(), 0);
        self.beacon_apis.insert("BeaconDataInt".to_string(), 0);
        self.beacon_apis.insert("BeaconDataShort".to_string(), 0);
        self.beacon_apis.insert("BeaconDataLength".to_string(), 0);
        self.beacon_apis.insert("BeaconDataExtract".to_string(), 0);
    }
    
    /// Resolve an import symbol
    pub fn resolve(&mut self, import: &Import) -> Result<usize> {
        let cache_key = format!("{}::{}", import.library, import.function);
        
        // Check cache
        if let Some(&addr) = self.resolved_cache.get(&cache_key) {
            return Ok(addr);
        }
        
        let addr = if import.library == "Beacon" {
            // Beacon API - get from our table
            self.beacon_apis.get(&import.function)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("Unknown Beacon API: {}", import.function))?
        } else {
            // Windows API - resolve via LoadLibrary/GetProcAddress
            self.resolve_windows_api(&import.library, &import.function)?
        };
        
        self.resolved_cache.insert(cache_key, addr);
        Ok(addr)
    }
    
    /// Resolve Windows API
    fn resolve_windows_api(&mut self, library: &str, function: &str) -> Result<usize> {
        // Get or load library
        let module = if let Some(&module) = self.library_cache.get(library) {
            module
        } else {
            // Convert library name to DLL name
            let dll_name = format!("{}.dll", library);
            let dll_cstr = std::ffi::CString::new(dll_name.clone())
                .context("Invalid DLL name")?;
            
            unsafe {
                let module = LoadLibraryA(PCSTR::from_raw(dll_cstr.as_ptr() as *const u8))
                    .context(format!("Failed to load library: {}", dll_name))?;
                
                self.library_cache.insert(library.to_string(), module);
                module
            }
        };
        
        // Get function address
        let func_cstr = std::ffi::CString::new(function)
            .context("Invalid function name")?;
        
        unsafe {
            let addr = GetProcAddress(module, PCSTR::from_raw(func_cstr.as_ptr() as *const u8))
                .ok_or_else(|| anyhow::anyhow!("Function not found: {}", function))?;
            
            Ok(addr as usize)
        }
    }
    
    /// Set Beacon API function address
    pub fn set_beacon_api(&mut self, name: &str, addr: usize) {
        self.beacon_apis.insert(name.to_string(), addr);
    }
}

impl Default for SymbolResolver {
    fn default() -> Self {
        Self::new()
    }
}

