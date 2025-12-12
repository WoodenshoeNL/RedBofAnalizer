//! Sandbox mode for safe execution

use std::collections::HashSet;

/// Sandbox configuration
pub struct Sandbox {
    enabled: bool,
    /// APIs that are blocked in sandbox mode
    blocked_apis: HashSet<String>,
    /// Maximum memory allocation size (bytes)
    max_allocation_size: Option<usize>,
    /// Allow token operations
    allow_token_ops: bool,
    /// Allow process operations
    allow_process_ops: bool,
    /// Allow network operations
    allow_network_ops: bool,
    /// Allow file operations
    allow_file_ops: bool,
}

impl Sandbox {
    /// Create a new sandbox with default restrictions
    pub fn new(enabled: bool) -> Self {
        let mut blocked_apis = HashSet::new();
        
        if enabled {
            // Block potentially dangerous APIs by default
            blocked_apis.insert("BeaconUseToken".to_string());
            blocked_apis.insert("BeaconInjectProcess".to_string());
            blocked_apis.insert("BeaconInjectTemporaryProcess".to_string());
            blocked_apis.insert("BeaconSpawnTemporaryProcess".to_string());
            // Note: We can add more dangerous Win32 APIs here
        }
        
        Self {
            enabled,
            blocked_apis,
            max_allocation_size: if enabled { Some(100 * 1024 * 1024) } else { None }, // 100MB limit
            allow_token_ops: !enabled,
            allow_process_ops: !enabled,
            allow_network_ops: !enabled,
            allow_file_ops: !enabled,
        }
    }
    
    /// Create a permissive sandbox (allows most operations)
    pub fn permissive() -> Self {
        Self::new(false)
    }
    
    /// Create a strict sandbox (blocks dangerous operations)
    pub fn strict() -> Self {
        Self::new(true)
    }
    
    /// Check if sandbox is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    
    /// Check if an API is allowed
    pub fn is_api_allowed(&self, api_name: &str) -> bool {
        if !self.enabled {
            return true;
        }
        
        !self.blocked_apis.contains(api_name)
    }
    
    /// Check if memory allocation is allowed
    pub fn is_allocation_allowed(&self, size: usize) -> bool {
        if !self.enabled {
            return true;
        }
        
        if let Some(max_size) = self.max_allocation_size {
            size <= max_size
        } else {
            true
        }
    }
    
    /// Check if token operations are allowed
    pub fn allow_token_ops(&self) -> bool {
        self.allow_token_ops
    }
    
    /// Check if process operations are allowed
    pub fn allow_process_ops(&self) -> bool {
        self.allow_process_ops
    }
    
    /// Check if network operations are allowed
    pub fn allow_network_ops(&self) -> bool {
        self.allow_network_ops
    }
    
    /// Check if file operations are allowed
    pub fn allow_file_ops(&self) -> bool {
        self.allow_file_ops
    }
    
    /// Block a specific API
    pub fn block_api(&mut self, api_name: String) {
        self.blocked_apis.insert(api_name);
    }
    
    /// Allow a specific API
    pub fn allow_api(&mut self, api_name: &str) {
        self.blocked_apis.remove(api_name);
    }
    
    /// Set maximum allocation size
    pub fn set_max_allocation_size(&mut self, size: Option<usize>) {
        self.max_allocation_size = size;
    }
    
    /// Set token operations permission
    pub fn set_allow_token_ops(&mut self, allow: bool) {
        self.allow_token_ops = allow;
    }
    
    /// Set process operations permission
    pub fn set_allow_process_ops(&mut self, allow: bool) {
        self.allow_process_ops = allow;
    }
}

use std::sync::OnceLock;

/// Global sandbox instance
static GLOBAL_SANDBOX: OnceLock<Sandbox> = OnceLock::new();

/// Initialize global sandbox
pub fn init_sandbox(enabled: bool) {
    GLOBAL_SANDBOX.get_or_init(|| Sandbox::new(enabled));
}

/// Get global sandbox
pub fn global_sandbox() -> Option<&'static Sandbox> {
    GLOBAL_SANDBOX.get()
}

/// Check if API is allowed (thread-safe wrapper)
pub fn is_api_allowed(api_name: &str) -> bool {
    if let Some(sandbox) = global_sandbox() {
        sandbox.is_api_allowed(api_name)
    } else {
        true // Default to allowed if sandbox not initialized
    }
}

/// Check if allocation is allowed (thread-safe wrapper)
pub fn is_allocation_allowed(size: usize) -> bool {
    if let Some(sandbox) = global_sandbox() {
        sandbox.is_allocation_allowed(size)
    } else {
        true // Default to allowed if sandbox not initialized
    }
}
