//! Execution tracing

#![allow(dead_code)]

use crate::core::models::report::ApiCall;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Execution tracer
pub struct ExecutionTracer {
    enabled: AtomicBool,
    api_calls: Mutex<Vec<ApiCall>>,
    memory_allocations: Mutex<Vec<MemoryAllocation>>,
}

/// Memory allocation record
#[derive(Debug, Clone)]
pub struct MemoryAllocation {
    pub address: usize,
    pub size: usize,
    pub timestamp: String,
}

impl ExecutionTracer {
    /// Create a new tracer
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            api_calls: Mutex::new(Vec::new()),
            memory_allocations: Mutex::new(Vec::new()),
        }
    }
    
    /// Enable or disable tracing at runtime
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }
    
    /// Check if tracing is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    
    /// Record an API call
    pub fn record_api_call(&self, name: String, arguments: Vec<String>) {
        if !self.is_enabled() {
            return;
        }
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_str = format!("{}", timestamp);
        
        if let Ok(mut calls) = self.api_calls.lock() {
            calls.push(ApiCall {
                name,
                timestamp: timestamp_str,
                arguments,
            });
        }
    }
    
    /// Record a memory allocation
    pub fn record_memory_allocation(&self, address: usize, size: usize) {
        if !self.is_enabled() {
            return;
        }
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_str = format!("{}", timestamp);
        
        if let Ok(mut allocations) = self.memory_allocations.lock() {
            allocations.push(MemoryAllocation {
                address,
                size,
                timestamp: timestamp_str,
            });
        }
    }
    
    /// Get all recorded API calls
    pub fn get_api_calls(&self) -> Vec<ApiCall> {
        self.api_calls.lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
    
    /// Get all memory allocations
    pub fn get_memory_allocations(&self) -> Vec<MemoryAllocation> {
        self.memory_allocations.lock()
            .map(|allocs| allocs.clone())
            .unwrap_or_default()
    }
    
    /// Clear all traces
    pub fn clear(&self) {
        if let Ok(mut calls) = self.api_calls.lock() {
            calls.clear();
        }
        if let Ok(mut allocations) = self.memory_allocations.lock() {
            allocations.clear();
        }
    }
}

use std::sync::OnceLock;

/// Global tracer instance
static GLOBAL_TRACER: OnceLock<ExecutionTracer> = OnceLock::new();

/// Initialize global tracer
pub fn init_tracer(enabled: bool) {
    let tracer = GLOBAL_TRACER.get_or_init(|| ExecutionTracer::new(enabled));
    // Update enabled flag on every initialization so each execution
    // can independently toggle tracing on or off.
    tracer.set_enabled(enabled);
}

/// Get global tracer
fn global_tracer() -> Option<&'static ExecutionTracer> {
    GLOBAL_TRACER.get()
}

/// Record API call (thread-safe wrapper)
pub fn record_api_call(name: String, arguments: Vec<String>) {
    if let Some(tracer) = global_tracer() {
        tracer.record_api_call(name, arguments);
    }
}

/// Record memory allocation (thread-safe wrapper)
pub fn record_memory_allocation(address: usize, size: usize) {
    if let Some(tracer) = global_tracer() {
        tracer.record_memory_allocation(address, size);
    }
}

/// Get all API calls
pub fn get_api_calls() -> Vec<ApiCall> {
    if let Some(tracer) = global_tracer() {
        tracer.get_api_calls()
    } else {
        Vec::new()
    }
}

/// Clear tracer
pub fn clear_tracer() {
    if let Some(tracer) = global_tracer() {
        tracer.clear();
    }
}
