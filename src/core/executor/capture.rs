//! Output capture for Beacon API calls, with per-task sink binding.
//!
//! Ported from RedLoader's `beacon::output` (live-verified on Windows
//! Server 2019). Cross-platform: pure `std` types, so the async harness
//! (`task.rs`) and its unit tests build everywhere.
//!
//! Writes from the Beacon APIs go through [`push_output`]: if the current
//! thread has a sink bound (i.e. it is running inside an async task, see
//! [`crate::core::executor::task`]), entries land in that task's private
//! capture; otherwise they land in the global capture, which is what
//! synchronous execution reads.

use std::cell::RefCell;
use std::sync::Mutex;

/// One captured `BeaconPrintf`/`BeaconOutput` entry.
#[derive(Debug, Clone)]
pub struct OutputEntry {
    pub callback_type: u32,
    pub data: Vec<u8>,
}

/// Output capture for Beacon API calls.
pub struct OutputCapture {
    entries: Mutex<Vec<OutputEntry>>,
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
        self.entries.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Take all entries, leaving the capture empty.
    pub fn take(&self) -> Vec<OutputEntry> {
        self.entries
            .lock()
            .map(|mut e| std::mem::take(&mut *e))
            .unwrap_or_default()
    }

    /// Clear entries
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }

    /// Whether no entries were captured.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().map(|e| e.is_empty()).unwrap_or(true)
    }
}

impl Default for OutputCapture {
    fn default() -> Self {
        Self::new()
    }
}

/// A shared, thread-safe handle to an [`OutputCapture`] (the per-task sink).
pub type OutputSink = std::sync::Arc<std::sync::Mutex<OutputCapture>>;

/// Global output capture (used by synchronous execution and by any thread
/// without a bound sink).
static GLOBAL_OUTPUT: OutputCapture = OutputCapture {
    entries: Mutex::new(Vec::new()),
};

thread_local! {
    /// Sink bound to the current thread while an async task's BOF executes.
    static BOUND_SINK: RefCell<Option<OutputSink>> = const { RefCell::new(None) };
}

/// Get global output capture
pub fn global_output() -> &'static OutputCapture {
    &GLOBAL_OUTPUT
}

/// Clear global output
pub fn clear_global_output() {
    GLOBAL_OUTPUT.clear();
}

/// Bind `sink` to the current thread: subsequent [`push_output`] calls on
/// this thread write into the sink instead of the global capture.
pub fn bind_output_sink(sink: OutputSink) {
    BOUND_SINK.with(|s| *s.borrow_mut() = Some(sink));
}

/// Remove the thread's sink binding; writes go back to the global capture.
pub fn unbind_output_sink() {
    BOUND_SINK.with(|s| *s.borrow_mut() = None);
}

/// Route one output entry to the bound sink (if any) or the global capture.
pub fn push_output(callback_type: u32, data: Vec<u8>) {
    BOUND_SINK.with(|s| {
        if let Some(sink) = s.borrow().as_ref() {
            sink.lock()
                .expect("output sink mutex poisoned")
                .add(callback_type, data);
        } else {
            GLOBAL_OUTPUT.add(callback_type, data);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbound_writes_go_global() {
        clear_global_output();
        push_output(0x00, b"global".to_vec());
        assert_eq!(global_output().get_entries().len(), 1);
        assert_eq!(global_output().get_entries()[0].data, b"global");
        clear_global_output();
    }

    #[test]
    fn bound_writes_go_sink() {
        clear_global_output();
        let sink: OutputSink = std::sync::Arc::new(std::sync::Mutex::new(OutputCapture::new()));
        bind_output_sink(std::sync::Arc::clone(&sink));
        push_output(0x00, b"sink".to_vec());
        unbind_output_sink();
        push_output(0x00, b"after".to_vec());
        let entries = sink.lock().unwrap().take();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"sink");
        assert!(global_output()
            .get_entries()
            .iter()
            .any(|e| e.data == b"after"));
        clear_global_output();
    }

    #[test]
    fn take_empties_capture() {
        let c = OutputCapture::new();
        c.add(0x00, vec![1]);
        assert_eq!(c.take().len(), 1);
        assert!(c.is_empty());
    }
}
