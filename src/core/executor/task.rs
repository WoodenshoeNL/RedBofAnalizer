//! Async BOF execution harness.
//!
//! Ported from RedLoader's `loader::task` (live-verified on Windows Server
//! 2019 — see RedLoader `tests/deep-verify/`). Runs a BOF on a worker
//! thread with:
//!
//! - a **per-task output sink** so concurrent tasks never mix
//!   `BeaconPrintf`/`BeaconOutput` output (see `capture.rs`);
//! - a **stop event** ([`StopEvent`]) surfaced to the BOF through the OC2
//!   async contract `BeaconGetStopJobEvent()` (and `BeaconWakeup()`), so a
//!   well-behaved async BOF notices operator stop and returns promptly.
//!
//! The harness itself is platform-neutral and unit-testable on any
//! platform; the COFF/PE execution that runs inside `spawn_task` is
//! Windows-only.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::core::executor::capture::{
    bind_output_sink, unbind_output_sink, OutputCapture, OutputEntry, OutputSink,
};

/// Next task id (monotonic).
static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

/// Manual-reset stop event, signaled when the operator asks the task to stop.
///
/// On Windows this is a real `HANDLE` (so `BeaconGetStopJobEvent` can hand
/// it to `WaitForSingleObject` inside BOF code). On other platforms it
/// degrades to an atomic flag — enough to unit-test the harness plumbing;
/// the execution path is Windows-only anyway.
pub struct StopEvent {
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
    #[cfg(not(windows))]
    signaled: Arc<AtomicBool>,
}

// HANDLE is a raw pointer wrapper; access is synchronized by the OS event
// itself (or the fallback AtomicBool), and the struct is only shared via Arc.
unsafe impl Send for StopEvent {}
unsafe impl Sync for StopEvent {}

impl StopEvent {
    /// Create a non-signaled manual-reset event.
    pub fn new() -> Self {
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::CreateEventW;
            let handle = unsafe { CreateEventW(None, true, false, windows::core::PCWSTR::null()) };
            // CreateEventW only fails on resource exhaustion; fall back to a
            // process-unique pseudo-handle so a NULL return can never be
            // mistaken for "not async".
            let handle = handle.unwrap_or(windows::Win32::Foundation::HANDLE(
                -1isize as *mut core::ffi::c_void,
            ));
            Self { handle }
        }
        #[cfg(not(windows))]
        {
            Self {
                signaled: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    /// Signal the event (ask the BOF to stop). Idempotent.
    pub fn signal(&self) {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::Threading::SetEvent;
            let _ = SetEvent(self.handle);
        }
        #[cfg(not(windows))]
        self.signaled.store(true, Ordering::SeqCst);
    }

    /// Whether the event is signaled.
    pub fn is_signaled(&self) -> bool {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::Foundation::WAIT_OBJECT_0;
            use windows::Win32::System::Threading::WaitForSingleObject;
            WaitForSingleObject(self.handle, 0).0 == WAIT_OBJECT_0.0
        }
        #[cfg(not(windows))]
        self.signaled.load(Ordering::SeqCst)
    }

    /// Wait up to `timeout` for the event; returns true if signaled.
    pub fn wait(&self, timeout: Duration) -> bool {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::Foundation::WAIT_TIMEOUT;
            use windows::Win32::System::Threading::WaitForSingleObject;
            let ms = timeout
                .min(Duration::from_millis(u32::MAX as u64))
                .as_millis() as u32;
            WaitForSingleObject(self.handle, ms).0 != WAIT_TIMEOUT.0
        }
        #[cfg(not(windows))]
        {
            let start = Instant::now();
            while !self.is_signaled() {
                if start.elapsed() >= timeout {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            true
        }
    }

    /// OS handle value for `BeaconGetStopJobEvent` (never 0).
    pub fn as_handle(&self) -> isize {
        #[cfg(windows)]
        {
            self.handle.0 as isize
        }
        #[cfg(not(windows))]
        {
            Arc::as_ptr(&self.signaled) as isize
        }
    }
}

impl Default for StopEvent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl Drop for StopEvent {
    fn drop(&mut self) {
        unsafe {
            use windows::Win32::Foundation::CloseHandle;
            // The pseudo-handle fallback must not be closed.
            if self.handle.0 as isize != -1 {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// Per-task context, bound to the worker thread while the BOF executes.
/// The Beacon async APIs (`BeaconWakeup`, `BeaconGetStopJobEvent`) resolve
/// it through [`current_task`].
pub struct TaskContext {
    /// Monotonic task id.
    pub id: u64,
    /// This task's private output capture.
    sink: OutputSink,
    stop: Arc<StopEvent>,
    wakeup_requested: AtomicBool,
    started: Instant,
}

impl TaskContext {
    /// Whether the operator signaled the stop event. Async BOFs must poll
    /// this (typically via `WaitForSingleObject` on the stop event handle).
    pub fn is_stopped(&self) -> bool {
        self.stop.is_signaled()
    }

    /// Signal the stop event from Rust side (operator stop).
    pub fn request_stop(&self) {
        self.stop.signal();
    }

    /// Stop event handle for `BeaconGetStopJobEvent` (never 0 inside a task).
    pub fn stop_event_handle(&self) -> isize {
        self.stop.as_handle()
    }

    /// Record a `BeaconWakeup()` call (BOF asks the C2 to wake/flush output).
    pub fn mark_wakeup(&self) {
        self.wakeup_requested.store(true, Ordering::SeqCst);
    }

    /// Whether the BOF called `BeaconWakeup()` so far.
    pub fn wakeup_requested(&self) -> bool {
        self.wakeup_requested.load(Ordering::SeqCst)
    }

    /// Shared handle to this task's output capture.
    pub fn sink(&self) -> &OutputSink {
        &self.sink
    }

    /// Take all output entries accumulated so far.
    pub fn drain_output(&self) -> Vec<OutputEntry> {
        self.sink.lock().expect("output sink mutex poisoned").take()
    }

    /// Elapsed time since the task started.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

thread_local! {
    /// The task whose BOF code is executing on this thread.
    static CURRENT_TASK: RefCell<Option<Arc<TaskContext>>> =
        const { RefCell::new(None) };
}

/// The task bound to the calling thread, if any (i.e. when called from
/// inside BOF execution).
pub fn current_task() -> Option<Arc<TaskContext>> {
    CURRENT_TASK.with(|c| c.borrow().clone())
}

/// Task lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    /// BOF code is running.
    Running = 0,
    /// BOF returned normally.
    Finished = 1,
    /// BOF execution returned an error.
    Failed = 2,
}

const fn state_code(s: TaskState) -> u8 {
    s as u8
}

fn state_from_code(v: u8) -> TaskState {
    match v {
        1 => TaskState::Finished,
        2 => TaskState::Failed,
        _ => TaskState::Running,
    }
}

/// A BOF execution running on a worker thread.
pub struct AsyncJob {
    ctx: Arc<TaskContext>,
    state: Arc<AtomicU8>,
    error: Arc<OnceLock<String>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// Spawn `body` as an async task: it runs on a fresh thread with its own
/// output sink and task context bound (so the Beacon APIs route output and
/// answer `BeaconGetStopJobEvent` correctly).
///
/// `body` is the stand-in for the (Windows-only) loader call; it receives
/// the task context so it can poll for stop.
pub fn spawn_task<F>(body: F) -> AsyncJob
where
    F: FnOnce(&TaskContext) -> Result<(), String> + Send + 'static,
{
    let ctx = Arc::new(TaskContext {
        id: NEXT_TASK_ID.fetch_add(1, Ordering::SeqCst),
        sink: Arc::new(Mutex::new(OutputCapture::new())),
        stop: Arc::new(StopEvent::new()),
        wakeup_requested: AtomicBool::new(false),
        started: Instant::now(),
    });
    let state = Arc::new(AtomicU8::new(state_code(TaskState::Running)));
    let error = Arc::new(OnceLock::new());

    let t_ctx = Arc::clone(&ctx);
    let t_state = Arc::clone(&state);
    let t_error = Arc::clone(&error);
    let thread = std::thread::Builder::new()
        .name(format!("redbofanalyzer-task-{}", ctx.id))
        .spawn(move || {
            bind_output_sink(Arc::clone(t_ctx.sink()));
            CURRENT_TASK.with(|c| *c.borrow_mut() = Some(Arc::clone(&t_ctx)));
            let result = body(&t_ctx);
            CURRENT_TASK.with(|c| *c.borrow_mut() = None);
            unbind_output_sink();
            match result {
                Ok(()) => t_state.store(state_code(TaskState::Finished), Ordering::SeqCst),
                Err(msg) => {
                    let _ = t_error.set(msg);
                    t_state.store(state_code(TaskState::Failed), Ordering::SeqCst);
                }
            }
        })
        .expect("failed to spawn task thread");

    AsyncJob {
        ctx,
        state,
        error,
        thread: Mutex::new(Some(thread)),
    }
}

impl AsyncJob {
    /// The task context (shared with the worker thread).
    pub fn context(&self) -> &Arc<TaskContext> {
        &self.ctx
    }

    /// Current lifecycle state.
    pub fn state(&self) -> TaskState {
        state_from_code(self.state.load(Ordering::SeqCst))
    }

    /// Whether the BOF is still executing.
    pub fn is_running(&self) -> bool {
        self.state() == TaskState::Running
    }

    /// Signal the stop event (OC2 "stop job" equivalent).
    pub fn stop(&self) {
        self.ctx.request_stop();
    }

    /// Take all output entries produced so far (streaming).
    pub fn drain_output(&self) -> Vec<OutputEntry> {
        self.ctx.drain_output()
    }

    /// Wait up to `timeout` for completion; returns the final state if the
    /// task finished within the timeout.
    pub fn wait_timeout(&self, timeout: Duration) -> Option<TaskState> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let s = self.state();
            if s != TaskState::Running {
                return Some(s);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// Block until the task finishes; returns `Err(message)` on failure.
    pub fn join(self) -> Result<(), String> {
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
        match self.state() {
            TaskState::Failed => Err(self
                .error
                .get()
                .cloned()
                .unwrap_or_else(|| "task failed".to_string())),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::executor::capture::{clear_global_output, global_output, push_output};

    fn drain_text(sink: &OutputSink) -> String {
        sink.lock()
            .unwrap()
            .take()
            .iter()
            .map(|e| String::from_utf8_lossy(&e.data).to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn stop_event_semantics() {
        let ev = StopEvent::new();
        assert!(!ev.is_signaled());
        assert!(ev.as_handle() != 0);
        assert!(!ev.wait(Duration::from_millis(30)));
        ev.signal();
        assert!(ev.is_signaled());
        assert!(ev.wait(Duration::from_millis(30)));
        ev.signal(); // idempotent
    }

    #[test]
    fn task_writes_go_to_sink_not_global() {
        clear_global_output();
        let job = spawn_task(|_ctx| {
            push_output(0x00, b"from-task".to_vec());
            Ok(())
        });
        let ctx = Arc::clone(job.context());
        assert_eq!(job.join(), Ok(()));
        assert_eq!(drain_text(ctx.sink()), "from-task");
        assert!(global_output().is_empty());
    }

    #[test]
    fn two_tasks_do_not_mix_output() {
        let a = spawn_task(|_ctx| {
            for i in 0..50 {
                push_output(0x00, format!("A{}", i).into_bytes());
            }
            Ok(())
        });
        let b = spawn_task(|_ctx| {
            for i in 0..50 {
                push_output(0x00, format!("B{}", i).into_bytes());
            }
            Ok(())
        });
        let a_ctx = Arc::clone(a.context());
        let b_ctx = Arc::clone(b.context());
        a.join().unwrap();
        b.join().unwrap();
        let a_out = drain_text(a_ctx.sink());
        let b_out = drain_text(b_ctx.sink());
        assert_eq!(a_out.lines().count(), 50);
        assert!(a_out.lines().all(|l| l.starts_with('A')));
        assert!(b_out.lines().all(|l| l.starts_with('B')));
    }

    #[test]
    fn unbound_threads_use_global() {
        clear_global_output();
        push_output(0x00, b"global-path".to_vec());
        assert_eq!(
            String::from_utf8_lossy(&global_output().get_entries()[0].data),
            "global-path"
        );
        clear_global_output();
    }

    #[test]
    fn stop_event_visible_to_task_and_null_outside() {
        // Outside any task: BeaconGetStopJobEvent semantics -> no task context.
        assert!(current_task().is_none());

        let job = spawn_task(|ctx| {
            assert!(current_task().is_some());
            assert_ne!(ctx.stop_event_handle(), 0);
            Ok(())
        });
        job.join().unwrap();
        assert!(current_task().is_none());
    }

    #[test]
    fn task_stops_on_signal() {
        let job = spawn_task(|ctx| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ctx.is_stopped() {
                if Instant::now() > deadline {
                    return Err("stop never signaled".into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        });
        assert_eq!(job.state(), TaskState::Running);
        job.stop();
        assert_eq!(
            job.wait_timeout(Duration::from_secs(5)),
            Some(TaskState::Finished)
        );
    }

    #[test]
    fn failure_propagates() {
        let job = spawn_task(|_ctx| Err("boom".into()));
        assert_eq!(
            job.wait_timeout(Duration::from_secs(5)),
            Some(TaskState::Failed)
        );
        assert_eq!(job.join(), Err("boom".into()));
    }

    #[test]
    fn wakeup_flag_round_trips() {
        let job = spawn_task(|ctx| {
            assert!(!ctx.wakeup_requested());
            ctx.mark_wakeup();
            Ok(())
        });
        let ctx = Arc::clone(job.context());
        job.join().unwrap();
        assert!(ctx.wakeup_requested());
    }
}
