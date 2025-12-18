//! GUI interface module (egui-based)
//!
//! This module provides a graphical user interface for RedBofAnalizer
//! using the egui immediate mode GUI framework.

mod app;
mod app_opsec;
mod theme;
mod tabs;
mod widgets;

use app::RedBofApp;

/// Determine if the current process is running with administrator privileges (Windows only).
#[cfg(windows)]
fn is_running_as_admin() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = Default::default();

        // Try to open the process token
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        // Always close the handle
        let _ = CloseHandle(token_handle);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Non-Windows platforms: never report admin (concept doesn't apply the same way).
#[cfg(not(windows))]
fn is_running_as_admin() -> bool {
    false
}

/// Launch GUI mode
pub fn run() -> anyhow::Result<()> {
    let base_title = "RedBofAnalyzer - BOF Analyzer & Execution Tool";
    let window_title = if is_running_as_admin() {
        format!("{base_title} : Running as Administrator")
    } else {
        base_title.to_string()
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title(window_title),
        ..Default::default()
    };

    eframe::run_native(
        "RedBofAnalizer",
        options,
        Box::new(|cc| {
            // Set up custom fonts and style (applies dark theme)
            theme::setup_custom_style(&cc.egui_ctx);
            Ok(Box::new(RedBofApp::new(cc)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {}", e))
}
