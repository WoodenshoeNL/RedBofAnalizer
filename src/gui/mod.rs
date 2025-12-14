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

/// Launch GUI mode
pub fn run() -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("RedBofAnalizer - BOF Analyzer & Execution Tool"),
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
    ).map_err(|e| anyhow::anyhow!("GUI error: {}", e))
}
