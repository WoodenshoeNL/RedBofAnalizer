//! Theme and styling for the GUI

#![allow(dead_code)]

use egui::{Color32, FontFamily, FontId, Rounding, Stroke, TextStyle, Visuals};

/// Set up custom styling for the application
pub fn setup_custom_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    
    // Custom font sizes
    style.text_styles = [
        (TextStyle::Heading, FontId::new(24.0, FontFamily::Proportional)),
        (TextStyle::Name("heading2".into()), FontId::new(20.0, FontFamily::Proportional)),
        (TextStyle::Name("heading3".into()), FontId::new(16.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        (TextStyle::Button, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(12.0, FontFamily::Proportional)),
    ].into();
    
    // Apply dark theme with custom colors
    style.visuals = dark_visuals();
    
    // Rounded corners
    style.visuals.window_rounding = Rounding::same(8.0);
    style.visuals.menu_rounding = Rounding::same(6.0);
    
    ctx.set_style(style);
}

/// Create custom dark visuals
fn dark_visuals() -> Visuals {
    let mut visuals = Visuals::dark();
    
    // Background colors
    visuals.panel_fill = Color32::from_rgb(28, 28, 32);
    visuals.window_fill = Color32::from_rgb(35, 35, 40);
    visuals.extreme_bg_color = Color32::from_rgb(20, 20, 24);
    visuals.faint_bg_color = Color32::from_rgb(40, 40, 48);
    
    // Text colors
    visuals.override_text_color = Some(Color32::from_rgb(230, 230, 235));
    
    // Widget colors
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(45, 45, 52);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(180, 180, 185));
    
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(50, 50, 58);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(200, 200, 205));
    
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(65, 65, 75);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.5, Color32::from_rgb(220, 220, 225));
    
    visuals.widgets.active.bg_fill = Color32::from_rgb(80, 80, 95);
    visuals.widgets.active.fg_stroke = Stroke::new(2.0, Color32::from_rgb(255, 255, 255));
    
    // Selection colors - red accent
    visuals.selection.bg_fill = Color32::from_rgb(180, 60, 60);
    visuals.selection.stroke = Stroke::new(1.0, Color32::from_rgb(220, 80, 80));
    
    // Hyperlink color
    visuals.hyperlink_color = Color32::from_rgb(120, 180, 255);
    
    // Warning/error colors
    visuals.warn_fg_color = Color32::from_rgb(255, 180, 80);
    visuals.error_fg_color = Color32::from_rgb(255, 100, 100);
    
    visuals
}

/// Color palette for the application
pub struct Colors;

impl Colors {
    pub const RED_ACCENT: Color32 = Color32::from_rgb(200, 60, 60);
    pub const RED_LIGHT: Color32 = Color32::from_rgb(255, 100, 100);
    pub const RED_DARK: Color32 = Color32::from_rgb(140, 40, 40);
    
    pub const GREEN_SUCCESS: Color32 = Color32::from_rgb(80, 200, 120);
    pub const YELLOW_WARNING: Color32 = Color32::from_rgb(255, 200, 80);
    pub const BLUE_INFO: Color32 = Color32::from_rgb(100, 160, 255);
    pub const CYAN_ACCENT: Color32 = Color32::from_rgb(0, 200, 220);
    
    pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(230, 230, 235);
    pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(160, 160, 170);
    pub const TEXT_MUTED: Color32 = Color32::from_rgb(120, 120, 130);
    
    pub const BG_DARK: Color32 = Color32::from_rgb(28, 28, 32);
    pub const BG_MEDIUM: Color32 = Color32::from_rgb(35, 35, 40);
    pub const BG_LIGHT: Color32 = Color32::from_rgb(45, 45, 52);
    
    pub const BORDER: Color32 = Color32::from_rgb(60, 60, 68);
}

