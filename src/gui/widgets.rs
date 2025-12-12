//! Custom widgets for the GUI
//!
//! This module provides reusable UI components for the GUI.
//! Some widgets may not be used yet but are available for future features.

#![allow(dead_code)]

use egui::{Color32, Response, RichText, Ui, Widget};
use super::theme::Colors;

/// A styled badge widget
pub struct Badge {
    text: String,
    color: Color32,
    bg_color: Color32,
}

impl Badge {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            color: Colors::TEXT_PRIMARY,
            bg_color: Colors::BG_LIGHT,
        }
    }
    
    pub fn color(mut self, color: Color32) -> Self {
        self.color = color;
        self
    }
    
    pub fn bg_color(mut self, bg_color: Color32) -> Self {
        self.bg_color = bg_color;
        self
    }
    
    pub fn success() -> Self {
        Self {
            text: String::new(),
            color: Color32::WHITE,
            bg_color: Colors::GREEN_SUCCESS,
        }
    }
    
    pub fn warning() -> Self {
        Self {
            text: String::new(),
            color: Color32::BLACK,
            bg_color: Colors::YELLOW_WARNING,
        }
    }
    
    pub fn error() -> Self {
        Self {
            text: String::new(),
            color: Color32::WHITE,
            bg_color: Colors::RED_ACCENT,
        }
    }
    
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.text = text.into();
        self
    }
}

impl Widget for Badge {
    fn ui(self, ui: &mut Ui) -> Response {
        let text = RichText::new(format!(" {} ", self.text))
            .color(self.color)
            .background_color(self.bg_color);
        ui.label(text)
    }
}

/// A styled card widget
pub struct Card<'a> {
    title: &'a str,
    icon: Option<&'a str>,
}

impl<'a> Card<'a> {
    pub fn new(title: &'a str) -> Self {
        Self { title, icon: None }
    }
    
    pub fn icon(mut self, icon: &'a str) -> Self {
        self.icon = Some(icon);
        self
    }
    
    pub fn show<R>(self, ui: &mut Ui, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                if let Some(icon) = self.icon {
                    ui.label(icon);
                }
                ui.heading(self.title);
            });
            ui.separator();
            add_contents(ui)
        }).inner
    }
}

/// Status indicator widget
pub struct StatusIndicator {
    status: Status,
    text: String,
}

#[derive(Clone, Copy)]
pub enum Status {
    Success,
    Warning,
    Error,
    Info,
    Loading,
}

impl StatusIndicator {
    pub fn new(status: Status, text: impl Into<String>) -> Self {
        Self {
            status,
            text: text.into(),
        }
    }
}

impl Widget for StatusIndicator {
    fn ui(self, ui: &mut Ui) -> Response {
        let (icon, color) = match self.status {
            Status::Success => ("✓", Colors::GREEN_SUCCESS),
            Status::Warning => ("⚠", Colors::YELLOW_WARNING),
            Status::Error => ("✗", Colors::RED_LIGHT),
            Status::Info => ("ℹ", Colors::BLUE_INFO),
            Status::Loading => ("⟳", Colors::TEXT_SECONDARY),
        };
        
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon).color(color));
            ui.label(&self.text);
        }).response
    }
}

/// Hex dump widget for displaying binary data
pub struct HexDump<'a> {
    data: &'a [u8],
    max_rows: usize,
}

impl<'a> HexDump<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            max_rows: 16,
        }
    }
    
    pub fn max_rows(mut self, rows: usize) -> Self {
        self.max_rows = rows;
        self
    }
}

impl Widget for HexDump<'_> {
    fn ui(self, ui: &mut Ui) -> Response {
        let bytes_per_row = 16;
        let max_bytes = self.max_rows * bytes_per_row;
        let display_len = self.data.len().min(max_bytes);
        
        let mut text = String::new();
        for (i, chunk) in self.data[..display_len].chunks(bytes_per_row).enumerate() {
            // Address
            text.push_str(&format!("{:08x}  ", i * bytes_per_row));
            
            // Hex bytes
            for (j, byte) in chunk.iter().enumerate() {
                if j == 8 { text.push(' '); }
                text.push_str(&format!("{:02x} ", byte));
            }
            
            // Padding for incomplete rows
            for j in chunk.len()..bytes_per_row {
                if j == 8 { text.push(' '); }
                text.push_str("   ");
            }
            
            text.push_str(" |");
            
            // ASCII representation
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    text.push(*byte as char);
                } else {
                    text.push('.');
                }
            }
            
            text.push_str("|\n");
        }
        
        if self.data.len() > max_bytes {
            text.push_str(&format!("... ({} more bytes)\n", self.data.len() - max_bytes));
        }
        
        ui.label(RichText::new(text.trim_end()).monospace().color(Colors::TEXT_SECONDARY))
    }
}

/// Progress bar with label
pub struct LabeledProgress {
    value: f32,
    label: String,
    color: Color32,
}

impl LabeledProgress {
    pub fn new(value: f32, label: impl Into<String>) -> Self {
        Self {
            value: value.clamp(0.0, 1.0),
            label: label.into(),
            color: Colors::RED_ACCENT,
        }
    }
    
    pub fn color(mut self, color: Color32) -> Self {
        self.color = color;
        self
    }
}

impl Widget for LabeledProgress {
    fn ui(self, ui: &mut Ui) -> Response {
        ui.horizontal(|ui| {
            ui.label(&self.label);
            let progress_bar = egui::ProgressBar::new(self.value)
                .fill(self.color);
            ui.add(progress_bar);
            ui.label(format!("{:.0}%", self.value * 100.0));
        }).response
    }
}

