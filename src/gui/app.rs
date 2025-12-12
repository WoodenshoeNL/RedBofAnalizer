//! Main application state and logic

#![allow(dead_code)]

use crate::core::analyzer;
use crate::core::executor;
use crate::core::models::bof::BofFile;
use crate::core::models::report::{AnalysisReport, ExecutionResult};
use crate::core::parser;
use super::tabs::ActiveTab;
use super::theme::Colors;

use egui::{Align, Layout, RichText};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

/// Message types for async operations
pub enum AppMessage {
    BofLoaded(Box<BofFile>),
    AnalysisComplete(Box<AnalysisReport>),
    ExecutionComplete(Box<ExecutionResult>),
    ExecutionOutput(String),
    Error(String),
}

/// Main application state
pub struct RedBofApp {
    /// Currently loaded BOF file
    bof_file: Option<BofFile>,
    /// Analysis report for current BOF
    analysis_report: Option<AnalysisReport>,
    /// Current active tab
    active_tab: ActiveTab,
    /// File path of the loaded BOF
    file_path: Option<PathBuf>,
    /// Status message
    status_message: String,
    /// Is loading in progress
    is_loading: bool,
    /// Is execution in progress
    is_executing: bool,
    /// Execution output log
    execution_output: Vec<String>,
    /// Arguments for BOF execution
    execution_args: String,
    /// Sandbox mode for execution
    execution_sandbox: bool,
    /// Trace API calls during execution
    execution_trace: bool,
    /// Timeout for execution (seconds)
    execution_timeout: u64,
    /// Search filter for symbols
    symbol_filter: String,
    /// Search filter for sections
    section_filter: String,
    /// Async message channel
    message_rx: Receiver<AppMessage>,
    message_tx: Sender<AppMessage>,
    /// Show disassembly panel
    show_disassembly: bool,
    /// Selected section for disassembly
    selected_section: Option<String>,
}

impl RedBofApp {
    /// Create a new application instance
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = mpsc::channel();
        
        Self {
            bof_file: None,
            analysis_report: None,
            active_tab: ActiveTab::Overview,
            file_path: None,
            status_message: "Ready - Open a BOF file to begin analysis".into(),
            is_loading: false,
            is_executing: false,
            execution_output: Vec::new(),
            execution_args: String::new(),
            execution_sandbox: false,
            execution_trace: false,
            execution_timeout: 30,
            symbol_filter: String::new(),
            section_filter: String::new(),
            message_rx: rx,
            message_tx: tx,
            show_disassembly: false,
            selected_section: None,
        }
    }

    /// Process async messages
    fn process_messages(&mut self) {
        while let Ok(msg) = self.message_rx.try_recv() {
            match msg {
                AppMessage::BofLoaded(bof) => {
                    self.bof_file = Some(*bof);
                    self.is_loading = false;
                    self.status_message = format!(
                        "Loaded: {}",
                        self.file_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
                    );
                    // Trigger analysis
                    self.run_analysis();
                }
                AppMessage::AnalysisComplete(report) => {
                    self.analysis_report = Some(*report);
                    self.is_loading = false;
                    self.status_message = "Analysis complete".into();
                }
                AppMessage::ExecutionComplete(result) => {
                    self.is_executing = false;
                    
                    // Add BOF output first
                    if !result.output.is_empty() {
                        self.execution_output.push("--- Output ---".into());
                        for msg in &result.output {
                            self.execution_output.push(format!("[{}] {}", msg.message_type, msg.content));
                        }
                    }
                    
                    // Add API calls if tracing was enabled
                    if !result.api_calls.is_empty() {
                        self.execution_output.push(format!("--- API Calls ({}) ---", result.api_calls.len()));
                        for call in &result.api_calls {
                            self.execution_output.push(format!("  {} @ {}", call.name, call.timestamp));
                            for arg in &call.arguments {
                                self.execution_output.push(format!("    - {}", arg));
                            }
                        }
                    }
                    
                    // Add execution result at the end
                    self.execution_output.push(format!(
                        "--- Execution {} ---",
                        if result.success { "SUCCESS" } else { "FAILED" }
                    ));
                    self.execution_output.push(format!(
                        "Time: {:.3}s",
                        result.execution_time.as_secs_f64()
                    ));
                    
                    if let Some(err) = &result.error {
                        self.execution_output.push(format!("Error: {}", err));
                    }
                    
                    self.execution_output.push(String::new()); // Empty line
                    
                    self.status_message = if result.success {
                        "Execution complete".into()
                    } else {
                        "Execution failed".into()
                    };
                }
                AppMessage::ExecutionOutput(output) => {
                    self.execution_output.push(output);
                }
                AppMessage::Error(err) => {
                    self.is_loading = false;
                    self.is_executing = false;
                    self.status_message = format!("Error: {}", err);
                }
            }
        }
    }

    /// Open file dialog and load BOF
    fn open_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("BOF Files", &["o", "obj", "bof"])
            .add_filter("All Files", &["*"])
            .pick_file()
        {
            self.load_bof(path);
        }
    }

    /// Load a BOF file
    fn load_bof(&mut self, path: PathBuf) {
        self.is_loading = true;
        self.status_message = format!("Loading {}...", path.display());
        self.file_path = Some(path.clone());
        
        let tx = self.message_tx.clone();
        
        thread::spawn(move || {
            match parser::load_bof(&path) {
                Ok(bof) => {
                    let _ = tx.send(AppMessage::BofLoaded(Box::new(bof)));
                }
                Err(e) => {
                    let _ = tx.send(AppMessage::Error(e.to_string()));
                }
            }
        });
    }

    /// Run analysis on loaded BOF
    fn run_analysis(&mut self) {
        if let Some(bof) = &self.bof_file {
            let bof_clone = bof.clone();
            let tx = self.message_tx.clone();
            self.is_loading = true;
            self.status_message = "Analyzing...".into();
            
            thread::spawn(move || {
                // Enable all analysis options
                match analyzer::analyze(&bof_clone, true, true, true, true, true, true) {
                    Ok(report) => {
                        let _ = tx.send(AppMessage::AnalysisComplete(Box::new(report)));
                    }
                    Err(e) => {
                        let _ = tx.send(AppMessage::Error(e.to_string()));
                    }
                }
            });
        }
    }

    /// Render the top menu bar
    fn render_menu_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open BOF...").clicked() {
                        self.open_file();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Reload").clicked() {
                        if let Some(path) = self.file_path.clone() {
                            self.load_bof(path);
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                
                ui.menu_button("Analysis", |ui| {
                    if ui.button("Re-analyze").clicked() {
                        self.run_analysis();
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.checkbox(&mut self.show_disassembly, "Show Disassembly");
                });
                
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        // TODO: Show about dialog
                        ui.close_menu();
                    }
                });
                
                // Show loaded BOF file path
                if let Some(path) = &self.file_path {
                    ui.separator();
                    ui.label(RichText::new("BOF:").color(Colors::TEXT_SECONDARY).small());
                    ui.label(RichText::new(path.display().to_string()).monospace().small());
                }
                
                // Right-aligned status
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if self.is_loading {
                        ui.spinner();
                    }
                    ui.label(RichText::new(&self.status_message).color(Colors::TEXT_SECONDARY).small());
                });
            });
        });
    }

    /// Render the tab bar
    fn render_tab_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            
            for tab in [
                ActiveTab::Overview,
                ActiveTab::Sections,
                ActiveTab::Symbols,
                ActiveTab::Imports,
                ActiveTab::Lints,
                ActiveTab::Disassembly,
                ActiveTab::Execute,
            ] {
                let is_selected = self.active_tab == tab;
                let text = match tab {
                    ActiveTab::Overview => "Overview",
                    ActiveTab::Sections => "Sections",
                    ActiveTab::Symbols => "Symbols",
                    ActiveTab::Imports => "Imports",
                    ActiveTab::Lints => "Lints",
                    ActiveTab::Disassembly => "Disasm",
                    ActiveTab::Execute => "Execute",
                };
                
                let response = ui.selectable_label(is_selected, text);
                if response.clicked() {
                    self.active_tab = tab;
                }
            }
        });
        ui.separator();
    }

    /// Render main content area
    fn render_content(&mut self, ui: &mut egui::Ui) {
        match self.active_tab {
            ActiveTab::Overview => self.render_overview_tab(ui),
            ActiveTab::Sections => self.render_sections_tab(ui),
            ActiveTab::Symbols => self.render_symbols_tab(ui),
            ActiveTab::Imports => self.render_imports_tab(ui),
            ActiveTab::Lints => self.render_lints_tab(ui),
            ActiveTab::Disassembly => self.render_disassembly_tab(ui),
            ActiveTab::Execute => self.render_execute_tab(ui),
        }
    }

    /// Render overview tab
    fn render_overview_tab(&self, ui: &mut egui::Ui) {
        if let Some(bof) = &self.bof_file {
            egui::ScrollArea::vertical().show(ui, |ui| {
                // File info card
                ui.group(|ui| {
                    ui.heading("File Information");
                    ui.separator();
                    
                    egui::Grid::new("file_info_grid")
                        .num_columns(2)
                        .spacing([40.0, 6.0])
                        .show(ui, |ui| {
                            ui.label(RichText::new("File:").color(Colors::TEXT_SECONDARY));
                            ui.label(self.file_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default());
                            ui.end_row();
                            
                            ui.label(RichText::new("Architecture:").color(Colors::TEXT_SECONDARY));
                            ui.label(format!("{:?}", bof.header.machine));
                            ui.end_row();
                            
                            ui.label(RichText::new("Sections:").color(Colors::TEXT_SECONDARY));
                            ui.label(format!("{}", bof.sections.len()));
                            ui.end_row();
                            
                            ui.label(RichText::new("Symbols:").color(Colors::TEXT_SECONDARY));
                            ui.label(format!("{}", bof.symbols.len()));
                            ui.end_row();
                            
                            ui.label(RichText::new("Entry Point:").color(Colors::TEXT_SECONDARY));
                            let entry_status = if bof.entry_point.is_some() { "Found (go)" } else { "Not found" };
                            ui.label(entry_status);
                            ui.end_row();
                        });
                });
                
                ui.add_space(10.0);
                
                // Analysis summary
                if let Some(report) = &self.analysis_report {
                    ui.group(|ui| {
                        ui.heading("Analysis Summary");
                        ui.separator();
                        
                        egui::Grid::new("analysis_grid")
                            .num_columns(2)
                            .spacing([40.0, 6.0])
                            .show(ui, |ui| {
                                ui.label(RichText::new("Win32 APIs:").color(Colors::TEXT_SECONDARY));
                                ui.label(format!("{}", report.apis.win32_apis.len()));
                                ui.end_row();
                                
                                ui.label(RichText::new("Beacon APIs:").color(Colors::TEXT_SECONDARY));
                                ui.label(format!("{}", report.apis.beacon_apis.len()));
                                ui.end_row();
                                
                                ui.label(RichText::new("Lint Issues:").color(Colors::TEXT_SECONDARY));
                                let lint_count = report.lints.len();
                                let color = if lint_count == 0 { Colors::GREEN_SUCCESS } else { Colors::YELLOW_WARNING };
                                ui.label(RichText::new(format!("{}", lint_count)).color(color));
                                ui.end_row();
                                
                                ui.label(RichText::new("Capabilities:").color(Colors::TEXT_SECONDARY));
                                ui.label(format!("{}", report.security.capabilities.len()));
                                ui.end_row();
                                
                                ui.label(RichText::new("OpSec Score:").color(Colors::TEXT_SECONDARY));
                                let score = report.security.opsec_score;
                                let color = if score >= 80 { Colors::GREEN_SUCCESS }
                                    else if score >= 50 { Colors::YELLOW_WARNING }
                                    else { Colors::RED_LIGHT };
                                ui.label(RichText::new(format!("{}/100", score)).color(color));
                                ui.end_row();
                            });
                    });
                    
                    ui.add_space(10.0);
                    
                    // Capabilities
                    if !report.security.capabilities.is_empty() {
                        ui.group(|ui| {
                            ui.heading("Detected Capabilities");
                            ui.separator();
                            
                            ui.horizontal_wrapped(|ui| {
                                for cap in &report.security.capabilities {
                                    let text = format!("{:?}", cap);
                                    ui.label(RichText::new(format!(" {} ", text))
                                        .background_color(Colors::BG_LIGHT)
                                        .color(Colors::RED_LIGHT));
                                }
                            });
                        });
                    }
                }
            });
        } else {
            // Welcome screen
            ui.vertical_centered(|ui| {
                ui.add_space(100.0);
                ui.heading(RichText::new("RedBofAnalizer").size(32.0).color(Colors::RED_ACCENT));
                ui.add_space(10.0);
                ui.label(RichText::new("BOF Analyzer & Execution Tool").color(Colors::TEXT_SECONDARY));
                ui.add_space(30.0);
                
                ui.label(RichText::new("Use File > Open BOF to load a file").size(16.0));
                
                ui.add_space(20.0);
                ui.label(RichText::new("or drag and drop a .o/.obj/.bof file").color(Colors::TEXT_MUTED));
            });
        }
    }

    /// Render sections tab
    fn render_sections_tab(&mut self, ui: &mut egui::Ui) {
        if let Some(bof) = &self.bof_file {
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.section_filter);
            });
            ui.separator();
            
            egui::ScrollArea::vertical().show(ui, |ui| {
                for section in &bof.sections {
                    let name_lower = section.name.to_lowercase();
                    if !self.section_filter.is_empty() && !name_lower.contains(&self.section_filter.to_lowercase()) {
                        continue;
                    }
                    
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&section.name).strong().monospace());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(format!("{} bytes", section.raw_size)).color(Colors::TEXT_SECONDARY));
                            });
                        });
                        
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Characteristics:").color(Colors::TEXT_SECONDARY).small());
                            
                            let chars = section.characteristics;
                            if chars & 0x20 != 0 { ui.label(RichText::new("CODE").small().color(Colors::BLUE_INFO)); }
                            if chars & 0x40 != 0 { ui.label(RichText::new("DATA").small().color(Colors::GREEN_SUCCESS)); }
                            if chars & 0x80 != 0 { ui.label(RichText::new("BSS").small().color(Colors::YELLOW_WARNING)); }
                            if chars & 0x20000000 != 0 { ui.label(RichText::new("EXEC").small().color(Colors::RED_LIGHT)); }
                            if chars & 0x40000000 != 0 { ui.label(RichText::new("READ").small()); }
                            if chars & 0x80000000 != 0 { ui.label(RichText::new("WRITE").small().color(Colors::YELLOW_WARNING)); }
                        });
                        
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("Entropy: {:.2}", section.entropy)).color(Colors::TEXT_SECONDARY).small());
                        });
                        
                        // Hex preview
                        if !section.data.is_empty() {
                            ui.collapsing("Hex Preview", |ui| {
                                let preview_len = section.data.len().min(256);
                                let hex_str: String = section.data[..preview_len]
                                    .iter()
                                    .enumerate()
                                    .map(|(i, b)| {
                                        if i > 0 && i % 16 == 0 { format!("\n{:02x}", b) }
                                        else if i > 0 && i % 8 == 0 { format!("  {:02x}", b) }
                                        else { format!(" {:02x}", b) }
                                    })
                                    .collect();
                                ui.label(RichText::new(hex_str.trim()).monospace().color(Colors::TEXT_SECONDARY));
                                if section.data.len() > 256 {
                                    ui.label(RichText::new("... (truncated)").color(Colors::TEXT_MUTED));
                                }
                            });
                        }
                    });
                    ui.add_space(4.0);
                }
            });
        } else {
            ui.label("No BOF loaded");
        }
    }

    /// Render symbols tab
    fn render_symbols_tab(&mut self, ui: &mut egui::Ui) {
        if let Some(bof) = &self.bof_file {
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.symbol_filter);
                ui.separator();
                ui.label(format!("{} symbols", bof.symbols.len()));
            });
            ui.separator();
            
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("symbols_grid")
                    .num_columns(4)
                    .striped(true)
                    .min_col_width(100.0)
                    .show(ui, |ui| {
                        // Header
                        ui.label(RichText::new("Name").strong());
                        ui.label(RichText::new("Type").strong());
                        ui.label(RichText::new("Section").strong());
                        ui.label(RichText::new("Value").strong());
                        ui.end_row();
                        
                        for sym in &bof.symbols {
                            let name_lower = sym.name.to_lowercase();
                            if !self.symbol_filter.is_empty() && !name_lower.contains(&self.symbol_filter.to_lowercase()) {
                                continue;
                            }
                            
                            // Color code by type
                            let color = if sym.name.starts_with("__imp_") || sym.name.starts_with("__imp__") {
                                Colors::BLUE_INFO
                            } else if sym.name == "go" || sym.name == "_go" {
                                Colors::GREEN_SUCCESS
                            } else if sym.is_external {
                                Colors::YELLOW_WARNING
                            } else {
                                Colors::TEXT_PRIMARY
                            };
                            
                            ui.label(RichText::new(&sym.name).monospace().color(color));
                            ui.label(if sym.is_external { "External" } else { "Local" });
                            ui.label(format!("{}", sym.section.map(|i| i.to_string()).unwrap_or("-".into())));
                            ui.label(format!("0x{:08x}", sym.value));
                            ui.end_row();
                        }
                    });
            });
        } else {
            ui.label("No BOF loaded");
        }
    }

    /// Render imports tab
    fn render_imports_tab(&self, ui: &mut egui::Ui) {
        if let Some(report) = &self.analysis_report {
            egui::ScrollArea::vertical().show(ui, |ui| {
                // Win32 APIs
                ui.group(|ui| {
                    ui.heading("Win32 APIs");
                    ui.label(format!("{} functions", report.apis.win32_apis.len()));
                    ui.separator();
                    
                    egui::Grid::new("win32_apis_grid")
                        .num_columns(2)
                        .striped(true)
                        .min_col_width(200.0)
                        .show(ui, |ui| {
                            ui.label(RichText::new("DLL").strong());
                            ui.label(RichText::new("Function").strong());
                            ui.end_row();
                            
                            for api in &report.apis.win32_apis {
                                ui.label(RichText::new(&api.dll).color(Colors::TEXT_SECONDARY));
                                ui.label(RichText::new(&api.function).monospace());
                                ui.end_row();
                            }
                        });
                });
                
                ui.add_space(10.0);
                
                // Beacon APIs
                ui.group(|ui| {
                    ui.heading("Beacon APIs");
                    ui.label(format!("{} functions", report.apis.beacon_apis.len()));
                    ui.separator();
                    
                    for api in &report.apis.beacon_apis {
                        ui.label(RichText::new(api).monospace().color(Colors::BLUE_INFO));
                    }
                });
            });
        } else {
            ui.label("No analysis report available");
        }
    }

    /// Render lints tab
    fn render_lints_tab(&self, ui: &mut egui::Ui) {
        if let Some(report) = &self.analysis_report {
            egui::ScrollArea::vertical().show(ui, |ui| {
                if report.lints.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(50.0);
                        ui.label(RichText::new("No lint issues found!").size(18.0).color(Colors::GREEN_SUCCESS));
                    });
                } else {
                    ui.label(RichText::new(format!("{} lint findings", report.lints.len()))
                        .color(Colors::YELLOW_WARNING));
                    ui.separator();
                    
                    for finding in &report.lints {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                use crate::core::models::lint::Severity;
                                let (icon, color) = match finding.severity {
                                    Severity::Error => ("[!]", Colors::RED_LIGHT),
                                    Severity::Warning => ("[*]", Colors::YELLOW_WARNING),
                                    Severity::Info => ("[i]", Colors::BLUE_INFO),
                                };
                                ui.label(icon);
                                ui.label(RichText::new(&finding.code).strong().monospace());
                                ui.label(RichText::new(format!("{}", finding.severity)).color(color));
                            });
                            
                            ui.label(&finding.message);
                            
                            if let Some(suggestion) = &finding.suggestion {
                                ui.label(RichText::new(format!("Tip: {}", suggestion))
                                    .color(Colors::TEXT_SECONDARY).italics());
                            }
                        });
                        ui.add_space(4.0);
                    }
                }
            });
        } else {
            ui.label("No analysis report available");
        }
    }

    /// Render disassembly tab
    fn render_disassembly_tab(&self, ui: &mut egui::Ui) {
        if let Some(report) = &self.analysis_report {
            egui::ScrollArea::vertical().show(ui, |ui| {
                if report.disassembly.is_empty() {
                    ui.label("No disassembly available");
                } else {
                    for disasm_result in &report.disassembly {
                        ui.group(|ui| {
                            ui.heading(format!("Section: {}", disasm_result.section_name));
                            ui.label(format!("{} instructions | {} functions detected", 
                                disasm_result.stats.total_instructions,
                                disasm_result.functions.len()));
                            ui.separator();
                            
                            egui::Grid::new(format!("disasm_grid_{}", disasm_result.section_name))
                                .num_columns(3)
                                .striped(true)
                                .min_col_width(80.0)
                                .show(ui, |ui| {
                                    ui.label(RichText::new("Address").strong());
                                    ui.label(RichText::new("Bytes").strong());
                                    ui.label(RichText::new("Instruction").strong());
                                    ui.end_row();
                                    
                                    for instr in &disasm_result.instructions {
                                        ui.label(RichText::new(format!("0x{:08x}", instr.address)).monospace());
                                        
                                        let bytes_str: String = instr.bytes.iter()
                                            .map(|b| format!("{:02x}", b))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        ui.label(RichText::new(bytes_str).monospace().color(Colors::TEXT_SECONDARY));
                                        
                                        // Color code instructions
                                        let color = if instr.is_call {
                                            Colors::BLUE_INFO
                                        } else if instr.is_jump {
                                            Colors::YELLOW_WARNING
                                        } else if instr.is_return {
                                            Colors::RED_LIGHT
                                        } else {
                                            Colors::TEXT_PRIMARY
                                        };
                                        
                                        ui.label(RichText::new(&instr.text).monospace().color(color));
                                        ui.end_row();
                                    }
                                });
                        });
                        ui.add_space(10.0);
                    }
                }
            });
        } else {
            ui.label("No analysis report available");
        }
    }

    /// Render execute tab
    fn render_execute_tab(&mut self, ui: &mut egui::Ui) {
        if let Some(bof) = &self.bof_file {
            let bof_clone = bof.clone();
            
            // Execution options panel
            ui.group(|ui| {
                ui.heading("Execution Options");
                ui.separator();
                
                egui::Grid::new("exec_options_grid")
                    .num_columns(2)
                    .spacing([20.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Arguments:");
                        ui.add(egui::TextEdit::singleline(&mut self.execution_args)
                            .hint_text(RichText::new("z:string i:123 s:456 b:deadbeef").color(Colors::TEXT_MUTED))
                            .desired_width(400.0));
                        ui.end_row();
                        
                        ui.label("Timeout (sec):");
                        ui.add(egui::DragValue::new(&mut self.execution_timeout)
                            .range(1..=300)
                            .speed(1.0));
                        ui.end_row();
                        
                        ui.label("Options:");
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.execution_sandbox, "Sandbox");
                            ui.checkbox(&mut self.execution_trace, "Trace API calls");
                        });
                        ui.end_row();
                    });
                
                ui.add_space(5.0);
                
                // Argument format help
                ui.collapsing("Argument Format Help", |ui| {
                    ui.label(RichText::new("Format: TYPE:VALUE separated by spaces").small());
                    ui.add_space(4.0);
                    egui::Grid::new("arg_help_grid")
                        .num_columns(3)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label(RichText::new("Type").strong().small());
                            ui.label(RichText::new("Description").strong().small());
                            ui.label(RichText::new("Example").strong().small());
                            ui.end_row();
                            
                            ui.label(RichText::new("z").monospace().small());
                            ui.label(RichText::new("ANSI string").small());
                            ui.label(RichText::new("z:hello").monospace().small());
                            ui.end_row();
                            
                            ui.label(RichText::new("Z").monospace().small());
                            ui.label(RichText::new("Wide string").small());
                            ui.label(RichText::new("Z:hello").monospace().small());
                            ui.end_row();
                            
                            ui.label(RichText::new("i").monospace().small());
                            ui.label(RichText::new("32-bit integer").small());
                            ui.label(RichText::new("i:12345").monospace().small());
                            ui.end_row();
                            
                            ui.label(RichText::new("s").monospace().small());
                            ui.label(RichText::new("16-bit integer").small());
                            ui.label(RichText::new("s:456").monospace().small());
                            ui.end_row();
                            
                            ui.label(RichText::new("b").monospace().small());
                            ui.label(RichText::new("Binary (hex)").small());
                            ui.label(RichText::new("b:deadbeef").monospace().small());
                            ui.end_row();
                        });
                });
            });
            
            ui.add_space(10.0);
            
            // Execute and Clear buttons
            ui.horizontal(|ui| {
                let can_execute = !self.is_executing && bof_clone.entry_point.is_some();
                
                ui.add_enabled_ui(can_execute, |ui| {
                    if ui.button(RichText::new("Execute BOF").size(16.0)).clicked() {
                        self.execute_bof();
                    }
                });
                
                if self.is_executing {
                    ui.spinner();
                    ui.label(RichText::new("Executing...").color(Colors::YELLOW_WARNING));
                }
                
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Clear Output").clicked() {
                        self.execution_output.clear();
                    }
                });
            });
            
            if bof_clone.entry_point.is_none() {
                ui.label(RichText::new("Warning: No entry point (go function) found in BOF")
                    .color(Colors::YELLOW_WARNING));
            }
            
            ui.separator();
            
            // Output console
            ui.heading("Output");
            
            let mut output_text = self.execution_output.join("\n");
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut output_text)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(20)
                            .interactive(true)
                    );
                });
        } else {
            ui.vertical_centered(|ui| {
                ui.add_space(50.0);
                ui.label(RichText::new("Load a BOF file first").size(18.0).color(Colors::TEXT_SECONDARY));
            });
        }
    }
    
    /// Execute the loaded BOF
    fn execute_bof(&mut self) {
        // Guard against re-entry
        if self.is_executing {
            return;
        }
        
        if let Some(bof) = &self.bof_file {
            // Parse arguments
            let args_result = if self.execution_args.is_empty() {
                Ok(Vec::new())
            } else {
                executor::arguments::parse_arguments(&self.execution_args)
            };
            
            let packed_args = match args_result {
                Ok(args) => args,
                Err(e) => {
                    self.execution_output.push(format!("Error: Argument error: {}", e));
                    return;
                }
            };
            
            self.is_executing = true;
            self.status_message = "Executing BOF...".into();
            self.execution_output.push(format!(
                "--- Executing {} ---",
                self.file_path.as_ref().map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string()).unwrap_or_default()
            ));
            
            if !self.execution_args.is_empty() {
                self.execution_output.push(format!("Args: {}", self.execution_args));
            }
            
            let bof_clone = bof.clone();
            let sandbox = self.execution_sandbox;
            let trace = self.execution_trace;
            let timeout = Duration::from_secs(self.execution_timeout);
            let tx = self.message_tx.clone();
            
            thread::spawn(move || {
                // Use catch_unwind to handle any panics in the execution
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    executor::execute(&bof_clone, &packed_args, sandbox, trace, timeout)
                }));
                
                match result {
                    Ok(Ok(exec_result)) => {
                        let _ = tx.send(AppMessage::ExecutionComplete(Box::new(exec_result)));
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(AppMessage::Error(format!("Execution failed: {}", e)));
                    }
                    Err(panic_info) => {
                        // Thread panicked - extract panic message
                        let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                            s.to_string()
                        } else if let Some(s) = panic_info.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            "Unknown panic during BOF execution".to_string()
                        };
                        let _ = tx.send(AppMessage::Error(format!("BOF crashed: {}", panic_msg)));
                    }
                }
            });
        }
    }
}

impl eframe::App for RedBofApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process async messages
        self.process_messages();
        
        // Handle dropped files
        ctx.input(|i| {
            if !i.raw.dropped_files.is_empty() {
                if let Some(path) = i.raw.dropped_files[0].path.clone() {
                    self.load_bof(path);
                }
            }
        });
        
        // Render menu bar
        self.render_menu_bar(ctx);
        
        // Main content panel
        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_tab_bar(ui);
            self.render_content(ui);
        });
        
        // Request repaint if loading or executing
        if self.is_loading || self.is_executing {
            ctx.request_repaint();
        }
    }
}
