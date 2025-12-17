//! Main application state and logic

#![allow(dead_code)]

use crate::core::analyzer;
use crate::core::analyzer::opsec_config::ProfileManager;
use crate::core::executor;
use crate::core::models::bof::BofFile;
use crate::core::models::report::{AnalysisReport, ExecutionResult};
use crate::core::parser;
use super::tabs::ActiveTab;
use super::theme::Colors;
use super::widgets::HexDump;

use egui::{Align, Layout, RichText};
use std::collections::HashSet;
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
    /// Cobalt Strike compatible argument mode
    execution_cs_compat: bool,
    /// Emulate real BeaconInformation data (instead of zeroed stub)
    execution_emulate_beacon_info: bool,
    /// Override automatic signature detection
    override_signature_detection: bool,
    /// Manual signature override (e.g., "zi", "zzi", etc.)
    manual_signature: String,
    /// Timeout for execution (seconds)
    execution_timeout: u64,
    /// Search filter for symbols
    symbol_filter: String,
    /// Search filter for sections
    section_filter: String,
    /// Search/filter for imports (used by OpSec jump navigation)
    imports_filter: String,
    /// Async message channel
    message_rx: Receiver<AppMessage>,
    message_tx: Sender<AppMessage>,
    /// Show disassembly panel
    show_disassembly: bool,
    /// Selected section for disassembly
    selected_section: Option<String>,
    /// Selected entry point name (None means use default)
    selected_entry_point: Option<String>,
    /// Enhanced OpSec analysis result
    opsec_analysis: Option<crate::core::analyzer::opsec::EnhancedOpsecAnalysis>,
    /// Compatibility analysis result
    compatibility_analysis: Option<crate::core::analyzer::compatibility::CompatibilityAnalysis>,
    /// Calling convention analysis result
    calling_convention_analysis: Option<crate::core::analyzer::calling_convention::CallingConventionAnalysis>,
    /// OpSec tab filter state
    opsec_api_filter: String,
    opsec_risk_filter: crate::core::analyzer::opsec::OpsecCategory,
    opsec_compat_severity_filter: crate::core::analyzer::compatibility::CompatibilitySeverity,
    opsec_show_all_severities: bool,
    /// OpSec table sorting state
    opsec_sort_column: Option<usize>, // 0=API, 1=Category, 2=Description
    opsec_sort_ascending: bool,
    /// OpSec filter preset (None = custom, Some = preset name)
    opsec_filter_preset: Option<String>,
    /// YARA rule paths (files or directories)
    yara_rule_paths: Vec<PathBuf>,
    /// Persistent YARA rules folder (automatically loaded on startup)
    yara_persistent_folder: Option<PathBuf>,
    /// Use default YARA rules together with custom rules
    yara_use_default_rules: bool,
    /// YARA rule manager for individual rule management
    yara_rule_manager: crate::core::analyzer::yara_rules::RuleManager,
    /// Rule management UI state
    rule_mgmt_search_filter: String,
    rule_mgmt_selected_category: Option<String>,
    rule_mgmt_selected_tags: HashSet<String>,
    rule_mgmt_show_disabled: bool,
    rule_mgmt_show_metrics: bool,
    rule_mgmt_selected_rule: Option<String>,
    /// OpSec scoring profile manager
    opsec_profile_manager: ProfileManager,
    /// Currently selected OpSec profile name
    opsec_selected_profile: String,
    /// Section name for which hex preview window should be shown (None = closed)
    hex_preview_section: Option<String>,
    /// Address to highlight and scroll to in disassembly view (set by navigation from OpSec/Imports)
    disasm_highlight_address: Option<u64>,
    /// Resolved import addresses from last execution (symbol_name -> function address)
    last_resolved_imports: std::collections::HashMap<String, u64>,
    /// Base address where BOF code was loaded during last execution
    last_code_base_address: Option<u64>,
}

impl RedBofApp {
    /// Create a new application instance
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = mpsc::channel();
        
        // Load persisted YARA rule paths
        let yara_rule_paths = if let Some(storage) = cc.storage {
            let key = format!("{}.yara_rule_paths", eframe::APP_KEY);
            if let Some(paths_json) = storage.get_string(&key) {
                if let Ok(paths) = serde_json::from_str::<Vec<String>>(&paths_json) {
                    paths.into_iter().map(PathBuf::from).collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        
        // Load persisted YARA use default rules setting
        let yara_use_default_rules = if let Some(storage) = cc.storage {
            let key = format!("{}.yara_use_default_rules", eframe::APP_KEY);
            storage.get_string(&key)
                .and_then(|s| s.parse::<bool>().ok())
                .unwrap_or(true) // Default to true
        } else {
            true
        };
        
        // Load persisted YARA rules folder
        let yara_persistent_folder = if let Some(storage) = cc.storage {
            let key = format!("{}.yara_persistent_folder", eframe::APP_KEY);
            storage.get_string(&key)
                .map(|s| PathBuf::from(s))
                .filter(|p| p.exists() && p.is_dir())
        } else {
            None
        };
        
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
            execution_cs_compat: false,
            execution_emulate_beacon_info: false,
            override_signature_detection: false,
            manual_signature: String::new(),
            execution_timeout: 30,
            symbol_filter: String::new(),
            section_filter: String::new(),
            imports_filter: String::new(),
            message_rx: rx,
            message_tx: tx,
            show_disassembly: false,
            selected_section: None,
            selected_entry_point: None,
            opsec_analysis: None,
            compatibility_analysis: None,
            calling_convention_analysis: None,
            opsec_api_filter: String::new(),
            opsec_risk_filter: crate::core::analyzer::opsec::OpsecCategory::LowRisk,
            opsec_compat_severity_filter: crate::core::analyzer::compatibility::CompatibilitySeverity::Warning,
            opsec_show_all_severities: true,
            opsec_sort_column: None,
            opsec_sort_ascending: true,
            opsec_filter_preset: None,
            yara_rule_paths,
            yara_persistent_folder,
            yara_use_default_rules,
            yara_rule_manager: crate::core::analyzer::yara_rules::RuleManager::new(),
            rule_mgmt_search_filter: String::new(),
            rule_mgmt_selected_category: None,
            rule_mgmt_selected_tags: HashSet::new(),
            rule_mgmt_show_disabled: true,
            rule_mgmt_show_metrics: false,
            rule_mgmt_selected_rule: None,
            opsec_profile_manager: ProfileManager::with_default_profiles(),
            opsec_selected_profile: "default".to_string(),
            hex_preview_section: None,
            disasm_highlight_address: None,
            last_resolved_imports: std::collections::HashMap::new(),
            last_code_base_address: None,
        }
    }
    
    /// Save YARA rule paths and settings to persistent storage
    fn save_yara_rule_paths(&self, ctx: &egui::Context) {
        // Use egui's memory persistence which is automatically saved by eframe
        let paths: Vec<String> = self.yara_rule_paths.iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        if let Ok(paths_json) = serde_json::to_string(&paths) {
            ctx.data_mut(|d| {
                let key = format!("{}.yara_rule_paths", eframe::APP_KEY);
                d.insert_persisted(egui::Id::new(&key), paths_json);
            });
        }
        // Save use default rules setting
        ctx.data_mut(|d| {
            let key = format!("{}.yara_use_default_rules", eframe::APP_KEY);
            d.insert_persisted(egui::Id::new(&key), self.yara_use_default_rules.to_string());
        });
        // Save persistent folder
        ctx.data_mut(|d| {
            let key = format!("{}.yara_persistent_folder", eframe::APP_KEY);
            let folder_str = self.yara_persistent_folder.as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            d.insert_persisted(egui::Id::new(&key), folder_str);
        });
    }

    /// Process async messages
    fn process_messages(&mut self) {
        while let Ok(msg) = self.message_rx.try_recv() {
            match msg {
                AppMessage::BofLoaded(bof) => {
                    // Reset selected entry point when loading a new BOF
                    self.selected_entry_point = None;
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
                    
                    // Perform advanced analysis
                    if let Some(bof) = &self.bof_file {
                        use crate::core::analyzer::opsec::analyze_api_opsec_with_bof;
                        let profile = self.opsec_profile_manager.get_profile(&self.opsec_selected_profile)
                            .or_else(|| self.opsec_profile_manager.get_profile("default"));
                        self.opsec_analysis = Some(analyze_api_opsec_with_bof(&bof.imports, Some(bof), profile));
                        self.compatibility_analysis = Some(analyzer::analyze_compatibility(bof));
                        self.calling_convention_analysis = Some(analyzer::analyze_calling_conventions(bof));
                    }
                }
                AppMessage::ExecutionComplete(result) => {
                    self.is_executing = false;
                    
                    // Store resolved imports for display in Imports tab
                    self.last_resolved_imports = result.resolved_imports.clone();
                    self.last_code_base_address = result.code_base_address;
                    
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
                    
                    // Add resolved imports (showing actual function addresses)
                    if !result.resolved_imports.is_empty() {
                        self.execution_output.push(format!("--- Resolved Imports ({}) ---", result.resolved_imports.len()));
                        let mut sorted_imports: Vec<_> = result.resolved_imports.iter().collect();
                        sorted_imports.sort_by_key(|(name, _)| *name);
                        for (symbol_name, address) in sorted_imports {
                            // Format: __imp_KERNEL32$GetLastError -> 0x00007FFE12345678
                            self.execution_output.push(format!("  {} -> 0x{:016X}", symbol_name, address));
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
            
            let yara_rules = self.yara_rule_paths.clone();
            let persistent_folder = self.yara_persistent_folder.clone();
            let use_default_rules = self.yara_use_default_rules;
            thread::spawn(move || {
                // Convert YARA rule paths to YaraRuleSource
                use crate::core::analyzer::YaraRuleSource;
                let mut yara_rule_sources: Vec<YaraRuleSource> = yara_rules.into_iter().map(|path| {
                    if path.is_dir() {
                        YaraRuleSource::Directory(path)
                    } else {
                        YaraRuleSource::File(path)
                    }
                }).collect();
                
                // Add persistent folder if set
                if let Some(folder) = persistent_folder {
                    if folder.exists() && folder.is_dir() {
                        yara_rule_sources.push(YaraRuleSource::Directory(folder));
                    }
                }
                
                // Enable all analysis options
                match analyzer::analyze(&bof_clone, true, true, true, true, true, true, &yara_rule_sources, use_default_rules) {
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
                ActiveTab::OpSec,
                ActiveTab::Disassembly,
                ActiveTab::StackAnalysis,
                ActiveTab::Yara,
                ActiveTab::Execute,
            ] {
                let is_selected = self.active_tab == tab;
                // Use short names for tabs to fit better
                let text = match tab {
                    ActiveTab::Overview => "Overview",
                    ActiveTab::Sections => "Sections",
                    ActiveTab::Symbols => "Symbols",
                    ActiveTab::Imports => "Imports",
                    ActiveTab::Lints => "Lints",
                    ActiveTab::OpSec => "OpSec",
                    ActiveTab::Disassembly => "Disasm",
                    ActiveTab::StackAnalysis => "Stack",
                    ActiveTab::Yara => "YARA",
                    ActiveTab::Execute => "Execute",
                };
                
                // Use selectable_label for standard tab appearance
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
            ActiveTab::OpSec => self.render_opsec_tab(ui),
            ActiveTab::Disassembly => self.render_disassembly_tab(ui),
            ActiveTab::StackAnalysis => self.render_stack_analysis_tab(ui),
            ActiveTab::Yara => {
                let ctx = ui.ctx().clone();
                self.render_yara_tab(ui, &ctx);
            },
            ActiveTab::Execute => self.render_execute_tab(ui),
        }
    }

    /// Render overview tab
    fn render_overview_tab(&mut self, ui: &mut egui::Ui) {
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
                    
                    // Argument Signature
                    ui.group(|ui| {
                        ui.heading("Argument Signature");
                        ui.separator();
                        
                        if !report.argument_signature.signature.is_empty() {
                            egui::Grid::new("signature_grid")
                                .num_columns(2)
                                .spacing([40.0, 6.0])
                                .show(ui, |ui| {
                                    ui.label(RichText::new("Signature:").color(Colors::TEXT_SECONDARY));
                                    ui.label(RichText::new(&report.argument_signature.signature)
                                        .monospace()
                                        .color(Colors::RED_ACCENT)
                                        .size(16.0));
                                    ui.end_row();
                                    
                                    ui.label(RichText::new("Confidence:").color(Colors::TEXT_SECONDARY));
                                    let conf_percent = (report.argument_signature.confidence * 100.0) as u8;
                                    let conf_color = if conf_percent >= 70 { Colors::GREEN_SUCCESS }
                                        else if conf_percent >= 40 { Colors::YELLOW_WARNING }
                                        else { Colors::TEXT_SECONDARY };
                                    ui.label(RichText::new(format!("{}%", conf_percent)).color(conf_color));
                                    ui.end_row();
                                    
                                    ui.label(RichText::new("Method:").color(Colors::TEXT_SECONDARY));
                                    let method_text = match report.argument_signature.method {
                                        crate::core::analyzer::signatures::DetectionMethod::Disassembly => "Disassembly Analysis",
                                        crate::core::analyzer::signatures::DetectionMethod::ApiPattern => "API Pattern",
                                        crate::core::analyzer::signatures::DetectionMethod::Unknown => "Unknown",
                                    };
                                    ui.label(method_text);
                                    ui.end_row();
                                });
                            
                            if !report.argument_signature.argument_types.is_empty() {
                                ui.separator();
                                ui.label(RichText::new("Arguments:").strong());
                                ui.indent("args_indent", |ui| {
                                    for arg_info in &report.argument_signature.argument_types {
                                        let type_char = match arg_info.arg_type {
                                            crate::core::executor::arguments::ArgumentType::String => "z",
                                            crate::core::executor::arguments::ArgumentType::WideString => "Z",
                                            crate::core::executor::arguments::ArgumentType::Int32 => "i",
                                            crate::core::executor::arguments::ArgumentType::Int16 => "s",
                                            crate::core::executor::arguments::ArgumentType::Binary => "b",
                                        };
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(format!("[{}]", arg_info.position))
                                                .color(Colors::TEXT_SECONDARY)
                                                .monospace());
                                            ui.label(RichText::new(type_char)
                                                .monospace()
                                                .color(Colors::RED_ACCENT)
                                                .strong());
                                            ui.label(RichText::new(":").color(Colors::TEXT_SECONDARY));
                                            ui.label(RichText::new(&arg_info.description)
                                                .color(Colors::TEXT_SECONDARY)
                                                .small());
                                        });
                                    }
                                });
                            }
                            
                            if !report.argument_signature.notes.is_empty() {
                                ui.separator();
                                ui.label(RichText::new("Notes:").strong().small());
                                ui.indent("notes_indent", |ui| {
                                    for note in &report.argument_signature.notes {
                                        ui.label(RichText::new(note).small().color(Colors::TEXT_SECONDARY));
                                    }
                                });
                            }
                        } else {
                            ui.label(RichText::new("No signature detected").color(Colors::TEXT_SECONDARY).italics());
                        }
                    });
                    
                    ui.add_space(10.0);
                    
                    // Enhanced OpSec Findings Summary (if available)
                    if let Some(opsec) = &self.opsec_analysis {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.heading("OpSec Findings");
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    // Use ASCII-only label to avoid missing glyphs on some platforms
                                    if ui.button("View Details >>").clicked() {
                                        self.active_tab = ActiveTab::OpSec;
                                    }
                                });
                            });
                            ui.separator();
                            
                            // Summary counts
                            let critical_count = opsec.api_classifications.iter()
                                .filter(|(_, info)| info.category == crate::core::analyzer::opsec::OpsecCategory::CriticalRisk).count();
                            let high_count = opsec.api_classifications.iter()
                                .filter(|(_, info)| info.category == crate::core::analyzer::opsec::OpsecCategory::HighRisk).count();
                            let combo_count = opsec.risky_combinations.len();
                            let pattern_count = opsec.suspicious_patterns.len();
                            
                            egui::Grid::new("opsec_summary_grid")
                                .num_columns(2)
                                .spacing([40.0, 6.0])
                                .show(ui, |ui| {
                                    ui.label(RichText::new("OpSec Score:").color(Colors::TEXT_SECONDARY));
                                    let score = opsec.opsec_score;
                                    let color = if score >= 70 { Colors::GREEN_SUCCESS }
                                        else if score >= 40 { Colors::YELLOW_WARNING }
                                        else { Colors::RED_LIGHT };
                                    ui.label(RichText::new(format!("{}/100", score)).color(color).strong());
                                    ui.end_row();
                                    
                                    if critical_count > 0 || high_count > 0 {
                                        ui.label(RichText::new("High/Critical Issues:").color(Colors::TEXT_SECONDARY));
                                        let issue_color = if critical_count > 0 { Colors::RED_ACCENT } else { Colors::RED_LIGHT };
                                        let resp = ui.label(RichText::new(format!("{} Critical, {} High", critical_count, high_count))
                                            .color(issue_color)
                                            .underline());
                                        if resp.clicked() {
                                            self.active_tab = ActiveTab::OpSec;
                                        }
                                        ui.end_row();
                                    }
                                    
                                    if combo_count > 0 {
                                        ui.label(RichText::new("Risky Combinations:").color(Colors::TEXT_SECONDARY));
                                        let resp = ui.label(RichText::new(format!("{}", combo_count))
                                            .color(Colors::YELLOW_WARNING)
                                            .underline());
                                        if resp.clicked() {
                                            self.active_tab = ActiveTab::OpSec;
                                        }
                                        ui.end_row();
                                    }
                                    
                                    if pattern_count > 0 {
                                        ui.label(RichText::new("Suspicious Patterns:").color(Colors::TEXT_SECONDARY));
                                        let resp = ui.label(RichText::new(format!("{}", pattern_count))
                                            .color(Colors::YELLOW_WARNING)
                                            .underline());
                                        if resp.clicked() {
                                            self.active_tab = ActiveTab::OpSec;
                                        }
                                        ui.end_row();
                                    }
                                });
                            
                            ui.add_space(5.0);
                            ui.label(RichText::new("Click counts or 'View Details' to see full OpSec analysis")
                                .small()
                                .color(Colors::TEXT_MUTED));
                        });
                        
                        ui.add_space(10.0);
                    }
                    
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
                        
                        // Hex preview button
                        if !section.data.is_empty() {
                            if ui.button(RichText::new("► Hex Preview").color(Colors::BLUE_INFO)).clicked() {
                                self.hex_preview_section = Some(section.name.clone());
                            }
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
                // Filter controls (primarily driven by OpSec jumps)
                ui.horizontal(|ui| {
                    ui.label("Filter by function:");
                    // We render read-only view of current filter here to avoid borrowing issues;
                    // actual filtering uses self.imports_filter.
                    ui.label(
                        if self.imports_filter.is_empty() {
                            "-".to_string()
                        } else {
                            self.imports_filter.clone()
                        }
                    );
                });
                ui.add_space(8.0);

                // Win32 APIs
                ui.group(|ui| {
                    ui.heading("Win32 APIs");
                    let has_resolved = !self.last_resolved_imports.is_empty();
                    ui.horizontal(|ui| {
                        ui.label(format!("{} functions", report.apis.win32_apis.len()));
                        if has_resolved {
                            ui.label(RichText::new(" | Resolved addresses available (from last execution)")
                                .small()
                                .color(Colors::GREEN_SUCCESS));
                        }
                    });
                    ui.separator();
                    
                    egui::Grid::new("win32_apis_grid")
                        .num_columns(3)
                        .striped(true)
                        .min_col_width(150.0)
                        .show(ui, |ui| {
                            ui.label(RichText::new("DLL").strong());
                            ui.label(RichText::new("Function").strong());
                            ui.label(RichText::new("Resolved Address").strong());
                            ui.end_row();
                            
                            for api in &report.apis.win32_apis {
                                // Apply optional filter from OpSec navigation
                                if !self.imports_filter.is_empty()
                                    && !api.function.to_lowercase().contains(&self.imports_filter.to_lowercase())
                                {
                                    continue;
                                }

                                ui.label(RichText::new(&api.dll).color(Colors::TEXT_SECONDARY));
                                ui.label(RichText::new(&api.function).monospace());
                                
                                // Look up resolved address using import symbol pattern
                                let symbol_name = format!("__imp_{}${}", api.dll.to_uppercase(), api.function);
                                // Also try with original case
                                let symbol_name_orig = format!("__imp_{}${}", api.dll, api.function);
                                
                                let resolved_addr = self.last_resolved_imports.get(&symbol_name)
                                    .or_else(|| self.last_resolved_imports.get(&symbol_name_orig))
                                    .or_else(|| {
                                        // Try case-insensitive match
                                        self.last_resolved_imports.iter()
                                            .find(|(k, _)| k.to_lowercase() == symbol_name.to_lowercase())
                                            .map(|(_, v)| v)
                                    });
                                
                                if let Some(addr) = resolved_addr {
                                    ui.label(RichText::new(format!("0x{:016X}", addr))
                                        .monospace()
                                        .color(Colors::GREEN_SUCCESS));
                                } else if has_resolved {
                                    ui.label(RichText::new("-").color(Colors::TEXT_MUTED));
                                } else {
                                    ui.label(RichText::new("-").color(Colors::TEXT_MUTED));
                                }
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
                    
                    let has_resolved = !self.last_resolved_imports.is_empty();
                    egui::Grid::new("beacon_apis_grid")
                        .num_columns(2)
                        .striped(true)
                        .min_col_width(200.0)
                        .show(ui, |ui| {
                            ui.label(RichText::new("Function").strong());
                            ui.label(RichText::new("Resolved Address").strong());
                            ui.end_row();
                            
                            for api in &report.apis.beacon_apis {
                                ui.label(RichText::new(api).monospace().color(Colors::BLUE_INFO));
                                
                                // Look up resolved address
                                let symbol_name = format!("__imp_{}", api);
                                let resolved_addr = self.last_resolved_imports.get(&symbol_name);
                                
                                if let Some(addr) = resolved_addr {
                                    ui.label(RichText::new(format!("0x{:016X}", addr))
                                        .monospace()
                                        .color(Colors::GREEN_SUCCESS));
                                } else if has_resolved {
                                    ui.label(RichText::new("-").color(Colors::TEXT_MUTED));
                                } else {
                                    ui.label(RichText::new("-").color(Colors::TEXT_MUTED));
                                }
                                ui.end_row();
                            }
                        });
                });
            });
        } else {
            ui.label("No analysis report available");
        }
    }

    /// Render OpSec tab
    fn render_opsec_tab(&mut self, ui: &mut egui::Ui) {
        use super::app_opsec::{render_opsec_tab, NavigationRequest};
        use egui::ComboBox;

        // Profile selection UI
        ui.horizontal(|ui| {
            ui.label(RichText::new("Scoring Profile:").strong());
            ComboBox::new("opsec_profile", "")
                .selected_text(&self.opsec_selected_profile)
                .show_ui(ui, |ui| {
                    for profile_name in self.opsec_profile_manager.list_profiles() {
                        if ui.selectable_value(
                            &mut self.opsec_selected_profile,
                            profile_name.clone(),
                            &profile_name,
                        ).changed() {
                            // Re-run analysis with new profile if BOF is loaded
                            if let Some(bof) = &self.bof_file {
                                use crate::core::analyzer::opsec::analyze_api_opsec_with_bof;
                                let profile = self.opsec_profile_manager.get_profile(&self.opsec_selected_profile)
                                    .or_else(|| self.opsec_profile_manager.get_profile("default"));
                                self.opsec_analysis = Some(analyze_api_opsec_with_bof(&bof.imports, Some(bof), profile));
                            }
                        }
                    }
                });
            
            if let Some(profile) = self.opsec_profile_manager.get_profile(&self.opsec_selected_profile) {
                ui.label(RichText::new(format!("({})", profile.description)).small().color(Colors::TEXT_SECONDARY));
            }
        });
        ui.separator();

        let mut nav_request: Option<NavigationRequest> = None;

        render_opsec_tab(
            ui,
            self.opsec_analysis.as_ref(),
            self.compatibility_analysis.as_ref(),
            self.calling_convention_analysis.as_ref(),
            &mut self.opsec_api_filter,
            &mut self.opsec_risk_filter,
            &mut self.opsec_compat_severity_filter,
            &mut self.opsec_show_all_severities,
            &mut self.opsec_sort_column,
            &mut self.opsec_sort_ascending,
            &mut self.opsec_filter_preset,
            &mut nav_request,
        );
        
        // Apply navigation after render_opsec_tab returns
        if let Some(request) = nav_request {
            if request.target == "export_opsec" {
                // Export OpSec findings
                self.export_opsec_findings();
            } else if request.address.is_some() || request.target.contains("!") || request.target.starts_with("__imp_") {
                // Navigate to Disassembly tab - find the actual call address from disassembly
                self.active_tab = ActiveTab::Disassembly;
                
                // Try to find the API call address in disassembly
                let mut found_addr: Option<u64> = None;
                if let Some(report) = &self.analysis_report {
                    // Extract API name from target (could be "LIBRARY!Function" or just "Function")
                    let api_search = if request.target.contains("!") {
                        request.target.clone()
                    } else if request.target.starts_with("__imp_") {
                        // Convert __imp_LIBRARY$Function to LIBRARY!Function
                        request.target.trim_start_matches("__imp_").replace("$", "!")
                    } else {
                        request.target.clone()
                    };
                    
                    // Search in disassembly API calls
                    for disasm in &report.disassembly {
                        for api_call in &disasm.api_calls {
                            if api_call.target == api_search || api_call.target.ends_with(&format!("!{}", request.target)) {
                                found_addr = Some(api_call.address);
                                break;
                            }
                        }
                        if found_addr.is_some() { break; }
                    }
                }
                
                // Use found address, or fallback to provided address (even if 0)
                self.disasm_highlight_address = found_addr.or(request.address);
            } else {
                // Navigate to Imports tab with API name filter
                self.active_tab = ActiveTab::Imports;
                self.imports_filter = request.target;
            }
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
    fn render_disassembly_tab(&mut self, ui: &mut egui::Ui) {
        if let Some(report) = &self.analysis_report {
            // Build a set of API call addresses for quick lookup
            let mut api_call_addresses: std::collections::HashSet<u64> = std::collections::HashSet::new();
            for disasm_result in &report.disassembly {
                for api_call in &disasm_result.api_calls {
                    api_call_addresses.insert(api_call.address);
                }
            }
            
            let highlight_addr = self.disasm_highlight_address;
            let mut should_clear_highlight = false;
            
            egui::ScrollArea::vertical().show(ui, |ui| {
                if report.disassembly.is_empty() {
                    ui.label("No disassembly available");
                } else {
                    // Show highlight info banner if navigated from OpSec
                    if let Some(addr) = highlight_addr {
                        ui.horizontal(|ui| {
                            if addr == 0 {
                                ui.label(RichText::new("⚠ API call not found in disassembly - API may be imported but not called")
                                    .color(Colors::YELLOW_WARNING));
                            } else {
                                ui.label(RichText::new(format!("📍 Navigated to address: 0x{:08X}", addr))
                                    .color(Colors::YELLOW_WARNING)
                                    .strong());
                            }
                            if ui.small_button("✕ Clear").clicked() {
                                should_clear_highlight = true;
                            }
                        });
                        ui.separator();
                    }
                    
                    for disasm_result in &report.disassembly {
                        ui.group(|ui| {
                            ui.heading(format!("Section: {}", disasm_result.section_name));
                            ui.horizontal(|ui| {
                                ui.label(format!("{} instructions | {} functions detected", 
                                    disasm_result.stats.total_instructions,
                                    disasm_result.functions.len()));
                                ui.label(RichText::new(format!(" | {} API calls", disasm_result.api_calls.len()))
                                    .color(Colors::CYAN_ACCENT));
                            });
                            ui.separator();
                            
                            // Show resolved base address if available
                            if let Some(base) = self.last_code_base_address {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("📍 Resolved base address:").color(Colors::TEXT_SECONDARY));
                                    ui.label(RichText::new(format!("0x{:016X}", base))
                                        .monospace()
                                        .color(Colors::CYAN_ACCENT));
                                });
                                ui.separator();
                            }
                            
                            egui::Grid::new(format!("disasm_grid_{}", disasm_result.section_name))
                                .num_columns(4)
                                .striped(true)
                                .min_col_width(80.0)
                                .show(ui, |ui| {
                                    let header = if self.last_code_base_address.is_some() {
                                        "Address (Relative → Resolved)"
                                    } else {
                                        "Address"
                                    };
                                    ui.label(RichText::new(header).strong());
                                    ui.label(RichText::new("Bytes").strong());
                                    ui.label(RichText::new("Instruction").strong());
                                    ui.label(RichText::new("Annotations").strong());
                                    ui.end_row();
                                    
                                    for instr in &disasm_result.instructions {
                                        let is_highlighted = highlight_addr == Some(instr.address);
                                        let is_api_call = api_call_addresses.contains(&instr.address);
                                        
                                        // Highlight background for navigated address
                                        let row_bg = if is_highlighted {
                                            Some(egui::Color32::from_rgba_unmultiplied(255, 200, 0, 60))
                                        } else if is_api_call {
                                            Some(egui::Color32::from_rgba_unmultiplied(0, 200, 255, 25))
                                        } else {
                                            None
                                        };
                                        
                                        // Address column - show both relative and resolved if base available
                                        let addr_str = if let Some(base) = self.last_code_base_address {
                                            let resolved = base + instr.address;
                                            format!("0x{:08x} → 0x{:016X}", instr.address, resolved)
                                        } else {
                                            format!("0x{:08x}", instr.address)
                                        };
                                        let addr_text = RichText::new(addr_str).monospace();
                                        let addr_text = if is_highlighted {
                                            addr_text.strong().color(Colors::YELLOW_WARNING)
                                        } else if is_api_call {
                                            addr_text.color(Colors::CYAN_ACCENT)
                                        } else {
                                            addr_text
                                        };
                                        
                                        if let Some(bg) = row_bg {
                                            ui.scope(|ui| {
                                                let rect = ui.available_rect_before_wrap();
                                                ui.painter().rect_filled(rect, 0.0, bg);
                                                ui.label(addr_text);
                                            });
                                        } else {
                                            ui.label(addr_text);
                                        }
                                        
                                        // Scroll to highlighted address
                                        if is_highlighted {
                                            ui.scroll_to_cursor(Some(egui::Align::Center));
                                        }
                                        
                                        let bytes_str: String = instr.bytes.iter()
                                            .map(|b| format!("{:02x}", b))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        ui.label(RichText::new(bytes_str).monospace().color(Colors::TEXT_SECONDARY));
                                        
                                        // Color code instructions
                                        let color = if is_api_call {
                                            Colors::CYAN_ACCENT
                                        } else if instr.is_call {
                                            Colors::BLUE_INFO
                                        } else if instr.is_jump {
                                            Colors::YELLOW_WARNING
                                        } else if instr.is_return {
                                            Colors::RED_LIGHT
                                        } else {
                                            Colors::TEXT_PRIMARY
                                        };
                                        
                                        let instr_text = RichText::new(&instr.text).monospace().color(color);
                                        let instr_text = if is_api_call { instr_text.strong() } else { instr_text };
                                        ui.label(instr_text);
                                        
                                        // Build annotation string
                                        let mut annotations = Vec::new();
                                        
                                        // Check for function name at this address
                                        if let Some(func) = disasm_result.functions.iter()
                                            .find(|f| f.start_address == instr.address) {
                                            if let Some(ref name) = func.name {
                                                annotations.push(format!("func: {}", name));
                                            }
                                        }
                                        
                                        // Check for API call at this address - make it prominent
                                        if let Some(api_call) = disasm_result.api_calls.iter()
                                            .find(|api| api.address == instr.address) {
                                            // Try to find resolved address for this API
                                            let resolved_addr = self.last_resolved_imports.iter()
                                                .find(|(k, _)| {
                                                    // Match __imp_LIBRARY$Function to LIBRARY!Function
                                                    let normalized = k.trim_start_matches("__imp_").replace("$", "!");
                                                    normalized.eq_ignore_ascii_case(&api_call.target)
                                                })
                                                .map(|(_, v)| *v);
                                            
                                            if let Some(addr) = resolved_addr {
                                                annotations.push(format!("⚡ API: {} → 0x{:X}", api_call.target, addr));
                                            } else {
                                                annotations.push(format!("⚡ API: {}", api_call.target));
                                            }
                                        }
                                        
                                        // Add comment if present
                                        if let Some(ref comment) = instr.comment {
                                            annotations.push(comment.clone());
                                        }
                                        
                                        // Display annotations
                                        let annotation_text = if annotations.is_empty() {
                                            String::new()
                                        } else {
                                            annotations.join(" | ")
                                        };
                                        
                                        if !annotation_text.is_empty() {
                                            let ann_color = if is_api_call { Colors::CYAN_ACCENT } else { Colors::TEXT_SECONDARY };
                                            ui.label(RichText::new(annotation_text)
                                                .monospace()
                                                .small()
                                                .color(ann_color));
                                        } else {
                                            ui.label("");
                                        }
                                        
                                        ui.end_row();
                                    }
                                });
                        });
                        ui.add_space(10.0);
                    }
                }
            });
            
            if should_clear_highlight {
                self.disasm_highlight_address = None;
            }
        } else {
            ui.label("No analysis report available");
        }
    }

    /// Render stack analysis tab
    fn render_stack_analysis_tab(&self, ui: &mut egui::Ui) {
        if let Some(report) = &self.analysis_report {
            if let Some(stack_analysis) = &report.stack_analysis {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    // Statistics summary
                    ui.group(|ui| {
                        ui.heading("Stack Usage Statistics");
                        ui.separator();
                        
                        egui::Grid::new("stack_stats")
                            .num_columns(2)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.label(RichText::new("Functions Analyzed:").strong());
                                ui.label(format!("{}", stack_analysis.stats.functions_analyzed));
                                ui.end_row();
                                
                                ui.label(RichText::new("Average Stack Usage:").strong());
                                ui.label(format!("{:.2} bytes", stack_analysis.stats.average_stack_usage));
                                ui.end_row();
                                
                                ui.label(RichText::new("Maximum Stack Usage:").strong());
                                ui.label(format!("{} bytes", stack_analysis.stats.max_stack_usage));
                                ui.end_row();
                                
                                ui.label(RichText::new("High Usage Functions (>1KB):").strong());
                                ui.label(format!("{}", stack_analysis.stats.high_usage_functions));
                                ui.end_row();
                                
                                ui.label(RichText::new("Very High Usage (>4KB):").strong());
                                let color = if stack_analysis.stats.very_high_usage_functions > 0 {
                                    Colors::RED_LIGHT
                                } else {
                                    Colors::GREEN_SUCCESS
                                };
                                ui.label(RichText::new(format!("{}", stack_analysis.stats.very_high_usage_functions))
                                    .color(color));
                                ui.end_row();
                                
                                ui.label(RichText::new("Overflow Risk Functions:").strong());
                                let risk_color = if stack_analysis.stats.overflow_risk_functions > 0 {
                                    Colors::RED_LIGHT
                                } else {
                                    Colors::GREEN_SUCCESS
                                };
                                ui.label(RichText::new(format!("{}", stack_analysis.stats.overflow_risk_functions))
                                    .color(risk_color));
                                ui.end_row();
                            });
                    });
                    
                    ui.add_space(10.0);
                    
                    // Warnings section
                    if !stack_analysis.warnings.is_empty() {
                        ui.group(|ui| {
                            ui.heading(RichText::new("Stack Usage Warnings").color(Colors::YELLOW_WARNING));
                            ui.separator();
                            
                            for warning in &stack_analysis.warnings {
                                let (icon, color) = match warning.severity {
                                    crate::core::analyzer::stack_analysis::StackWarningSeverity::Error => 
                                        ("[!]", Colors::RED_LIGHT),
                                    crate::core::analyzer::stack_analysis::StackWarningSeverity::Warning => 
                                        ("[*]", Colors::YELLOW_WARNING),
                                    crate::core::analyzer::stack_analysis::StackWarningSeverity::Info => 
                                        ("[i]", Colors::BLUE_INFO),
                                };
                                
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(icon).color(color));
                                    if let Some(ref func_name) = warning.function_name {
                                        ui.label(RichText::new(func_name).strong().monospace());
                                    }
                                    ui.label(RichText::new(format!("({} bytes)", warning.stack_usage))
                                        .color(color));
                                });
                                ui.label(&warning.message);
                                ui.label(RichText::new(format!("Address: 0x{:08X}", warning.address))
                                    .monospace()
                                    .color(Colors::TEXT_SECONDARY));
                                ui.add_space(5.0);
                            }
                        });
                        ui.add_space(10.0);
                    }
                    
                    // Function stack usage table
                    if !stack_analysis.function_stack_usage.is_empty() {
                        ui.group(|ui| {
                            ui.heading("Function Stack Usage");
                            ui.separator();
                            
                            egui::Grid::new("stack_usage_table")
                                .num_columns(5)
                                .striped(true)
                                .min_col_width(100.0)
                                .show(ui, |ui| {
                                    ui.label(RichText::new("Function").strong());
                                    ui.label(RichText::new("Address").strong());
                                    ui.label(RichText::new("Stack Size").strong());
                                    ui.label(RichText::new("Max Usage").strong());
                                    ui.label(RichText::new("Risk").strong());
                                    ui.end_row();
                                    
                                    for func in &stack_analysis.function_stack_usage {
                                        let func_name = func.function_name.as_deref()
                                            .unwrap_or("<unknown>");
                                        ui.label(RichText::new(func_name).monospace());
                                        ui.label(RichText::new(format!("0x{:08X}", func.start_address))
                                            .monospace()
                                            .color(Colors::TEXT_SECONDARY));
                                        
                                        // Stack size with color coding
                                        let size_color = if func.estimated_stack_size > 4096 {
                                            Colors::RED_LIGHT
                                        } else if func.estimated_stack_size > 1024 {
                                            Colors::YELLOW_WARNING
                                        } else {
                                            Colors::GREEN_SUCCESS
                                        };
                                        ui.label(RichText::new(format!("{} bytes", func.estimated_stack_size))
                                            .color(size_color));
                                        
                                        ui.label(format!("{} bytes", func.max_stack_usage));
                                        
                                        // Risk level
                                        let (risk_text, risk_color) = match func.risk_level {
                                            crate::core::analyzer::stack_analysis::StackRiskLevel::Critical => 
                                                ("CRITICAL", Colors::RED_LIGHT),
                                            crate::core::analyzer::stack_analysis::StackRiskLevel::High => 
                                                ("HIGH", Colors::YELLOW_WARNING),
                                            crate::core::analyzer::stack_analysis::StackRiskLevel::Medium => 
                                                ("MEDIUM", Colors::YELLOW_WARNING),
                                            crate::core::analyzer::stack_analysis::StackRiskLevel::Low => 
                                                ("LOW", Colors::GREEN_SUCCESS),
                                        };
                                        ui.label(RichText::new(risk_text).color(risk_color));
                                        ui.end_row();
                                    }
                                });
                        });
                        
                        ui.add_space(10.0);
                        
                        // Stack operations detail (collapsible)
                        for func in &stack_analysis.function_stack_usage {
                            let func_name = func.function_name.as_deref()
                                .unwrap_or("<unknown>");
                            
                            ui.collapsing(format!("{} - Stack Operations", func_name), |ui| {
                                if func.stack_operations.is_empty() {
                                    ui.label(RichText::new("No stack operations detected")
                                        .color(Colors::TEXT_SECONDARY));
                                } else {
                                    egui::Grid::new(format!("stack_ops_{}", func.start_address))
                                        .num_columns(4)
                                        .striped(true)
                                        .show(ui, |ui| {
                                            ui.label(RichText::new("Address").strong());
                                            ui.label(RichText::new("Instruction").strong());
                                            ui.label(RichText::new("Delta").strong());
                                            ui.label(RichText::new("Stack Usage").strong());
                                            ui.end_row();
                                            
                                            for op in &func.stack_operations {
                                                ui.label(RichText::new(format!("0x{:08X}", op.address))
                                                    .monospace()
                                                    .color(Colors::TEXT_SECONDARY));
                                                ui.label(RichText::new(&op.instruction).monospace());
                                                
                                                let delta_color = if op.stack_delta > 0 {
                                                    Colors::YELLOW_WARNING
                                                } else {
                                                    Colors::GREEN_SUCCESS
                                                };
                                                ui.label(RichText::new(format!("{:+}", op.stack_delta))
                                                    .color(delta_color));
                                                
                                                ui.label(format!("{} bytes", op.current_stack_usage));
                                                ui.end_row();
                                            }
                                        });
                                }
                            });
                        }
                    }
                });
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(50.0);
                    ui.label(RichText::new("Stack analysis requires disassembly to be enabled")
                        .size(16.0)
                        .color(Colors::TEXT_SECONDARY));
                    ui.label(RichText::new("Enable disassembly in analysis options to see stack usage information")
                        .color(Colors::TEXT_SECONDARY));
                });
            }
        } else {
            ui.label("No analysis report available");
        }
    }
    
    /// Render YARA analysis tab
    fn render_yara_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // Make the entire YARA tab scrollable so large rule sets and details remain accessible
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
        // YARA Rule Loading Section
        ui.group(|ui| {
            ui.heading("YARA Rule Management");
            ui.separator();
            
            ui.horizontal(|ui| {
                if ui.button("Load Rule File").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("YARA Rules", &["yar", "yara"])
                        .pick_file()
                    {
                        if !self.yara_rule_paths.contains(&path) {
                            self.yara_rule_paths.push(path);
                            self.save_yara_rule_paths(ctx);
                            // Trigger re-analysis if BOF is loaded
                            if self.bof_file.is_some() {
                                self.run_analysis();
                            }
                        }
                    }
                }
                
                if ui.button("Load Rule Directory").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        if !self.yara_rule_paths.contains(&path) {
                            self.yara_rule_paths.push(path);
                            self.save_yara_rule_paths(ctx);
                            // Trigger re-analysis if BOF is loaded
                            if self.bof_file.is_some() {
                                self.run_analysis();
                            }
                        }
                    }
                }
                
                if !self.yara_rule_paths.is_empty() {
                    if ui.button("Clear All Rules").clicked() {
                        self.yara_rule_paths.clear();
                        self.save_yara_rule_paths(ctx);
                        // Trigger re-analysis if BOF is loaded
                        if self.bof_file.is_some() {
                            self.run_analysis();
                        }
                    }
                }
            });
            
            if !self.yara_rule_paths.is_empty() {
                ui.add_space(5.0);
                ui.label(RichText::new("Loaded Rules:").strong());
                let mut to_remove = None;
                for (idx, path) in self.yara_rule_paths.iter().enumerate() {
                    ui.horizontal(|ui| {
                        let is_dir = path.is_dir();
                        let prefix = if is_dir { 
                            RichText::new("[DIR]").color(Colors::BLUE_INFO).monospace()
                        } else { 
                            RichText::new("[FILE]").color(Colors::TEXT_SECONDARY).monospace()
                        };
                        ui.label(prefix);
                        ui.label(path.display().to_string());
                        if ui.small_button("×").clicked() {
                            to_remove = Some(idx);
                        }
                    });
                }
                if let Some(idx) = to_remove {
                    self.yara_rule_paths.remove(idx);
                    self.save_yara_rule_paths(ctx);
                    // Trigger re-analysis if BOF is loaded
                    if self.bof_file.is_some() {
                        self.run_analysis();
                    }
                }
            } else {
                ui.label(RichText::new("No custom rules loaded (using default rules)")
                    .color(Colors::TEXT_SECONDARY)
                    .italics());
            }
            
            // Persistent YARA Rules Folder
            ui.add_space(5.0);
            ui.separator();
            ui.add_space(5.0);
            ui.label(RichText::new("Persistent Rules Folder:").strong());
            ui.horizontal(|ui| {
                if let Some(ref folder) = self.yara_persistent_folder {
                    ui.label(RichText::new("[DIR]").color(Colors::BLUE_INFO).monospace());
                    ui.label(folder.display().to_string());
                    if ui.small_button("×").clicked() {
                        self.yara_persistent_folder = None;
                        self.save_yara_rule_paths(ctx);
                        // Trigger re-analysis if BOF is loaded
                        if self.bof_file.is_some() {
                            self.run_analysis();
                        }
                    }
                } else {
                    ui.label(RichText::new("No persistent folder set")
                        .color(Colors::TEXT_SECONDARY)
                        .italics());
                }
                if ui.button("Select Folder").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        self.yara_persistent_folder = Some(path);
                        self.save_yara_rule_paths(ctx);
                        // Trigger re-analysis if BOF is loaded
                        if self.bof_file.is_some() {
                            self.run_analysis();
                        }
                    }
                }
            });
            if self.yara_persistent_folder.is_some() {
                ui.label(RichText::new("Rules from this folder are automatically loaded on startup")
                    .color(Colors::TEXT_SECONDARY)
                    .italics()
                    .small());
            }
            
            // Checkbox to use default rules with custom rules
            if !self.yara_rule_paths.is_empty() || self.yara_persistent_folder.is_some() {
                ui.add_space(5.0);
                ui.separator();
                ui.add_space(5.0);
                if ui.checkbox(&mut self.yara_use_default_rules, "Use default BOF rules together with custom rules").changed() {
                    self.save_yara_rule_paths(ctx);
                    // Trigger re-analysis if BOF is loaded
                    if self.bof_file.is_some() {
                        self.run_analysis();
                    }
                }
            }
        });
        
        ui.add_space(10.0);
        
        // Rule Management UI
        self.render_rule_management_ui(ui, ctx);
        
        ui.add_space(10.0);
        
        if let Some(report) = &self.analysis_report {
            if let Some(yara_analysis) = &report.yara_analysis {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    // Engine availability status
                    if !yara_analysis.engine_available {
                        ui.group(|ui| {
                            ui.heading(RichText::new("YARA Engine Status").color(Colors::YELLOW_WARNING));
                            ui.separator();
                            ui.label("YARA engine is not available.");
                            ui.label("This may be because:");
                            ui.label("• YARA feature is not enabled (build with --features yara)");
                            ui.label("• YARA library failed to initialize");
                            ui.label("• YARA dependencies are not installed");
                            ui.add_space(10.0);
                            ui.label(RichText::new("To enable YARA scanning:").strong());
                            ui.label("1. Build with YARA feature: cargo build --features yara");
                            ui.label("2. The vendored feature will automatically build YARA from source");
                            ui.label("3. YARA rules will be automatically loaded and scanned");
                        });
                        ui.add_space(10.0);
                    } else {
                        // Show success message if engine is available
                        ui.group(|ui| {
                            ui.heading(RichText::new("YARA Engine Status").color(Colors::GREEN_SUCCESS));
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("YARA engine is active and ready").color(Colors::GREEN_SUCCESS));
                            });
                            ui.label(format!("{} rules loaded, {} sections scanned", 
                                yara_analysis.stats.rules_loaded,
                                yara_analysis.stats.sections_scanned));
                        });
                        ui.add_space(10.0);
                        
                        // Show compilation errors if any
                        if let Some(ref errors) = yara_analysis.compilation_errors {
                            if !errors.is_empty() {
                                ui.group(|ui| {
                                    ui.heading(RichText::new("YARA Compilation Errors").color(Colors::RED_LIGHT));
                                    ui.separator();
                                    for error in errors {
                                        ui.label(RichText::new(error).color(Colors::RED_LIGHT).monospace());
                                    }
                                });
                                ui.add_space(10.0);
                            }
                        }
                    }
                    
                    // Statistics
                    ui.group(|ui| {
                        ui.heading("YARA Analysis Statistics");
                        ui.separator();
                        
                        egui::Grid::new("yara_stats")
                            .num_columns(2)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.label(RichText::new("Rules Loaded:").strong());
                                ui.label(format!("{}", yara_analysis.stats.rules_loaded));
                                ui.end_row();
                                
                                ui.label(RichText::new("Total Matches:").strong());
                                let match_color = if yara_analysis.stats.total_matches > 0 {
                                    Colors::YELLOW_WARNING
                                } else {
                                    Colors::GREEN_SUCCESS
                                };
                                ui.label(RichText::new(format!("{}", yara_analysis.stats.total_matches))
                                    .color(match_color));
                                ui.end_row();
                                
                                ui.label(RichText::new("Unique Rules Matched:").strong());
                                ui.label(format!("{}", yara_analysis.stats.unique_rules_matched));
                                ui.end_row();
                                
                                ui.label(RichText::new("Sections Scanned:").strong());
                                ui.label(format!("{}", yara_analysis.stats.sections_scanned));
                                ui.end_row();
                            });
                    });
                    
                    ui.add_space(10.0);
                    
                    // Matches section
                    if !yara_analysis.matches.is_empty() {
                        ui.group(|ui| {
                            ui.heading(RichText::new("YARA Rule Matches").color(Colors::YELLOW_WARNING));
                            ui.separator();
                            
                            for (idx, match_item) in yara_analysis.matches.iter().enumerate() {
                                ui.collapsing(format!("{} - {}", match_item.rule_name, 
                                    match_item.namespace.as_deref().unwrap_or("default")), |ui| {
                                    egui::Grid::new(format!("yara_match_{}", idx))
                                        .num_columns(2)
                                        .striped(true)
                                        .show(ui, |ui| {
                                            ui.label(RichText::new("Rule Name:").strong());
                                            ui.label(RichText::new(&match_item.rule_name).monospace());
                                            ui.end_row();
                                            
                                            if let Some(ref ns) = match_item.namespace {
                                                ui.label(RichText::new("Namespace:").strong());
                                                ui.label(ns);
                                                ui.end_row();
                                            }
                                            
                                            ui.label(RichText::new("Section:").strong());
                                            ui.label(&match_item.section);
                                            ui.end_row();
                                            
                                            ui.label(RichText::new("Offset:").strong());
                                            ui.label(RichText::new(format!("0x{:08X}", match_item.offset))
                                                .monospace());
                                            ui.end_row();
                                            
                                            ui.label(RichText::new("Length:").strong());
                                            ui.label(format!("{} bytes", match_item.length));
                                            ui.end_row();
                                            
                                            if let Some(ref severity) = match_item.severity {
                                                ui.label(RichText::new("Severity:").strong());
                                                let severity_color = match severity.as_str() {
                                                    "critical" | "high" => Colors::RED_LIGHT,
                                                    "medium" => Colors::YELLOW_WARNING,
                                                    _ => Colors::BLUE_INFO,
                                                };
                                                ui.label(RichText::new(severity.to_uppercase())
                                                    .color(severity_color));
                                                ui.end_row();
                                            }
                                        });
                                    
                                    // Matched strings
                                    if !match_item.matched_strings.is_empty() {
                                        ui.add_space(5.0);
                                        ui.label(RichText::new("Matched Strings:").strong());
                                        for matched_str in &match_item.matched_strings {
                                            ui.horizontal(|ui| {
                                                ui.label(RichText::new(&matched_str.identifier)
                                                    .monospace()
                                                    .color(Colors::BLUE_INFO));
                                                ui.label("->");
                                                ui.label(RichText::new(format!("0x{:08X}", matched_str.offset))
                                                    .monospace());
                                                ui.label(RichText::new(&matched_str.data)
                                                    .monospace()
                                                    .color(Colors::TEXT_SECONDARY));
                                            });
                                        }
                                    }
                                    
                                    // Metadata
                                    if !match_item.metadata.is_empty() {
                                        ui.add_space(5.0);
                                        ui.label(RichText::new("Rule Metadata:").strong());
                                        for (key, value) in &match_item.metadata {
                                            ui.horizontal(|ui| {
                                                ui.label(RichText::new(key).strong());
                                                ui.label(value);
                                            });
                                        }
                                    }
                                });
                                ui.add_space(5.0);
                            }
                        });
                    } else if yara_analysis.engine_available {
                        ui.vertical_centered(|ui| {
                            ui.add_space(50.0);
                            ui.label(RichText::new("No YARA rule matches found").size(18.0)
                                .color(Colors::GREEN_SUCCESS));
                        });
                    }
                    
                    // Default rules info - only show if default rules are being used
                    if self.yara_use_default_rules || self.yara_rule_paths.is_empty() {
                        ui.add_space(10.0);
                        ui.collapsing("Default BOF YARA Rules", |ui| {
                            ui.label("The following default YARA rules are available:");
                            ui.label("• BOF_BeaconAPI - Detects Beacon API usage");
                            ui.label("• BOF_ProcessInjection - Detects process injection patterns");
                            ui.label("• BOF_TokenManipulation - Detects token manipulation APIs");
                            ui.label("• BOF_NetworkActivity - Detects network-related APIs");
                            ui.label("• BOF_AntiDebug - Detects anti-debugging techniques");
                            ui.label("• BOF_StringObfuscation - Detects potential string obfuscation");
                            ui.add_space(5.0);
                            ui.label(RichText::new("Note: Use create_default_bof_rules() to generate rule file")
                                .color(Colors::TEXT_SECONDARY)
                                .italics());
                        });
                    }
                });
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(50.0);
                    ui.label(RichText::new("YARA analysis requires disassembly to be enabled")
                        .size(16.0)
                        .color(Colors::TEXT_SECONDARY));
                    ui.label(RichText::new("Enable disassembly in analysis options to see YARA matches")
                        .color(Colors::TEXT_SECONDARY));
                });
            }
        } else {
            ui.label("No analysis report available");
        }

        // Close outer YARA tab scroll area
        });
    }

    /// Render rule management UI
    fn render_rule_management_ui(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        // Update rule manager from YARA analysis if available (before UI to avoid borrow issues)
        #[cfg(feature = "yara")]
        {
            if let Some(report) = &self.analysis_report {
                if let Some(yara_analysis) = &report.yara_analysis {
                    if yara_analysis.engine_available {
                        // Extract rule info from compiled rules
                        // This would need access to the compiled Rules object
                        // For now, we'll extract from matches
                        for match_item in &yara_analysis.matches {
                            if self.yara_rule_manager.get_rule(&match_item.rule_name).is_none() {
                                let rule_info = crate::core::analyzer::yara_rules::RuleInfo {
                                    name: match_item.rule_name.clone(),
                                    namespace: match_item.namespace.clone(),
                                    category: match_item.metadata.get("category").cloned(),
                                    tags: match_item.metadata.get("tags")
                                        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                                        .unwrap_or_default(),
                                    description: match_item.metadata.get("description").cloned(),
                                    severity: match_item.severity.clone(),
                                    source_file: None,
                                    enabled: true,
                                    metrics: crate::core::analyzer::yara_rules::RuleMetrics::new(),
                                    content: None,
                                };
                                self.yara_rule_manager.add_rule(rule_info);
                            }
                        }
                    }
                }
            }
        }
        
        // Extract rule data before closures to avoid borrow issues
        let selected_rule_data = if let Some(ref selected_rule_name) = self.rule_mgmt_selected_rule {
            self.yara_rule_manager.get_rule(selected_rule_name).cloned()
        } else {
            None
        };
        
        ui.group(|ui| {
            ui.heading("Rule Browser & Management");
            ui.separator();
            
            // Filter controls
            ui.horizontal(|ui| {
                ui.label("Search:");
                ui.text_edit_singleline(&mut self.rule_mgmt_search_filter);
                self.yara_rule_manager.set_search_filter(self.rule_mgmt_search_filter.clone());
                
                ui.separator();
                
                ui.label("Category:");
                let categories = self.yara_rule_manager.get_all_categories();
                egui::ComboBox::new(egui::Id::new("rule_category_filter"), "Category")
                    .selected_text(self.rule_mgmt_selected_category.as_ref().map(|s| s.as_str()).unwrap_or("All"))
                    .show_ui(ui, |ui| {
                        if ui.selectable_label(self.rule_mgmt_selected_category.is_none(), "All").clicked() {
                            self.rule_mgmt_selected_category = None;
                            self.yara_rule_manager.set_category_filter(None);
                        }
                        for cat in &categories {
                            if ui.selectable_label(
                                self.rule_mgmt_selected_category.as_ref().map(|s| s == cat).unwrap_or(false),
                                cat
                            ).clicked() {
                                self.rule_mgmt_selected_category = Some(cat.clone());
                                self.yara_rule_manager.set_category_filter(Some(cat.clone()));
                            }
                        }
                    });
                
                ui.separator();
                
                ui.checkbox(&mut self.rule_mgmt_show_disabled, "Show Disabled");
                ui.checkbox(&mut self.rule_mgmt_show_metrics, "Show Metrics");
            });
            
            // Tag filters
            let all_tags = self.yara_rule_manager.get_all_tags();
            if !all_tags.is_empty() {
                ui.horizontal(|ui| {
                    ui.label("Filter by tags:");
                    for tag in &all_tags {
                        let is_selected = self.rule_mgmt_selected_tags.contains(tag);
                        if ui.selectable_label(is_selected, tag).clicked() {
                            if is_selected {
                                self.rule_mgmt_selected_tags.remove(tag);
                                self.yara_rule_manager.remove_tag_filter(tag);
                            } else {
                                self.rule_mgmt_selected_tags.insert(tag.clone());
                                self.yara_rule_manager.add_tag_filter(tag.clone());
                            }
                        }
                    }
                    if !self.rule_mgmt_selected_tags.is_empty() {
                        if ui.small_button("Clear Tags").clicked() {
                            self.rule_mgmt_selected_tags.clear();
                            self.yara_rule_manager.clear_tag_filters();
                        }
                    }
                });
            }
            
            ui.separator();
            ui.add_space(5.0);
            
            // Rule list - collect rules first to avoid borrow checker issues
            let filtered_rules: Vec<String> = self.yara_rule_manager.get_filtered_rules()
                .iter()
                .filter(|r| self.rule_mgmt_show_disabled || r.enabled)
                .map(|r| r.name.clone())
                .collect();
            
            if filtered_rules.is_empty() {
                ui.label(RichText::new("No rules found").color(Colors::TEXT_SECONDARY).italics());
            } else {
                ui.label(RichText::new(format!("{} rule(s)", filtered_rules.len())).strong());
                ui.add_space(5.0);
                
                egui::ScrollArea::vertical()
                    .max_height(400.0)
                    .show(ui, |ui| {
                        egui::Grid::new("rule_list")
                            .num_columns(6)
                            .striped(true)
                            .min_col_width(100.0)
                            .show(ui, |ui| {
                                // Header
                                ui.strong("Enabled");
                                ui.strong("Rule Name");
                                ui.strong("Category");
                                ui.strong("Severity");
                                ui.strong("Tags");
                                ui.strong("Actions");
                                ui.end_row();
                                
                                // Rules
                                for rule_name in &filtered_rules {
                                    let rule_enabled = self.yara_rule_manager.get_rule(rule_name)
                                        .map(|r| r.enabled)
                                        .unwrap_or(false);
                                    
                                    // Enable/disable toggle
                                    let mut enabled = rule_enabled;
                                    if ui.checkbox(&mut enabled, "").changed() {
                                        if enabled {
                                            self.yara_rule_manager.enable_rule(rule_name);
                                        } else {
                                            self.yara_rule_manager.disable_rule(rule_name);
                                        }
                                        // Trigger re-analysis if BOF is loaded
                                        if self.bof_file.is_some() {
                                            self.run_analysis();
                                        }
                                    }
                                    
                                    if let Some(rule) = self.yara_rule_manager.get_rule(rule_name) {
                                        
                                        // Rule name (clickable to view details)
                                        let name_color = if rule.enabled {
                                            Colors::TEXT_PRIMARY
                                        } else {
                                            Colors::TEXT_SECONDARY
                                        };
                                        if ui.selectable_label(
                                            self.rule_mgmt_selected_rule.as_ref().map(|s| s == rule_name).unwrap_or(false),
                                            RichText::new(rule_name).color(name_color).monospace()
                                        ).clicked() {
                                            if self.rule_mgmt_selected_rule.as_ref().map(|s| s == rule_name).unwrap_or(false) {
                                                self.rule_mgmt_selected_rule = None;
                                            } else {
                                                self.rule_mgmt_selected_rule = Some(rule_name.clone());
                                            }
                                        }
                                        
                                        // Category
                                        if let Some(ref cat) = rule.category {
                                            ui.label(cat);
                                        } else {
                                            ui.label(RichText::new("-").color(Colors::TEXT_SECONDARY));
                                        }
                                        
                                        // Severity
                                        if let Some(ref sev) = rule.severity {
                                            let sev_color = match sev.as_str() {
                                                "critical" | "high" => Colors::RED_LIGHT,
                                                "medium" => Colors::YELLOW_WARNING,
                                                _ => Colors::BLUE_INFO,
                                            };
                                            ui.label(RichText::new(sev.to_uppercase()).color(sev_color));
                                        } else {
                                            ui.label(RichText::new("-").color(Colors::TEXT_SECONDARY));
                                        }
                                        
                                        // Tags
                                        if !rule.tags.is_empty() {
                                            let tags_str = rule.tags.join(", ");
                                            ui.label(RichText::new(tags_str).small());
                                        } else {
                                            ui.label(RichText::new("-").color(Colors::TEXT_SECONDARY));
                                        }
                                        
                                        // Actions
                                        ui.horizontal(|ui| {
                                            if ui.small_button("View").clicked() {
                                                self.rule_mgmt_selected_rule = Some(rule_name.clone());
                                            }
                                        });
                                        
                                        ui.end_row();
                                        
                                        // Performance metrics (if enabled)
                                        if self.rule_mgmt_show_metrics && rule.metrics.evaluation_count > 0 {
                                            ui.label(""); // Skip enabled column
                                            ui.label(RichText::new("Metrics:").small().strong());
                                            ui.label(format!("Matches: {}", rule.metrics.match_count));
                                            ui.label(format!("Rate: {:.1}%", rule.metrics.match_rate() * 100.0));
                                            ui.label(format!("Avg: {:.2}μs", rule.metrics.avg_evaluation_time_us));
                                            ui.label(""); // Skip actions column
                                            ui.end_row();
                                        }
                                    }
                                }
                            });
                    });
            }
            
            // Rule details panel
            if let Some(rule) = selected_rule_data {
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(5.0);
                    
                    ui.group(|ui| {
                        ui.heading(format!("Rule Details: {}", rule.name));
                        ui.separator();
                        
                        egui::Grid::new("rule_details")
                            .num_columns(2)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.label(RichText::new("Name:").strong());
                                ui.label(RichText::new(&rule.name).monospace());
                                ui.end_row();
                                
                                if let Some(ref ns) = rule.namespace {
                                    ui.label(RichText::new("Namespace:").strong());
                                    ui.label(ns);
                                    ui.end_row();
                                }
                                
                                if let Some(ref cat) = rule.category {
                                    ui.label(RichText::new("Category:").strong());
                                    ui.label(cat);
                                    ui.end_row();
                                }
                                
                                if let Some(ref desc) = rule.description {
                                    ui.label(RichText::new("Description:").strong());
                                    ui.label(desc);
                                    ui.end_row();
                                }
                                
                                if let Some(ref sev) = rule.severity {
                                    ui.label(RichText::new("Severity:").strong());
                                    let sev_color = match sev.as_str() {
                                        "critical" | "high" => Colors::RED_LIGHT,
                                        "medium" => Colors::YELLOW_WARNING,
                                        _ => Colors::BLUE_INFO,
                                    };
                                    ui.label(RichText::new(sev.to_uppercase()).color(sev_color));
                                    ui.end_row();
                                }
                                
                                if !rule.tags.is_empty() {
                                    ui.label(RichText::new("Tags:").strong());
                                    ui.label(rule.tags.join(", "));
                                    ui.end_row();
                                }
                                
                                ui.label(RichText::new("Status:").strong());
                                if rule.enabled {
                                    ui.label(RichText::new("Enabled").color(Colors::GREEN_SUCCESS));
                                } else {
                                    ui.label(RichText::new("Disabled").color(Colors::TEXT_SECONDARY));
                                }
                                ui.end_row();
                                
                                if let Some(ref source) = rule.source_file {
                                    ui.label(RichText::new("Source:").strong());
                                    ui.label(source.display().to_string());
                                    ui.end_row();
                                }
                            });
                        
                        // Performance metrics
                        if rule.metrics.evaluation_count > 0 {
                            ui.add_space(10.0);
                            ui.separator();
                            ui.heading("Performance Metrics");
                            
                            egui::Grid::new("rule_metrics")
                                .num_columns(2)
                                .striped(true)
                                .show(ui, |ui| {
                                    ui.label(RichText::new("Evaluations:").strong());
                                    ui.label(format!("{}", rule.metrics.evaluation_count));
                                    ui.end_row();
                                    
                                    ui.label(RichText::new("Matches:").strong());
                                    ui.label(format!("{}", rule.metrics.match_count));
                                    ui.end_row();
                                    
                                    ui.label(RichText::new("Match Rate:").strong());
                                    ui.label(format!("{:.2}%", rule.metrics.match_rate() * 100.0));
                                    ui.end_row();
                                    
                                    ui.label(RichText::new("Avg Evaluation Time:").strong());
                                    ui.label(format!("{:.2} μs", rule.metrics.avg_evaluation_time_us));
                                    ui.end_row();
                                    
                                    if let Some(last_match) = rule.metrics.last_match_time {
                                        ui.label(RichText::new("Last Match:").strong());
                                        let elapsed = last_match.elapsed();
                                        let elapsed_str = if elapsed.as_secs() < 60 {
                                            format!("{}s ago", elapsed.as_secs())
                                        } else if elapsed.as_secs() < 3600 {
                                            format!("{}m ago", elapsed.as_secs() / 60)
                                        } else {
                                            format!("{}h ago", elapsed.as_secs() / 3600)
                                        };
                                        ui.label(elapsed_str);
                                        ui.end_row();
                                    }
                                });
                        }
                        
                        // Rule content (if available)
                        if let Some(ref content) = rule.content {
                            ui.add_space(10.0);
                            ui.separator();
                            ui.heading("Rule Content");
                            ui.add_space(5.0);
                            
                            egui::ScrollArea::vertical()
                                .max_height(200.0)
                                .show(ui, |ui| {
                                    let mut content_display = content.clone();
                                    ui.add(egui::TextEdit::multiline(&mut content_display)
                                        .font(egui::TextStyle::Monospace)
                                        .desired_width(f32::INFINITY)
                                        .interactive(false));
                                });
                        }
                        
                        // Rule validation and testing
                        ui.add_space(10.0);
                        ui.separator();
                        ui.heading("Rule Testing");
                        ui.add_space(5.0);
                        
                        ui.horizontal(|ui| {
                            if ui.button("Validate Rule").clicked() {
                                self.validate_rule(&rule.name);
                            }
                            if ui.button("Test Rule").clicked() {
                                self.test_rule(&rule.name);
                            }
                        });
                        
                        // Show validation/test results if available
                        // (This would be stored in app state and displayed here)
                    });
                }
        });
    }

    /// Render execute tab
    fn render_execute_tab(&mut self, ui: &mut egui::Ui) {
        if let Some(bof) = &self.bof_file {
            let bof_clone = bof.clone();
            
            // Show detected argument signature if available (or manual override)
            let display_signature = if self.override_signature_detection && !self.manual_signature.is_empty() {
                Some((self.manual_signature.clone(), true))
            } else if let Some(report) = &self.analysis_report {
                if !report.argument_signature.signature.is_empty() {
                    Some((report.argument_signature.signature.clone(), false))
                } else {
                    None
                }
            } else {
                None
            };
            
            if let Some((sig, is_override)) = display_signature {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("📋 Expected Signature:").strong());
                        ui.label(RichText::new(&sig)
                            .monospace()
                            .color(Colors::RED_ACCENT)
                            .size(16.0));
                        
                        if is_override {
                            ui.label(RichText::new("(manual override)")
                                .small()
                                .color(Colors::GREEN_SUCCESS));
                        } else if let Some(report) = &self.analysis_report {
                            let conf_percent = (report.argument_signature.confidence * 100.0) as u8;
                            let conf_color = if conf_percent >= 70 { Colors::GREEN_SUCCESS }
                                else if conf_percent >= 40 { Colors::YELLOW_WARNING }
                                else { Colors::TEXT_SECONDARY };
                            ui.label(RichText::new(format!("({}% confidence)", conf_percent))
                                .small()
                                .color(conf_color));
                        }
                    });
                    
                    // Show argument breakdown
                    if !is_override {
                        if let Some(report) = &self.analysis_report {
                            if !report.argument_signature.argument_types.is_empty() {
                                ui.horizontal_wrapped(|ui| {
                                    for arg_info in &report.argument_signature.argument_types {
                                        let type_char = match arg_info.arg_type {
                                            crate::core::executor::arguments::ArgumentType::String => "z",
                                            crate::core::executor::arguments::ArgumentType::WideString => "Z",
                                            crate::core::executor::arguments::ArgumentType::Int32 => "i",
                                            crate::core::executor::arguments::ArgumentType::Int16 => "s",
                                            crate::core::executor::arguments::ArgumentType::Binary => "b",
                                        };
                                        ui.label(RichText::new(format!("[{}] {}", arg_info.position, type_char))
                                            .monospace()
                                            .background_color(Colors::BG_LIGHT)
                                            .color(Colors::RED_ACCENT));
                                    }
                                });
                            }
                        }
                    } else {
                        // Show manual signature breakdown
                        ui.horizontal_wrapped(|ui| {
                            for (i, ch) in sig.chars().enumerate() {
                                ui.label(RichText::new(format!("[{}] {}", i, ch))
                                    .monospace()
                                    .background_color(Colors::BG_LIGHT)
                                    .color(Colors::RED_ACCENT));
                            }
                        });
                    }
                });
                ui.add_space(10.0);
            }
            
            // Signature override option
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.override_signature_detection, "Override Signature Detection");
                    if self.override_signature_detection {
                        ui.label(RichText::new("Manual Signature:").small());
                        ui.add(egui::TextEdit::singleline(&mut self.manual_signature)
                            .hint_text("e.g., zi, zzi, iiz")
                            .desired_width(100.0)
                            .font(egui::TextStyle::Monospace));
                        ui.label(RichText::new("(z=string, Z=wide, i=int32, s=int16, b=binary)")
                            .small()
                            .color(Colors::TEXT_MUTED));
                    }
                });
                if self.override_signature_detection {
                    ui.add_space(4.0);
                    if self.manual_signature.trim().is_empty() {
                        ui.label(RichText::new("Warning: Override is enabled but the manual signature is empty. Please enter a signature (e.g., 'zi', 'zzi') or disable override.")
                            .small()
                            .color(Colors::YELLOW_WARNING));
                    } else {
                        ui.label(RichText::new("Note: When enabled, the manual signature will be used instead of the auto-detected signature.")
                            .small()
                            .color(Colors::TEXT_MUTED));
                    }
                }
            });
            ui.add_space(10.0);
            
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
                        
                        // Entry point selection
                        ui.label(RichText::new("Entry Point:").color(Colors::TEXT_SECONDARY));
                        let potential_entry_points = bof_clone.find_potential_entry_points();
                        if !potential_entry_points.is_empty() {
                            let entry_point_names: Vec<String> = potential_entry_points.iter()
                                .map(|ep| ep.name.clone())
                                .collect();
                            
                            let current_selection = self.selected_entry_point.as_ref()
                                .map(|s| s.as_str())
                                .or_else(|| {
                                    // Default to "go" if available, otherwise first entry point
                                    potential_entry_points.iter()
                                        .find(|ep| ep.name == "go")
                                        .or_else(|| potential_entry_points.first())
                                        .map(|ep| ep.name.as_str())
                                });
                            
                            egui::ComboBox::new("entry_point_selector", "")
                                .selected_text(current_selection.unwrap_or("Default"))
                                .show_ui(ui, |ui| {
                                    // Add "Default" option (uses bof.entry_point or first available)
                                    ui.selectable_value(
                                        &mut self.selected_entry_point,
                                        None,
                                        "Default (auto-detect)"
                                    );
                                    
                                    // Add each potential entry point
                                    for ep_name in &entry_point_names {
                                        ui.selectable_value(
                                            &mut self.selected_entry_point,
                                            Some(ep_name.clone()),
                                            ep_name.clone()
                                        );
                                    }
                                });
                        } else {
                            ui.label(RichText::new("No entry points found").color(Colors::YELLOW_WARNING));
                        }
                        ui.end_row();
                        
                        ui.label("Options:");
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.execution_sandbox, "Sandbox");
                            ui.checkbox(&mut self.execution_trace, "Trace Beacon API calls");
                            ui.checkbox(&mut self.execution_cs_compat, "Cobalt Strike Compatible");
                            ui.checkbox(
                                &mut self.execution_emulate_beacon_info,
                                "Emulate BeaconInformation",
                            );
                        });
                        ui.end_row();
                    });
                
                ui.add_space(5.0);
                
                // CS Compatible mode help text
                if self.execution_cs_compat {
                    let ep_name = self.selected_entry_point.as_ref()
                        .map(|s| s.as_str())
                        .unwrap_or("go");
                    if ep_name == "go" {
                        ui.label(RichText::new("ℹ️ CS Compatible: Simple string arguments will be passed as null-terminated strings (like Cobalt Strike)")
                            .small()
                            .color(Colors::TEXT_MUTED));
                    } else {
                        ui.label(RichText::new("ℹ️ Note: CS Compatible mode only applies to 'go' entry point. Using standard format for this entry point.")
                            .small()
                            .color(Colors::TEXT_MUTED));
                    }
                    ui.add_space(4.0);
                } else {
                    // Show hint for standard format
                    let ep_name = self.selected_entry_point.as_ref()
                        .map(|s| s.as_str())
                        .unwrap_or("go");
                    if ep_name != "go" {
                        ui.label(RichText::new("ℹ️ Tip: Use format like 'z:string' for string arguments (e.g., 'z:test')")
                            .small()
                            .color(Colors::TEXT_MUTED));
                        ui.add_space(4.0);
                    }
                }
                
                // Argument format help
                ui.collapsing("Argument Format Help", |ui| {
                    ui.label(RichText::new("Format: TYPE:VALUE separated by spaces").small());
                    if self.execution_cs_compat {
                        ui.add_space(4.0);
                        ui.label(RichText::new("Note: In CS Compatible mode, simple string arguments are passed as null-terminated strings (not packed).")
                            .small()
                            .color(Colors::TEXT_MUTED));
                        ui.add_space(4.0);
                    }
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
                // Check if we have any entry point available (default or selected)
                let has_entry_point = bof_clone.entry_point.is_some() 
                    || !bof_clone.find_potential_entry_points().is_empty();
                let can_execute = !self.is_executing && has_entry_point;
                
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
            
            // Show warning if no entry points found at all
            let potential_entry_points = bof_clone.find_potential_entry_points();
            if potential_entry_points.is_empty() {
                ui.label(RichText::new("Warning: No entry point found in BOF")
                    .color(Colors::YELLOW_WARNING));
            } else if bof_clone.entry_point.is_none() {
                ui.label(RichText::new("Info: No 'go' entry point found, but alternative entry points are available")
                    .color(Colors::TEXT_MUTED));
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
            // Parse arguments with selected mode
            // CS Compatible mode only applies to the default "go" entry point
            // Alternative entry points typically use standard Beacon API format
            let use_cs_compat = self.execution_cs_compat && 
                (self.selected_entry_point.is_none() || 
                 self.selected_entry_point.as_ref().map(|s| s == "go").unwrap_or(false));
            
            // Check if we have a detected signature and use it for parsing
            let args_result = if self.execution_args.is_empty() {
                Ok(Vec::new())
            } else if self.override_signature_detection {
                // Override mode: require manual signature
                let manual_sig = self.manual_signature.trim();
                if manual_sig.is_empty() {
                    self.execution_output.push("Error: Override Signature Detection is enabled but manual signature is empty. Please enter a signature (e.g., 'zi', 'zzi') or disable override.".to_string());
                    return;
                }
                // Use manual signature override
                if executor::is_debug_mode() {
                    eprintln!("[GUI] Using manual signature override '{}' to parse arguments", 
                        manual_sig);
                }
                executor::arguments::parse_arguments_with_signature(
                    &self.execution_args, 
                    manual_sig
                )
            } else if let Some(ref report) = self.analysis_report {
                // Use detected signature if available (even with low confidence)
                // If signature is shown in GUI, user expects it to work
                if !report.argument_signature.signature.is_empty() {
                    if executor::is_debug_mode() {
                        eprintln!("[GUI] Using detected signature '{}' (confidence: {:.0}%) to parse arguments", 
                            report.argument_signature.signature,
                            report.argument_signature.confidence * 100.0);
                    }
                    executor::arguments::parse_arguments_with_signature(
                        &self.execution_args, 
                        &report.argument_signature.signature
                    )
                } else {
                    // Fall back to standard parsing
                    let mode = if use_cs_compat {
                        executor::arguments::ArgumentMode::CobaltStrike
                    } else {
                        executor::arguments::ArgumentMode::Standard
                    };
                    executor::arguments::parse_arguments_with_mode(&self.execution_args, mode)
                }
            } else {
                // No analysis report, use standard parsing
                let mode = if use_cs_compat {
                    executor::arguments::ArgumentMode::CobaltStrike
                } else {
                    executor::arguments::ArgumentMode::Standard
                };
                executor::arguments::parse_arguments_with_mode(&self.execution_args, mode)
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
            let entry_point_name = self.selected_entry_point.clone();
            let emulate_beacon_info = self.execution_emulate_beacon_info;
            
            thread::spawn(move || {
                // Use catch_unwind to handle any panics in the execution
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    executor::execute_with_entry_point(
                        &bof_clone, 
                        &packed_args, 
                        sandbox, 
                        trace, 
                        timeout,
                        entry_point_name.as_deref(),
                        emulate_beacon_info,
                    )
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
    /// Validate a YARA rule
    fn validate_rule(&mut self, rule_name: &str) {
        #[cfg(feature = "yara")]
        {
            use yara::Compiler;
            
            if let Some(rule) = self.yara_rule_manager.get_rule(rule_name) {
                if let Some(ref content) = rule.content {
                    match Compiler::new() {
                        Ok(compiler) => {
                            match compiler.add_rules_str(content) {
                                Ok(compiler) => {
                                    match compiler.compile_rules() {
                                        Ok(_) => {
                                            self.status_message = format!("Rule '{}' is valid", rule_name);
                                        }
                                        Err(e) => {
                                            self.status_message = format!("Rule '{}' compilation error: {}", rule_name, e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    self.status_message = format!("Rule '{}' syntax error: {}", rule_name, e);
                                }
                            }
                        }
                        Err(e) => {
                            self.status_message = format!("YARA compiler initialization failed: {}", e);
                        }
                    }
                } else {
                    self.status_message = format!("Rule '{}' has no content to validate", rule_name);
                }
            } else {
                self.status_message = format!("Rule '{}' not found", rule_name);
            }
        }
        #[cfg(not(feature = "yara"))]
        {
            self.status_message = "YARA feature not enabled".to_string();
        }
    }
    
    /// Test a YARA rule against sample data
    fn test_rule(&mut self, rule_name: &str) {
        #[cfg(feature = "yara")]
        {
            use yara::Compiler;
            
            if let Some(rule) = self.yara_rule_manager.get_rule(rule_name) {
                if let Some(ref content) = rule.content {
                    // Compile the rule
                    match Compiler::new() {
                        Ok(compiler) => {
                            match compiler.add_rules_str(content) {
                                Ok(compiler) => {
                                    match compiler.compile_rules() {
                                        Ok(rules) => {
                                            // Test against current BOF if available
                                            if let Some(ref bof) = self.bof_file {
                                                let start = std::time::Instant::now();
                                                let mut matches = 0;
                                                
                                                // Test against all sections
                                                for section in &bof.sections {
                                                    if !section.data.is_empty() {
                                                        if let Ok(scan_results) = rules.scan_mem(&section.data, 0) {
                                                            if !scan_results.is_empty() {
                                                                matches += scan_results.len();
                                                            }
                                                        }
                                                    }
                                                }
                                                
                                                let duration = start.elapsed();
                                                self.yara_rule_manager.update_metrics(rule_name, duration, matches > 0);
                                                
                                                if matches > 0 {
                                                    self.status_message = format!("Rule '{}' matched {} time(s) in {:.2}ms", 
                                                        rule_name, matches, duration.as_secs_f64() * 1000.0);
                                                } else {
                                                    self.status_message = format!("Rule '{}' did not match (tested in {:.2}ms)", 
                                                        rule_name, duration.as_secs_f64() * 1000.0);
                                                }
                                                
                                                // Trigger re-analysis to update metrics
                                                if self.bof_file.is_some() {
                                                    self.run_analysis();
                                                }
                                            } else {
                                                self.status_message = "No BOF loaded - cannot test rule".to_string();
                                            }
                                        }
                                        Err(e) => {
                                            self.status_message = format!("Rule '{}' compilation error: {}", rule_name, e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    self.status_message = format!("Rule '{}' syntax error: {}", rule_name, e);
                                }
                            }
                        }
                        Err(e) => {
                            self.status_message = format!("YARA compiler initialization failed: {}", e);
                        }
                    }
                } else {
                    self.status_message = format!("Rule '{}' has no content to test", rule_name);
                }
            } else {
                self.status_message = format!("Rule '{}' not found", rule_name);
            }
        }
        #[cfg(not(feature = "yara"))]
        {
            self.status_message = "YARA feature not enabled".to_string();
        }
    }
    
    /// Export OpSec findings to JSON or Markdown
    fn export_opsec_findings(&mut self) {
        if let Some(opsec) = &self.opsec_analysis {
            // Try JSON first, then Markdown
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("JSON", &["json"])
                .add_filter("Markdown", &["md"])
                .set_file_name("opsec_findings.json")
                .save_file()
            {
                let format = if path.extension().and_then(|s| s.to_str()) == Some("md") {
                    "md"
                } else {
                    "json"
                };
                
                match self.write_opsec_export(&path, opsec, format) {
                    Ok(_) => {
                        self.status_message = format!("Exported OpSec findings to {}", path.display());
                    }
                    Err(e) => {
                        self.status_message = format!("Export failed: {}", e);
                    }
                }
            }
        } else {
            self.status_message = "No OpSec analysis available to export".to_string();
        }
    }
    
    /// Write OpSec findings to file
    fn write_opsec_export(&self, path: &std::path::Path, opsec: &crate::core::analyzer::opsec::EnhancedOpsecAnalysis, format: &str) -> anyhow::Result<()> {
        use std::fs;
        
        let content = if format == "json" {
            self.format_opsec_json(opsec)?
        } else {
            self.format_opsec_markdown(opsec)
        };
        
        fs::write(path, content)?;
        Ok(())
    }
    
    /// Format OpSec findings as JSON
    fn format_opsec_json(&self, opsec: &crate::core::analyzer::opsec::EnhancedOpsecAnalysis) -> anyhow::Result<String> {
        use serde_json::json;
        
        let mut api_findings = Vec::new();
        for (api_name, info) in &opsec.api_classifications {
            api_findings.push(json!({
                "api": api_name,
                "category": format!("{:?}", info.category),
                "description": info.description,
                "locations": info.locations.iter().map(|loc| {
                    let mut loc_obj = json!({});
                    if let Some(ref import_info) = loc.import_info {
                        loc_obj["library"] = json!(import_info.library);
                        loc_obj["function"] = json!(import_info.function);
                    }
                    if let Some(ref sym) = loc.symbol {
                        loc_obj["symbol"] = json!(sym);
                    }
                    if let Some(addr) = loc.address {
                        loc_obj["address"] = json!(format!("0x{:X}", addr));
                    }
                    loc_obj
                }).collect::<Vec<_>>()
            }));
        }
        
        let mut combinations = Vec::new();
        for combo in &opsec.risky_combinations {
            combinations.push(json!({
                "risk_level": format!("{:?}", combo.risk_level),
                "apis": combo.apis,
                "description": combo.description,
                "recommendation": combo.recommendation
            }));
        }
        
        let mut patterns = Vec::new();
        for pattern in &opsec.suspicious_patterns {
            patterns.push(json!({
                "pattern_type": format!("{:?}", pattern.pattern_type),
                "severity": format!("{:?}", pattern.severity),
                "description": pattern.description,
                "location": pattern.location
            }));
        }
        
        let json_obj = json!({
            "opsec_score": opsec.opsec_score,
            "overall_stealth_score": opsec.overall_stealth_score,
            "injection_noise_score": opsec.injection_noise_score,
            "anti_debug_evasion_score": opsec.anti_debug_evasion_score,
            "persistence_profile_score": opsec.persistence_profile_score,
            "api_classifications": api_findings,
            "risky_combinations": combinations,
            "suspicious_patterns": patterns,
            "recommendations": opsec.recommendations
        });
        
        serde_json::to_string_pretty(&json_obj).map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))
    }
    
    /// Format OpSec findings as Markdown
    fn format_opsec_markdown(&self, opsec: &crate::core::analyzer::opsec::EnhancedOpsecAnalysis) -> String {
        let mut md = String::new();
        
        md.push_str("# OpSec Analysis Report\n\n");
        md.push_str(&format!("**OpSec Score:** {}/100\n\n", opsec.opsec_score));
        md.push_str(&format!("- Overall Stealth: {}/100\n", opsec.overall_stealth_score));
        md.push_str(&format!("- Injection Noise: {}/100\n", opsec.injection_noise_score));
        md.push_str(&format!("- Anti-Debug/Evasion: {}/100\n", opsec.anti_debug_evasion_score));
        md.push_str(&format!("- Persistence Profile: {}/100\n\n", opsec.persistence_profile_score));
        
        // API Classifications
        if !opsec.api_classifications.is_empty() {
            md.push_str("## API Classifications\n\n");
            md.push_str("| API | Category | Description |\n");
            md.push_str("|-----|----------|-------------|\n");
            
            for (api_name, info) in &opsec.api_classifications {
                md.push_str(&format!("| `{}` | {:?} | {} |\n", 
                    api_name, info.category, info.description));
            }
            md.push_str("\n");
        }
        
        // Risky Combinations
        if !opsec.risky_combinations.is_empty() {
            md.push_str("## Risky API Combinations\n\n");
            for combo in &opsec.risky_combinations {
                md.push_str(&format!("### {:?} Risk\n\n", combo.risk_level));
                md.push_str(&format!("**APIs:** {}\n\n", combo.apis.join(", ")));
                md.push_str(&format!("{}\n\n", combo.description));
                md.push_str(&format!("**Recommendation:** {}\n\n", combo.recommendation));
            }
        }
        
        // Suspicious Patterns
        if !opsec.suspicious_patterns.is_empty() {
            md.push_str("## Suspicious Patterns\n\n");
            for pattern in &opsec.suspicious_patterns {
                md.push_str(&format!("### {:?} ({:?})\n\n", pattern.pattern_type, pattern.severity));
                md.push_str(&format!("{}\n\n", pattern.description));
                if let Some(ref loc) = pattern.location {
                    md.push_str(&format!("**Location:** {}\n\n", loc));
                }
            }
        }
        
        // Recommendations
        if !opsec.recommendations.is_empty() {
            md.push_str("## Recommendations\n\n");
            for rec in &opsec.recommendations {
                md.push_str(&format!("- {}\n", rec));
            }
        }
        
        md
    }
}

impl eframe::App for RedBofApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        // Save YARA settings to eframe storage
        let paths: Vec<String> = self.yara_rule_paths.iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        if let Ok(paths_json) = serde_json::to_string(&paths) {
            let key = format!("{}.yara_rule_paths", eframe::APP_KEY);
            storage.set_string(&key, paths_json);
        }
        
        let key_use_default = format!("{}.yara_use_default_rules", eframe::APP_KEY);
        storage.set_string(&key_use_default, self.yara_use_default_rules.to_string());
        
        let key_folder = format!("{}.yara_persistent_folder", eframe::APP_KEY);
        let folder_str = self.yara_persistent_folder.as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        storage.set_string(&key_folder, folder_str);
    }
    
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
        
        // Render hex preview window if a section is selected
        if let Some(section_name) = &self.hex_preview_section {
            if let Some(bof) = &self.bof_file {
                if let Some(section) = bof.sections.iter().find(|s| &s.name == section_name) {
                    egui::Window::new(format!("Hex Preview: {}", section_name))
                        .collapsible(false)
                        .resizable(true)
                        .default_size([800.0, 600.0])
                        .show(ctx, |ui| {
                            // Close button at the top
                            ui.horizontal(|ui| {
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.button("Close").clicked() {
                                        self.hex_preview_section = None;
                                    }
                                });
                            });
                            ui.separator();
                            
                            // Scrollable hex content
                            egui::ScrollArea::both().show(ui, |ui| {
                                if !section.data.is_empty() {
                                    ui.add(HexDump::new(&section.data).max_rows(1000));
                                } else {
                                    ui.label(RichText::new("Section is empty").color(Colors::TEXT_MUTED));
                                }
                            });
                        });
                } else {
                    // Section not found, close the window
                    self.hex_preview_section = None;
                }
            }
        }
        
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
