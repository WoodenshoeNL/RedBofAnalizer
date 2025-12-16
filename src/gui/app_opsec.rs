//! OpSec tab rendering implementation

use crate::core::analyzer::opsec::{EnhancedOpsecAnalysis, OpsecCategory, PatternType};
use crate::core::analyzer::compatibility::{CompatibilityAnalysis, CompatibilitySeverity};
use crate::core::analyzer::calling_convention::{CallingConventionAnalysis, IssueSeverity};
use super::theme::Colors;
use egui::{RichText, ScrollArea, ComboBox};
use std::collections::HashMap;

/// Navigation request for jumping to different views
#[derive(Clone, Debug)]
pub struct NavigationRequest {
    pub target: String,
    pub address: Option<u64>,
}

/// Helper: render summary of counts by risk level
fn render_risk_summary<TGetSeverity>(
    ui: &mut egui::Ui,
    label: &str,
    items_len: usize,
    mut get_severity: TGetSeverity,
) where
    TGetSeverity: FnMut(usize) -> OpsecCategory,
{
    if items_len == 0 {
        ui.label(RichText::new(format!("{label}: none")).color(Colors::TEXT_SECONDARY));
        return;
    }

    let mut counts: HashMap<OpsecCategory, usize> = HashMap::new();
    for idx in 0..items_len {
        let sev = get_severity(idx);
        *counts.entry(sev).or_insert(0) += 1;
    }

    let fmt = |cat: OpsecCategory| -> String {
        let n = counts.get(&cat).copied().unwrap_or(0);
        if n == 0 {
            String::new()
        } else {
            format!("{:?}: {}", cat, n)
        }
    };

    let parts: Vec<String> = [OpsecCategory::CriticalRisk, OpsecCategory::HighRisk, OpsecCategory::MediumRisk, OpsecCategory::LowRisk]
        .iter()
        .map(|c| fmt(*c))
        .filter(|s| !s.is_empty())
        .collect();

    ui.label(
        RichText::new(format!(
            "{label}: {} item(s) [{}]",
            items_len,
            parts.join(", ")
        ))
        .small()
        .color(Colors::TEXT_SECONDARY),
    );
}

fn render_global_opsec_breakdown(ui: &mut egui::Ui, opsec_analysis: &EnhancedOpsecAnalysis) {
    let api_count = opsec_analysis.api_classifications.len();
    let combo_count = opsec_analysis.risky_combinations.len();
    let pattern_count = opsec_analysis.suspicious_patterns.len();

    render_risk_summary(ui, "APIs by OpSec category", api_count, |idx| {
        opsec_analysis.api_classifications[idx].1.category
    });
    render_risk_summary(ui, "Risky API combinations", combo_count, |idx| {
        opsec_analysis.risky_combinations[idx].risk_level
    });
    render_risk_summary(ui, "Suspicious patterns", pattern_count, |idx| {
        opsec_analysis.suspicious_patterns[idx].severity
    });

    ui.add_space(4.0);
    ui.label(
        RichText::new(
            "These counts feed into the global OpSec score via weighted penalties \
for higher-risk APIs, combinations and patterns.",
        )
        .small()
        .color(Colors::TEXT_MUTED),
    );
}

fn has_injection_activity(opsec_analysis: &EnhancedOpsecAnalysis) -> bool {
    opsec_analysis
        .risky_combinations
        .iter()
        .any(|combo| {
            combo
                .apis
                .iter()
                .any(|a| a.contains("VirtualAlloc") || a.contains("WriteProcessMemory") || a.contains("Thread") || a.contains("Apc"))
        })
        || opsec_analysis
            .suspicious_patterns
            .iter()
            .any(|pattern| {
                matches!(
                    pattern.pattern_type,
                    PatternType::DirectSyscall | PatternType::ProcessInjection | PatternType::Unhooking
                )
            })
}

fn render_injection_breakdown(ui: &mut egui::Ui, opsec_analysis: &EnhancedOpsecAnalysis) {
    let mut has_any = false;

    for combo in &opsec_analysis.risky_combinations {
        if combo
            .apis
            .iter()
            .any(|a| a.contains("VirtualAlloc") || a.contains("WriteProcessMemory") || a.contains("Thread") || a.contains("Apc"))
        {
            has_any = true;
            let risk_color = match combo.risk_level {
                OpsecCategory::LowRisk => Colors::GREEN_SUCCESS,
                OpsecCategory::MediumRisk => Colors::YELLOW_WARNING,
                OpsecCategory::HighRisk => Colors::RED_LIGHT,
                OpsecCategory::CriticalRisk => Colors::RED_ACCENT,
            };

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Combination").strong());
                    ui.label(
                        RichText::new(format!("{:?}", combo.risk_level))
                            .color(risk_color)
                            .strong(),
                    );
                });
                ui.label(RichText::new(format!("APIs: {}", combo.apis.join(", "))).monospace());
                ui.label(RichText::new(&combo.description));
            });
        }
    }

    for pattern in &opsec_analysis.suspicious_patterns {
        if matches!(
            pattern.pattern_type,
            PatternType::DirectSyscall | PatternType::ProcessInjection | PatternType::Unhooking
        ) {
            has_any = true;
            let sev_color = match pattern.severity {
                OpsecCategory::LowRisk => Colors::GREEN_SUCCESS,
                OpsecCategory::MediumRisk => Colors::YELLOW_WARNING,
                OpsecCategory::HighRisk => Colors::RED_LIGHT,
                OpsecCategory::CriticalRisk => Colors::RED_ACCENT,
            };

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{:?}", pattern.pattern_type)).strong());
                    ui.label(
                        RichText::new(format!("({:?})", pattern.severity))
                            .color(sev_color)
                            .small(),
                    );
                });
                ui.label(RichText::new(&pattern.description));
                if let Some(loc) = &pattern.location {
                    ui.label(RichText::new(format!("Location: {}", loc)).small().color(Colors::TEXT_SECONDARY));
                }
            });
        }
    }

    if !has_any {
        ui.label(
            RichText::new("No injection-related combinations or patterns were detected.")
                .small()
                .color(Colors::TEXT_SECONDARY),
        );
    }
}

fn has_antidebug_activity(opsec_analysis: &EnhancedOpsecAnalysis) -> bool {
    opsec_analysis
        .risky_combinations
        .iter()
        .any(|combo| {
            combo
                .apis
                .iter()
                .any(|a| a.contains("Debugger") || a.contains("QueryInformationProcess") || a.contains("SetInformationThread"))
        })
        || opsec_analysis
            .suspicious_patterns
            .iter()
            .any(|pattern| matches!(pattern.pattern_type, PatternType::AntiDebugging))
}

fn render_antidebug_breakdown(ui: &mut egui::Ui, opsec_analysis: &EnhancedOpsecAnalysis) {
    let mut has_any = false;

    for combo in &opsec_analysis.risky_combinations {
        if combo
            .apis
            .iter()
            .any(|a| a.contains("Debugger") || a.contains("QueryInformationProcess") || a.contains("SetInformationThread"))
        {
            has_any = true;
            let risk_color = match combo.risk_level {
                OpsecCategory::LowRisk => Colors::GREEN_SUCCESS,
                OpsecCategory::MediumRisk => Colors::YELLOW_WARNING,
                OpsecCategory::HighRisk => Colors::RED_LIGHT,
                OpsecCategory::CriticalRisk => Colors::RED_ACCENT,
            };

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Combination").strong());
                    ui.label(
                        RichText::new(format!("{:?}", combo.risk_level))
                            .color(risk_color)
                            .strong(),
                    );
                });
                ui.label(RichText::new(format!("APIs: {}", combo.apis.join(", "))).monospace());
                ui.label(RichText::new(&combo.description));
            });
        }
    }

    for pattern in &opsec_analysis.suspicious_patterns {
        if matches!(pattern.pattern_type, PatternType::AntiDebugging) {
            has_any = true;
            let sev_color = match pattern.severity {
                OpsecCategory::LowRisk => Colors::GREEN_SUCCESS,
                OpsecCategory::MediumRisk => Colors::YELLOW_WARNING,
                OpsecCategory::HighRisk => Colors::RED_LIGHT,
                OpsecCategory::CriticalRisk => Colors::RED_ACCENT,
            };

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{:?}", pattern.pattern_type)).strong());
                    ui.label(
                        RichText::new(format!("({:?})", pattern.severity))
                            .color(sev_color)
                            .small(),
                    );
                });
                ui.label(RichText::new(&pattern.description));
                if let Some(loc) = &pattern.location {
                    ui.label(RichText::new(format!("Location: {}", loc)).small().color(Colors::TEXT_SECONDARY));
                }
            });
        }
    }

    if !has_any {
        ui.label(
            RichText::new("No anti-debugging or evasion patterns were detected.")
                .small()
                .color(Colors::TEXT_SECONDARY),
        );
    }
}

fn has_persistence_activity(opsec_analysis: &EnhancedOpsecAnalysis) -> bool {
    opsec_analysis
        .risky_combinations
        .iter()
        .any(|combo| {
            combo
                .apis
                .iter()
                .any(|a| a.contains("Reg") || a.contains("Service") || a.contains("CreateService") || a.contains("OpenSCManager"))
        })
        || opsec_analysis
            .suspicious_patterns
            .iter()
            .any(|pattern| matches!(pattern.pattern_type, PatternType::Persistence))
}

fn render_persistence_breakdown(ui: &mut egui::Ui, opsec_analysis: &EnhancedOpsecAnalysis) {
    let mut has_any = false;

    for combo in &opsec_analysis.risky_combinations {
        if combo
            .apis
            .iter()
            .any(|a| a.contains("Reg") || a.contains("Service") || a.contains("CreateService") || a.contains("OpenSCManager"))
        {
            has_any = true;
            let risk_color = match combo.risk_level {
                OpsecCategory::LowRisk => Colors::GREEN_SUCCESS,
                OpsecCategory::MediumRisk => Colors::YELLOW_WARNING,
                OpsecCategory::HighRisk => Colors::RED_LIGHT,
                OpsecCategory::CriticalRisk => Colors::RED_ACCENT,
            };

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Combination").strong());
                    ui.label(
                        RichText::new(format!("{:?}", combo.risk_level))
                            .color(risk_color)
                            .strong(),
                    );
                });
                ui.label(RichText::new(format!("APIs: {}", combo.apis.join(", "))).monospace());
                ui.label(RichText::new(&combo.description));
            });
        }
    }

    for pattern in &opsec_analysis.suspicious_patterns {
        if matches!(pattern.pattern_type, PatternType::Persistence) {
            has_any = true;
            let sev_color = match pattern.severity {
                OpsecCategory::LowRisk => Colors::GREEN_SUCCESS,
                OpsecCategory::MediumRisk => Colors::YELLOW_WARNING,
                OpsecCategory::HighRisk => Colors::RED_LIGHT,
                OpsecCategory::CriticalRisk => Colors::RED_ACCENT,
            };

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{:?}", pattern.pattern_type)).strong());
                    ui.label(
                        RichText::new(format!("({:?})", pattern.severity))
                            .color(sev_color)
                            .small(),
                    );
                });
                ui.label(RichText::new(&pattern.description));
                if let Some(loc) = &pattern.location {
                    ui.label(RichText::new(format!("Location: {}", loc)).small().color(Colors::TEXT_SECONDARY));
                }
            });
        }
    }

    if !has_any {
        ui.label(
            RichText::new("No persistence-related combinations or patterns were detected.")
                .small()
                .color(Colors::TEXT_SECONDARY),
        );
    }
}

/// Render OpSec tab content
pub fn render_opsec_tab(
    ui: &mut egui::Ui,
    opsec: Option<&EnhancedOpsecAnalysis>,
    compatibility: Option<&CompatibilityAnalysis>,
    calling_conv: Option<&CallingConventionAnalysis>,
    api_filter: &mut String,
    risk_filter: &mut OpsecCategory,
    compat_severity_filter: &mut CompatibilitySeverity,
    show_all_severities: &mut bool,
    sort_column: &mut Option<usize>,
    sort_ascending: &mut bool,
    filter_preset: &mut Option<String>,
    nav_request: &mut Option<NavigationRequest>,
) {
    ScrollArea::vertical().show(ui, |ui| {
        // OpSec Analysis Section
        if let Some(opsec_analysis) = opsec {
            ui.group(|ui| {
                ui.heading("OpSec Analysis");
                ui.separator();
                
                // OpSec Score (global overview)
                let score = opsec_analysis.opsec_score;
                let score_color = if score >= 70 {
                    Colors::GREEN_SUCCESS
                } else if score >= 40 {
                    Colors::YELLOW_WARNING
                } else {
                    Colors::RED_LIGHT
                };
                
                // Main score + dimension profile
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("OpSec Score (global):").strong());
                        ui.label(RichText::new(format!("{}/100", score))
                            .size(18.0)
                            .color(score_color));
                    });

                    ui.add_space(6.0);

                    // Explain relationship between global score and dimension scores
                    ui.label(
                        RichText::new(
                            "Derived from all risky APIs, combinations and patterns.\nDimension scores below are heuristic profiles and are not averaged into the global score.",
                        )
                        .small()
                        .color(Colors::TEXT_MUTED),
                    );

                    ui.add_space(6.0);

                    let has_injection = has_injection_activity(opsec_analysis);
                    let has_antidebug = has_antidebug_activity(opsec_analysis);
                    let has_persistence = has_persistence_activity(opsec_analysis);

                    egui::Grid::new("opsec_dimension_scores")
                        .num_columns(2)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new("Dimension scores")
                                    .strong()
                                    .color(Colors::TEXT_SECONDARY),
                            );
                            ui.end_row();

                            ui.label(RichText::new("Overall stealth:").color(Colors::TEXT_SECONDARY));
                            ui.label(RichText::new(format!("{}/100", opsec_analysis.overall_stealth_score))
                                .color(score_color));
                            ui.end_row();

                            ui.label(RichText::new("Injection noise:").color(Colors::TEXT_SECONDARY));
                            if has_injection {
                                ui.label(
                                    RichText::new(format!(
                                        "{}/100",
                                        opsec_analysis.injection_noise_score
                                    ))
                                    .color(Colors::RED_LIGHT),
                                );
                            } else {
                                ui.label(
                                    RichText::new("N/A (no injection-related activity detected)")
                                        .color(Colors::TEXT_MUTED),
                                );
                            }
                            ui.end_row();

                            ui.label(RichText::new("Anti-debug / evasion:").color(Colors::TEXT_SECONDARY));
                            if has_antidebug {
                                ui.label(
                                    RichText::new(format!(
                                        "{}/100",
                                        opsec_analysis.anti_debug_evasion_score
                                    ))
                                    .color(Colors::YELLOW_WARNING),
                                );
                            } else {
                                ui.label(
                                    RichText::new("N/A (no anti-debugging or evasion activity detected)")
                                        .color(Colors::TEXT_MUTED),
                                );
                            }
                            ui.end_row();

                            ui.label(RichText::new("Persistence profile:").color(Colors::TEXT_SECONDARY));
                            if has_persistence {
                                ui.label(
                                    RichText::new(format!(
                                        "{}/100",
                                        opsec_analysis.persistence_profile_score
                                    ))
                                    .color(Colors::YELLOW_WARNING),
                                );
                            } else {
                                ui.label(
                                    RichText::new("N/A (no persistence-related activity detected)")
                                        .color(Colors::TEXT_MUTED),
                                );
                            }
                            ui.end_row();
                        });

                    ui.add_space(8.0);

                    // Drill-down sections for how each score is composed
                    ui.collapsing("Global OpSec score breakdown", |ui| {
                        render_global_opsec_breakdown(ui, opsec_analysis);
                    });

                    ui.collapsing("Injection noise breakdown", |ui| {
                        render_injection_breakdown(ui, opsec_analysis);
                    });

                    ui.collapsing("Anti-debug / evasion breakdown", |ui| {
                        render_antidebug_breakdown(ui, opsec_analysis);
                    });

                    ui.collapsing("Persistence profile breakdown", |ui| {
                        render_persistence_breakdown(ui, opsec_analysis);
                    });
                });
                
                ui.add_space(10.0);
                
                // API Classifications with enhanced UX
                if !opsec_analysis.api_classifications.is_empty() {
                    // Calculate summary counts
                    let critical_count = opsec_analysis.api_classifications.iter()
                        .filter(|(_, info)| info.category == OpsecCategory::CriticalRisk).count();
                    let high_count = opsec_analysis.api_classifications.iter()
                        .filter(|(_, info)| info.category == OpsecCategory::HighRisk).count();
                    let medium_count = opsec_analysis.api_classifications.iter()
                        .filter(|(_, info)| info.category == OpsecCategory::MediumRisk).count();
                    let low_count = opsec_analysis.api_classifications.iter()
                        .filter(|(_, info)| info.category == OpsecCategory::LowRisk).count();
                    
                    ui.collapsing("API Classifications", |ui| {
                        ui.add_space(5.0);
                        
                        // Summary cards for high/critical issues
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;
                            
                            if critical_count > 0 {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("🔴").size(16.0));
                                    ui.label(RichText::new(format!("{} Critical Risk APIs", critical_count))
                                        .strong()
                                        .color(Colors::RED_ACCENT));
                                });
                            }
                            
                            if high_count > 0 {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("🟠").size(16.0));
                                    ui.label(RichText::new(format!("{} High Risk APIs", high_count))
                                        .strong()
                                        .color(Colors::RED_LIGHT));
                                });
                            }
                            
                            if medium_count > 0 {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("🟡").size(16.0));
                                    ui.label(RichText::new(format!("{} Medium Risk APIs", medium_count))
                                        .color(Colors::YELLOW_WARNING));
                                });
                            }
                            
                            if low_count > 0 {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("🟢").size(16.0));
                                    ui.label(RichText::new(format!("{} Low Risk APIs", low_count))
                                        .color(Colors::GREEN_SUCCESS));
                                });
                            }
                            
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                // Export button
                                if ui.button("📥 Export").clicked() {
                                    *nav_request = Some(NavigationRequest {
                                        target: "export_opsec".to_string(),
                                        address: None,
                                    });
                                }
                            });
                        });
                        
                        ui.add_space(10.0);
                        
                        // Filter controls with presets
                        ui.horizontal(|ui| {
                            ui.label("Filter presets:");
                            if ui.selectable_label(filter_preset.as_ref().map(|s| s == "high_critical").unwrap_or(false), "High/Critical Only").clicked() {
                                *filter_preset = Some("high_critical".to_string());
                                *risk_filter = OpsecCategory::HighRisk; // Will be handled in filter logic
                            }
                            if ui.selectable_label(filter_preset.as_ref().map(|s| s == "injection").unwrap_or(false), "Injection-Related").clicked() {
                                *filter_preset = Some("injection".to_string());
                                *api_filter = "VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|NtWriteVirtualMemory".to_string();
                            }
                            if ui.selectable_label(filter_preset.as_ref().map(|s| s == "antidebug").unwrap_or(false), "Anti-Debug").clicked() {
                                *filter_preset = Some("antidebug".to_string());
                                *api_filter = "Debugger|QueryInformationProcess|SetInformationThread".to_string();
                            }
                            if ui.selectable_label(filter_preset.is_none(), "Custom").clicked() {
                                *filter_preset = None;
                            }
                        });
                        
                        ui.add_space(5.0);
                        
                        ui.horizontal(|ui| {
                            ui.label("Filter by name:");
                            ui.text_edit_singleline(api_filter);
                            
                            ui.add_space(20.0);
                            ui.label("Filter by risk:");
                            let show_all_risks = matches!(*risk_filter, OpsecCategory::LowRisk) && filter_preset.is_none();
                            ComboBox::new("risk_filter", "Risk Level")
                                .selected_text(if show_all_risks {
                                    "All".to_string()
                                } else {
                                    format!("{:?}", risk_filter)
                                })
                                .show_ui(ui, |ui| {
                                    if ui.selectable_label(show_all_risks, "All").clicked() {
                                        *risk_filter = OpsecCategory::LowRisk; // Use as "All" indicator
                                        *filter_preset = None;
                                    }
                                    if ui.selectable_label(!show_all_risks && matches!(*risk_filter, OpsecCategory::LowRisk), "Low Risk").clicked() {
                                        *risk_filter = OpsecCategory::LowRisk;
                                        *filter_preset = None;
                                    }
                                    if ui.selectable_label(!show_all_risks && matches!(*risk_filter, OpsecCategory::MediumRisk), "Medium Risk").clicked() {
                                        *risk_filter = OpsecCategory::MediumRisk;
                                        *filter_preset = None;
                                    }
                                    if ui.selectable_label(!show_all_risks && matches!(*risk_filter, OpsecCategory::HighRisk), "High Risk").clicked() {
                                        *risk_filter = OpsecCategory::HighRisk;
                                        *filter_preset = None;
                                    }
                                    if ui.selectable_label(!show_all_risks && matches!(*risk_filter, OpsecCategory::CriticalRisk), "Critical Risk").clicked() {
                                        *risk_filter = OpsecCategory::CriticalRisk;
                                        *filter_preset = None;
                                    }
                                });
                            
                            if ui.button("Clear Filters").clicked() {
                                *api_filter = String::new();
                                *risk_filter = OpsecCategory::LowRisk; // Use as "All" indicator
                                *filter_preset = None;
                            }
                        });
                        
                        ui.add_space(5.0);
                        
                        // Filter APIs based on preset or custom filters
                        let mut filtered_apis: Vec<_> = opsec_analysis.api_classifications.iter()
                            .filter(|(api_name, info)| {
                                // Apply preset filters
                                if let Some(ref preset) = filter_preset {
                                    match preset.as_str() {
                                        "high_critical" => {
                                            if info.category != OpsecCategory::HighRisk && 
                                               info.category != OpsecCategory::CriticalRisk {
                                                return false;
                                            }
                                        }
                                        "injection" => {
                                            let injection_keywords = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", 
                                                                    "NtCreateThreadEx", "NtWriteVirtualMemory", "Thread", "Apc"];
                                            if !injection_keywords.iter().any(|kw| api_name.contains(kw)) {
                                                return false;
                                            }
                                        }
                                        "antidebug" => {
                                            let antidebug_keywords = ["Debugger", "QueryInformationProcess", "SetInformationThread"];
                                            if !antidebug_keywords.iter().any(|kw| api_name.contains(kw)) {
                                                return false;
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                
                                // Name filter (supports regex-like patterns with |)
                                let name_match = if api_filter.contains('|') {
                                    api_filter.split('|').any(|pattern| {
                                        api_name.to_lowercase().contains(&pattern.trim().to_lowercase())
                                    })
                                } else {
                                    api_filter.is_empty() || 
                                    api_name.to_lowercase().contains(&api_filter.to_lowercase())
                                };
                                
                                // Risk filter (LowRisk means "All" in our filter when it's the default and no preset)
                                let show_all_risks = matches!(*risk_filter, OpsecCategory::LowRisk) && filter_preset.is_none();
                                let risk_match = show_all_risks || info.category == *risk_filter;
                                
                                name_match && risk_match
                            })
                            .collect();
                        
                        // Apply sorting
                        if let Some(col) = sort_column {
                            filtered_apis.sort_by(|a, b| {
                                let cmp = match col {
                                    0 => a.0.cmp(&b.0), // API name
                                    1 => {
                                        let risk_order = |cat: &OpsecCategory| match cat {
                                            OpsecCategory::CriticalRisk => 0,
                                            OpsecCategory::HighRisk => 1,
                                            OpsecCategory::MediumRisk => 2,
                                            OpsecCategory::LowRisk => 3,
                                        };
                                        risk_order(&a.1.category).cmp(&risk_order(&b.1.category))
                                    }
                                    2 => a.1.description.cmp(&b.1.description), // Description
                                    _ => std::cmp::Ordering::Equal,
                                };
                                
                                if *sort_ascending {
                                    cmp
                                } else {
                                    cmp.reverse()
                                }
                            });
                        } else {
                            // Default sort: by risk level (Critical -> High -> Medium -> Low), then by name
                            filtered_apis.sort_by(|a, b| {
                                let risk_order = |cat: &OpsecCategory| match cat {
                                    OpsecCategory::CriticalRisk => 0,
                                    OpsecCategory::HighRisk => 1,
                                    OpsecCategory::MediumRisk => 2,
                                    OpsecCategory::LowRisk => 3,
                                };
                                
                                let risk_cmp = risk_order(&a.1.category).cmp(&risk_order(&b.1.category));
                                if risk_cmp == std::cmp::Ordering::Equal {
                                    a.0.cmp(&b.0)
                                } else {
                                    risk_cmp
                                }
                            });
                        }
                        
                        ui.label(RichText::new(format!("Showing {} of {} APIs", 
                            filtered_apis.len(), 
                            opsec_analysis.api_classifications.len()))
                            .small()
                            .color(Colors::TEXT_SECONDARY));
                        
                        ui.add_space(5.0);
                        
                        // Table with sortable columns
                        egui::Grid::new("api_classifications_grid")
                            .num_columns(4)
                            .striped(true)
                            .min_col_width(150.0)
                            .show(ui, |ui| {
                                // Column headers with sorting
                                let api_sort_indicator = if sort_column == &Some(0) {
                                    if *sort_ascending { " ▲" } else { " ▼" }
                                } else { "" };
                                if ui.button(RichText::new(format!("API{}", api_sort_indicator)).strong()).clicked() {
                                    if sort_column == &Some(0) {
                                        *sort_ascending = !*sort_ascending;
                                    } else {
                                        *sort_column = Some(0);
                                        *sort_ascending = true;
                                    }
                                }
                                
                                let cat_sort_indicator = if sort_column == &Some(1) {
                                    if *sort_ascending { " ▲" } else { " ▼" }
                                } else { "" };
                                if ui.button(RichText::new(format!("Category{}", cat_sort_indicator)).strong()).clicked() {
                                    if sort_column == &Some(1) {
                                        *sort_ascending = !*sort_ascending;
                                    } else {
                                        *sort_column = Some(1);
                                        *sort_ascending = true;
                                    }
                                }
                                
                                let desc_sort_indicator = if sort_column == &Some(2) {
                                    if *sort_ascending { " ▲" } else { " ▼" }
                                } else { "" };
                                if ui.button(RichText::new(format!("Description{}", desc_sort_indicator)).strong()).clicked() {
                                    if sort_column == &Some(2) {
                                        *sort_ascending = !*sort_ascending;
                                    } else {
                                        *sort_column = Some(2);
                                        *sort_ascending = true;
                                    }
                                }
                                
                                ui.label(RichText::new("Location").strong());
                                
                                ui.end_row();
                                
                                for (api_name, info) in filtered_apis {
                                    let category_color = match info.category {
                                        OpsecCategory::LowRisk => Colors::GREEN_SUCCESS,
                                        OpsecCategory::MediumRisk => Colors::YELLOW_WARNING,
                                        OpsecCategory::HighRisk => Colors::RED_LIGHT,
                                        OpsecCategory::CriticalRisk => Colors::RED_ACCENT,
                                    };
                                    
                                    // Make API name clickable to jump to Imports tab
                                    let api_resp = ui
                                        .label(RichText::new(api_name).monospace().underline());
                                    if api_resp.clicked() {
                                        *nav_request = Some(NavigationRequest {
                                            target: api_name.to_string(),
                                            address: None,
                                        });
                                    }
                                    ui.label(RichText::new(format!("{:?}", info.category))
                                        .color(category_color));
                                    
                                    // Clean description without location info
                                    ui.label(RichText::new(&info.description).small());
                                    
                                    // Location buttons column
                                    ui.horizontal(|ui| {
                                        if !info.locations.is_empty() {
                                            for loc in &info.locations {
                                                // Button to jump to Imports tab
                                                if let Some(ref import_info) = loc.import_info {
                                                    if ui.small_button("📥 Imports").clicked() {
                                                        *nav_request = Some(NavigationRequest {
                                                            target: import_info.function.clone(),
                                                            address: None,
                                                        });
                                                    }
                                                }
                                                
                                                // Button to jump to Disassembly tab (if address available)
                                                if let Some(addr) = loc.address {
                                                    if ui.small_button("🔍 Disasm").clicked() {
                                                        *nav_request = Some(NavigationRequest {
                                                            target: if let Some(ref sym) = loc.symbol {
                                                                sym.clone()
                                                            } else {
                                                                format!("0x{:X}", addr)
                                                            },
                                                            address: Some(addr),
                                                        });
                                                    }
                                                }
                                            }
                                        } else {
                                            ui.label(RichText::new("-").small().color(Colors::TEXT_SECONDARY));
                                        }
                                    });
                                    
                                    ui.end_row();
                                }
                            });
                    });
                }
                
                ui.add_space(10.0);
                
                // Risky Combinations
                if !opsec_analysis.risky_combinations.is_empty() {
                    ui.collapsing("Risky API Combinations", |ui| {
                        for combo in &opsec_analysis.risky_combinations {
                            let risk_color = match combo.risk_level {
                                OpsecCategory::LowRisk => Colors::GREEN_SUCCESS,
                                OpsecCategory::MediumRisk => Colors::YELLOW_WARNING,
                                OpsecCategory::HighRisk => Colors::RED_LIGHT,
                                OpsecCategory::CriticalRisk => Colors::RED_ACCENT,
                            };
                            
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(format!("{:?}", combo.risk_level))
                                        .strong()
                                        .color(risk_color));
                                    ui.label(RichText::new(&combo.description).strong());
                                });
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("APIs:").color(Colors::TEXT_SECONDARY));
                                    for (idx, api) in combo.apis.iter().enumerate() {
                                        if idx > 0 {
                                            ui.label(RichText::new(",").color(Colors::TEXT_SECONDARY));
                                        }
                                        let resp = ui.label(
                                            RichText::new(api)
                                                .monospace()
                                                .underline()
                                                .color(Colors::TEXT_PRIMARY),
                                        );
                                        if resp.clicked() {
                                            *nav_request = Some(NavigationRequest {
                                                target: api.to_string(),
                                                address: None,
                                            });
                                        }
                                    }
                                });
                                ui.label(RichText::new(format!("- {}", combo.recommendation))
                                    .small()
                                    .color(Colors::BLUE_INFO));
                                
                                // Display location buttons for the combination
                                if !combo.locations.is_empty() {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new("Locations: ").small().color(Colors::TEXT_SECONDARY));
                                        for loc in &combo.locations {
                                            if let Some(ref import_info) = loc.import_info {
                                                if ui.small_button(format!("📥 {}", import_info.function)).clicked() {
                                                    *nav_request = Some(NavigationRequest {
                                                        target: import_info.function.clone(),
                                                        address: None,
                                                    });
                                                }
                                            }
                                            if let Some(addr) = loc.address {
                                                if ui.small_button(format!("🔍 0x{:X}", addr)).clicked() {
                                                    *nav_request = Some(NavigationRequest {
                                                        target: if let Some(ref sym) = loc.symbol {
                                                            sym.clone()
                                                        } else {
                                                            format!("0x{:X}", addr)
                                                        },
                                                        address: Some(addr),
                                                    });
                                                }
                                            }
                                        }
                                    });
                                }
                            });
                            ui.add_space(5.0);
                        }
                    });
                }
                
                ui.add_space(10.0);
                
                // Function-based OpSec findings
                if !opsec_analysis.function_findings.is_empty() {
                    ui.collapsing("OpSec Findings by Function", |ui| {
                        ui.label(RichText::new("Functions that use risky APIs and patterns")
                            .small()
                            .color(Colors::TEXT_SECONDARY));
                        ui.add_space(5.0);
                        
                        for func_info in &opsec_analysis.function_findings {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    let func_label = if let Some(addr) = func_info.function_address {
                                        format!("{} @ 0x{:X}", func_info.function_name, addr)
                                    } else {
                                        func_info.function_name.clone()
                                    };
                                    
                                    let func_resp = ui.label(RichText::new(&func_label)
                                        .strong()
                                        .monospace());
                                    if func_resp.clicked() {
                                        *nav_request = Some(NavigationRequest {
                                            target: func_info.function_name.clone(),
                                            address: func_info.function_address,
                                        });
                                    }
                                });
                                
                                // Show risky APIs used by this function with location details
                                if !func_info.risky_apis.is_empty() {
                                    ui.label(RichText::new("Risky APIs:").small().strong());
                                    ui.indent("func_apis", |ui| {
                                        for (api_name, api_info) in &func_info.risky_apis {
                                            let category_color = match api_info.category {
                                                OpsecCategory::LowRisk => Colors::GREEN_SUCCESS,
                                                OpsecCategory::MediumRisk => Colors::YELLOW_WARNING,
                                                OpsecCategory::HighRisk => Colors::RED_LIGHT,
                                                OpsecCategory::CriticalRisk => Colors::RED_ACCENT,
                                            };
                                            ui.vertical(|ui| {
                                                ui.horizontal(|ui| {
                                                    let api_resp = ui.label(RichText::new(api_name)
                                                        .monospace()
                                                        .small()
                                                        .underline());
                                                    if api_resp.clicked() {
                                                        *nav_request = Some(NavigationRequest {
                                                            target: api_name.to_string(),
                                                            address: None,
                                                        });
                                                    }
                                                    ui.label(RichText::new(format!("({:?})", api_info.category))
                                                        .small()
                                                        .color(category_color));
                                                });
                                                
                                                // Show location buttons for this API in this function
                                                if !api_info.locations.is_empty() {
                                                    ui.horizontal(|ui| {
                                                        ui.label(RichText::new("  ↳ ").small().color(Colors::TEXT_SECONDARY));
                                                        for loc in &api_info.locations {
                                                            // Button to jump to Imports tab
                                                            if let Some(ref import_info) = loc.import_info {
                                                                if ui.small_button(format!("📥 {}", import_info.function)).clicked() {
                                                                    *nav_request = Some(NavigationRequest {
                                                                        target: import_info.function.clone(),
                                                                        address: None,
                                                                    });
                                                                }
                                                            }
                                                            
                                                            // Button to jump to Disassembly tab (if address available)
                                                            if let Some(addr) = loc.address {
                                                                if ui.small_button(format!("🔍 0x{:X}", addr)).clicked() {
                                                                    *nav_request = Some(NavigationRequest {
                                                                        target: if let Some(ref sym) = loc.symbol {
                                                                            sym.clone()
                                                                        } else {
                                                                            format!("0x{:X}", addr)
                                                                        },
                                                                        address: Some(addr),
                                                                    });
                                                                }
                                                            }
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                            ui.add_space(5.0);
                        }
                    });
                }
                
                ui.add_space(10.0);
                
                // Suspicious Patterns
                if !opsec_analysis.suspicious_patterns.is_empty() {
                    ui.collapsing("Suspicious Patterns", |ui| {
                        for pattern in &opsec_analysis.suspicious_patterns {
                            let severity_color = match pattern.severity {
                                OpsecCategory::LowRisk => Colors::GREEN_SUCCESS,
                                OpsecCategory::MediumRisk => Colors::YELLOW_WARNING,
                                OpsecCategory::HighRisk => Colors::RED_LIGHT,
                                OpsecCategory::CriticalRisk => Colors::RED_ACCENT,
                            };
                            
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(format!("{:?}", pattern.pattern_type))
                                        .strong()
                                        .color(severity_color));
                                    ui.label(RichText::new(format!("({:?})", pattern.severity))
                                        .small()
                                        .color(severity_color));
                                });
                                ui.label(RichText::new(&pattern.description));
                                
                                // Display location buttons
                                if !pattern.locations.is_empty() {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new("Locations: ").small().color(Colors::TEXT_SECONDARY));
                                        for loc in &pattern.locations {
                                            // Button to jump to Imports tab
                                            if let Some(ref import_info) = loc.import_info {
                                                if ui.small_button(format!("📥 {}", import_info.function)).clicked() {
                                                    *nav_request = Some(NavigationRequest {
                                                        target: import_info.function.clone(),
                                                        address: None,
                                                    });
                                                }
                                            }
                                            
                                            // Button to jump to Disassembly tab (if address available)
                                            if let Some(addr) = loc.address {
                                                if ui.small_button(format!("🔍 0x{:X}", addr)).clicked() {
                                                    *nav_request = Some(NavigationRequest {
                                                        target: if let Some(ref sym) = loc.symbol {
                                                            sym.clone()
                                                        } else {
                                                            format!("0x{:X}", addr)
                                                        },
                                                        address: Some(addr),
                                                    });
                                                }
                                            }
                                        }
                                    });
                                } else if let Some(location) = &pattern.location {
                                    // Fallback to legacy location string
                                    ui.label(RichText::new(format!("Location: {}", location))
                                        .small()
                                        .color(Colors::TEXT_SECONDARY));
                                }
                            });
                            ui.add_space(5.0);
                        }
                    });
                }
                
            });
        } else {
            ui.label("No OpSec analysis available. Load and analyze a BOF first.");
        }
        
        ui.add_space(20.0);
        
        // Compatibility Analysis Section
        if let Some(compat) = compatibility {
            ui.group(|ui| {
                ui.heading("Compatibility Analysis");
                ui.separator();
                
                // Compatible Versions
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Compatible with:").strong());
                    if compat.compatible_versions.is_empty() {
                        ui.label(RichText::new("None - Review issues below")
                            .color(Colors::RED_LIGHT));
                    } else {
                        let versions: Vec<String> = compat.compatible_versions.iter()
                            .map(|v| format!("{}", v))
                            .collect();
                        ui.label(RichText::new(versions.join(", "))
                            .color(Colors::GREEN_SUCCESS));
                    }
                });
                
                ui.add_space(10.0);
                
                // Version-Specific Features
                if !compat.version_specific_features.is_empty() {
                            ui.collapsing("Version-Specific Features", |ui| {
                                for feature in &compat.version_specific_features {
                                    ui.label(RichText::new(format!("- {}", feature))
                                        .color(Colors::BLUE_INFO));
                                }
                            });
                }
                
                ui.add_space(10.0);
                
                // Compatibility Issues with filtering
                if !compat.issues.is_empty() {
                    ui.collapsing("Compatibility Issues", |ui| {
                        // Filter controls
                        ui.horizontal(|ui| {
                            ui.label("Filter by severity:");
                            ComboBox::new("compat_severity_filter", "Severity")
                                .selected_text(if *show_all_severities {
                                    "All".to_string()
                                } else {
                                    format!("{:?}", compat_severity_filter)
                                })
                                .show_ui(ui, |ui| {
                                    if ui.selectable_label(*show_all_severities, "All").clicked() {
                                        *show_all_severities = true;
                                    }
                                    if ui.selectable_label(!*show_all_severities && matches!(*compat_severity_filter, CompatibilitySeverity::Warning), "Warning").clicked() {
                                        *show_all_severities = false;
                                        *compat_severity_filter = CompatibilitySeverity::Warning;
                                    }
                                    if ui.selectable_label(!*show_all_severities && matches!(*compat_severity_filter, CompatibilitySeverity::Error), "Error").clicked() {
                                        *show_all_severities = false;
                                        *compat_severity_filter = CompatibilitySeverity::Error;
                                    }
                                });
                            
                            if ui.button("Clear Filter").clicked() {
                                *show_all_severities = true;
                            }
                        });
                        
                        ui.add_space(5.0);
                        
                        // Filter issues
                        let filtered_issues: Vec<_> = compat.issues.iter()
                            .filter(|issue| {
                                *show_all_severities || issue.severity == *compat_severity_filter
                            })
                            .collect();
                        
                        // Sort by severity (Error -> Warning -> Info)
                        let mut sorted_issues = filtered_issues;
                        sorted_issues.sort_by(|a, b| {
                            let severity_order = |sev: &CompatibilitySeverity| match sev {
                                CompatibilitySeverity::Error => 0,
                                CompatibilitySeverity::Warning => 1,
                                CompatibilitySeverity::Info => 2,
                            };
                            severity_order(&a.severity).cmp(&severity_order(&b.severity))
                        });
                        
                        ui.label(RichText::new(format!("Showing {} of {} issues", 
                            sorted_issues.len(), 
                            compat.issues.len()))
                            .small()
                            .color(Colors::TEXT_SECONDARY));
                        
                        ui.add_space(5.0);
                        
                        for issue in sorted_issues {
                            let severity_color = match issue.severity {
                                CompatibilitySeverity::Info => Colors::BLUE_INFO,
                                CompatibilitySeverity::Warning => Colors::YELLOW_WARNING,
                                CompatibilitySeverity::Error => Colors::RED_LIGHT,
                            };
                            
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(format!("{:?}", issue.severity))
                                        .strong()
                                        .color(severity_color));
                                    ui.label(RichText::new(&issue.message).strong());
                                });
                                let affected: Vec<String> = issue.affected_versions.iter()
                                    .map(|v| format!("{}", v))
                                    .collect();
                                ui.label(RichText::new(format!("Affects: {}", affected.join(", ")))
                                    .small()
                                    .color(Colors::TEXT_SECONDARY));
                                ui.label(RichText::new(format!("- {}", issue.recommendation))
                                    .small()
                                    .color(Colors::BLUE_INFO));
                            });
                            ui.add_space(5.0);
                        }
                    });
                }
                
                // Recommendations
                if !compat.recommendations.is_empty() {
                    ui.add_space(10.0);
                    ui.collapsing("Recommendations", |ui| {
                        for rec in &compat.recommendations {
                            ui.label(RichText::new(format!("- {}", rec))
                                .color(Colors::BLUE_INFO));
                        }
                    });
                }
            });
        } else {
            ui.label("No compatibility analysis available.");
        }
        
        ui.add_space(20.0);
        
        // Calling Convention Analysis Section
        if let Some(cc) = calling_conv {
            ui.group(|ui| {
                ui.heading("Calling Convention Analysis");
                ui.separator();
                
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Detected Convention:").strong());
                    ui.label(RichText::new(format!("{}", cc.detected_convention))
                        .monospace()
                        .color(Colors::BLUE_INFO));
                });
                
                ui.add_space(10.0);
                
                // Issues
                if !cc.issues.is_empty() {
                    ui.collapsing("Issues", |ui| {
                        for issue in &cc.issues {
                            let severity_color = match issue.severity {
                                IssueSeverity::Info => Colors::BLUE_INFO,
                                IssueSeverity::Warning => Colors::YELLOW_WARNING,
                                IssueSeverity::Error => Colors::RED_LIGHT,
                            };
                            
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(format!("{:?}", issue.severity))
                                        .strong()
                                        .color(severity_color));
                                    ui.label(RichText::new(&issue.location).monospace());
                                });
                                ui.label(RichText::new(&issue.message));
                                if let Some(detected) = issue.detected {
                                    ui.label(RichText::new(format!("Detected: {} | Expected: {}", 
                                        detected, issue.expected))
                                        .small()
                                        .color(Colors::TEXT_SECONDARY));
                                }
                            });
                            ui.add_space(5.0);
                        }
                    });
                } else {
                    ui.label(RichText::new("No issues detected")
                        .color(Colors::GREEN_SUCCESS));
                }
                
                // Recommendations
                if !cc.recommendations.is_empty() {
                    ui.add_space(10.0);
                    ui.collapsing("Recommendations", |ui| {
                        for rec in &cc.recommendations {
                            ui.label(RichText::new(format!("- {}", rec))
                                .color(Colors::BLUE_INFO));
                        }
                    });
                }
            });
        } else {
            ui.label("No calling convention analysis available.");
        }
    });
}

