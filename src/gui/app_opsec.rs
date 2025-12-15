//! OpSec tab rendering implementation

use crate::core::analyzer::opsec::{EnhancedOpsecAnalysis, OpsecCategory};
use crate::core::analyzer::compatibility::{CompatibilityAnalysis, CompatibilitySeverity};
use crate::core::analyzer::calling_convention::{CallingConventionAnalysis, IssueSeverity};
use super::theme::Colors;
use egui::{RichText, ScrollArea, ComboBox};

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
    jump_to_imports: &mut dyn FnMut(&str),
) {
    ScrollArea::vertical().show(ui, |ui| {
        // OpSec Analysis Section
        if let Some(opsec_analysis) = opsec {
            ui.group(|ui| {
                ui.heading("OpSec Analysis");
                ui.separator();
                
                // OpSec Score
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
                        ui.label(RichText::new("OpSec Score:").strong());
                        ui.label(RichText::new(format!("{}/100", score))
                            .size(18.0)
                            .color(score_color));
                    });

                    ui.add_space(6.0);

                    egui::Grid::new("opsec_dimension_scores")
                        .num_columns(2)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            ui.label(RichText::new("Overall stealth:").color(Colors::TEXT_SECONDARY));
                            ui.label(RichText::new(format!("{}/100", opsec_analysis.overall_stealth_score))
                                .color(score_color));
                            ui.end_row();

                            ui.label(RichText::new("Injection noise:").color(Colors::TEXT_SECONDARY));
                            ui.label(RichText::new(format!("{}/100", opsec_analysis.injection_noise_score))
                                .color(Colors::RED_LIGHT));
                            ui.end_row();

                            ui.label(RichText::new("Anti-debug / evasion:").color(Colors::TEXT_SECONDARY));
                            ui.label(RichText::new(format!("{}/100", opsec_analysis.anti_debug_evasion_score))
                                .color(Colors::YELLOW_WARNING));
                            ui.end_row();

                            ui.label(RichText::new("Persistence profile:").color(Colors::TEXT_SECONDARY));
                            ui.label(RichText::new(format!("{}/100", opsec_analysis.persistence_profile_score))
                                .color(Colors::YELLOW_WARNING));
                            ui.end_row();
                        });
                });
                
                ui.add_space(10.0);
                
                // API Classifications with filtering and sorting
                if !opsec_analysis.api_classifications.is_empty() {
                    ui.collapsing("API Classifications", |ui| {
                        // Filter controls
                        ui.horizontal(|ui| {
                            ui.label("Filter by name:");
                            ui.text_edit_singleline(api_filter);
                            
                            ui.add_space(20.0);
                            ui.label("Filter by risk:");
                            let show_all_risks = matches!(*risk_filter, OpsecCategory::LowRisk);
                            ComboBox::new("risk_filter", "Risk Level")
                                .selected_text(if show_all_risks {
                                    "All".to_string()
                                } else {
                                    format!("{:?}", risk_filter)
                                })
                                .show_ui(ui, |ui| {
                                    if ui.selectable_label(show_all_risks, "All").clicked() {
                                        *risk_filter = OpsecCategory::LowRisk; // Use as "All" indicator
                                    }
                                    if ui.selectable_label(!show_all_risks && matches!(*risk_filter, OpsecCategory::LowRisk), "Low Risk").clicked() {
                                        *risk_filter = OpsecCategory::LowRisk;
                                    }
                                    if ui.selectable_label(!show_all_risks && matches!(*risk_filter, OpsecCategory::MediumRisk), "Medium Risk").clicked() {
                                        *risk_filter = OpsecCategory::MediumRisk;
                                    }
                                    if ui.selectable_label(!show_all_risks && matches!(*risk_filter, OpsecCategory::HighRisk), "High Risk").clicked() {
                                        *risk_filter = OpsecCategory::HighRisk;
                                    }
                                    if ui.selectable_label(!show_all_risks && matches!(*risk_filter, OpsecCategory::CriticalRisk), "Critical Risk").clicked() {
                                        *risk_filter = OpsecCategory::CriticalRisk;
                                    }
                                });
                            
                            if ui.button("Clear Filters").clicked() {
                                *api_filter = String::new();
                                *risk_filter = OpsecCategory::LowRisk; // Use as "All" indicator
                            }
                        });
                        
                        ui.add_space(5.0);
                        
                        // Filter and sort APIs
                        let mut filtered_apis: Vec<_> = opsec_analysis.api_classifications.iter()
                            .filter(|(api_name, info)| {
                                // Name filter
                                let name_match = api_filter.is_empty() || 
                                    api_name.to_lowercase().contains(&api_filter.to_lowercase());
                                
                                // Risk filter (LowRisk means "All" in our filter when it's the default)
                                let show_all_risks = matches!(*risk_filter, OpsecCategory::LowRisk);
                                let risk_match = show_all_risks || info.category == *risk_filter;
                                
                                name_match && risk_match
                            })
                            .collect();
                        
                        // Sort by risk level (Critical -> High -> Medium -> Low), then by name
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
                        
                        ui.label(RichText::new(format!("Showing {} of {} APIs", 
                            filtered_apis.len(), 
                            opsec_analysis.api_classifications.len()))
                            .small()
                            .color(Colors::TEXT_SECONDARY));
                        
                        ui.add_space(5.0);
                        
                        egui::Grid::new("api_classifications_grid")
                            .num_columns(3)
                            .striped(true)
                            .min_col_width(150.0)
                            .show(ui, |ui| {
                                ui.label(RichText::new("API").strong());
                                ui.label(RichText::new("Category").strong());
                                ui.label(RichText::new("Description").strong());
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
                                        jump_to_imports(api_name);
                                    }
                                    ui.label(RichText::new(format!("{:?}", info.category))
                                        .color(category_color));
                                    ui.label(RichText::new(&info.description).small());
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
                                            jump_to_imports(api);
                                        }
                                    }
                                });
                                ui.label(RichText::new(format!("• {}", combo.recommendation))
                                    .small()
                                    .color(Colors::BLUE_INFO));
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
                                if let Some(location) = &pattern.location {
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
                            ui.label(RichText::new(format!("• {}", feature))
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
                                ui.label(RichText::new(format!("• {}", issue.recommendation))
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
                            ui.label(RichText::new(format!("• {}", rec))
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
                            ui.label(RichText::new(format!("• {}", rec))
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

