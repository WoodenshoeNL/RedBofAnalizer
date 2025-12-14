//! YARA rule management module
//!
//! This module provides rule-level management including:
//! - Individual rule enable/disable
//! - Rule metadata and tagging
//! - Rule performance metrics
//! - Rule validation and testing

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Information about a single YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    /// Rule name/identifier
    pub name: String,
    /// Rule namespace (if any)
    pub namespace: Option<String>,
    /// Rule category (security, functionality, opsec)
    pub category: Option<String>,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule description from metadata
    pub description: Option<String>,
    /// Severity level
    pub severity: Option<String>,
    /// Source file where rule is defined
    pub source_file: Option<PathBuf>,
    /// Whether this rule is enabled
    pub enabled: bool,
    /// Performance metrics
    pub metrics: RuleMetrics,
    /// Rule content (YARA rule text)
    pub content: Option<String>,
}

/// Performance metrics for a rule
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleMetrics {
    /// Number of times this rule has matched
    pub match_count: u64,
    /// Number of times this rule has been evaluated
    pub evaluation_count: u64,
    /// Average evaluation time in microseconds
    pub avg_evaluation_time_us: f64,
    /// Last time this rule matched (not serialized)
    #[serde(skip)]
    pub last_match_time: Option<Instant>,
    /// Total evaluation time in microseconds
    #[serde(skip)]
    total_evaluation_time_us: u64,
}

impl RuleMetrics {
    pub fn new() -> Self {
        Self {
            match_count: 0,
            evaluation_count: 0,
            avg_evaluation_time_us: 0.0,
            last_match_time: None,
            total_evaluation_time_us: 0,
        }
    }

    /// Record a rule evaluation
    pub fn record_evaluation(&mut self, duration: Duration, matched: bool) {
        self.evaluation_count += 1;
        let duration_us = duration.as_micros() as u64;
        self.total_evaluation_time_us += duration_us;
        self.avg_evaluation_time_us = self.total_evaluation_time_us as f64 / self.evaluation_count as f64;
        
        if matched {
            self.match_count += 1;
            self.last_match_time = Some(Instant::now());
        }
    }

    /// Get match rate (matches / evaluations)
    pub fn match_rate(&self) -> f64 {
        if self.evaluation_count == 0 {
            0.0
        } else {
            self.match_count as f64 / self.evaluation_count as f64
        }
    }
}

/// Rule management state
#[derive(Debug, Clone)]
pub struct RuleManager {
    /// Map of rule names to rule info
    rules: HashMap<String, RuleInfo>,
    /// Set of disabled rule names
    disabled_rules: HashSet<String>,
    /// Active filter tags
    filter_tags: HashSet<String>,
    /// Active filter category
    filter_category: Option<String>,
    /// Search filter text
    search_filter: String,
}

impl RuleManager {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            disabled_rules: HashSet::new(),
            filter_tags: HashSet::new(),
            filter_category: None,
            search_filter: String::new(),
        }
    }

    /// Add or update a rule
    pub fn add_rule(&mut self, rule: RuleInfo) {
        let name = rule.name.clone();
        let was_enabled = self.rules.get(&name)
            .map(|r| r.enabled)
            .unwrap_or(true);
        
        let mut rule = rule;
        rule.enabled = was_enabled && !self.disabled_rules.contains(&name);
        self.rules.insert(name, rule);
    }

    /// Get a rule by name
    pub fn get_rule(&self, name: &str) -> Option<&RuleInfo> {
        self.rules.get(name)
    }

    /// Get all rules
    #[allow(dead_code)] // Public API method, may be used by external code or future features
    pub fn get_all_rules(&self) -> Vec<&RuleInfo> {
        self.rules.values().collect()
    }

    /// Get filtered rules
    pub fn get_filtered_rules(&self) -> Vec<&RuleInfo> {
        self.rules.values()
            .filter(|rule| {
                // Check if rule matches search filter
                if !self.search_filter.is_empty() {
                    let search_lower = self.search_filter.to_lowercase();
                    let name_matches = rule.name.to_lowercase().contains(&search_lower);
                    let desc_matches = rule.description.as_ref()
                        .map(|d| d.to_lowercase().contains(&search_lower))
                        .unwrap_or(false);
                    if !name_matches && !desc_matches {
                        return false;
                    }
                }

                // Check category filter
                if let Some(ref filter_cat) = self.filter_category {
                    if rule.category.as_ref() != Some(filter_cat) {
                        return false;
                    }
                }

                // Check tag filter
                if !self.filter_tags.is_empty() {
                    let rule_tags: HashSet<String> = rule.tags.iter().cloned().collect();
                    if !self.filter_tags.iter().any(|tag| rule_tags.contains(tag)) {
                        return false;
                    }
                }

                true
            })
            .collect()
    }

    /// Enable a rule
    pub fn enable_rule(&mut self, name: &str) {
        self.disabled_rules.remove(name);
        if let Some(rule) = self.rules.get_mut(name) {
            rule.enabled = true;
        }
    }

    /// Disable a rule
    pub fn disable_rule(&mut self, name: &str) {
        self.disabled_rules.insert(name.to_string());
        if let Some(rule) = self.rules.get_mut(name) {
            rule.enabled = false;
        }
    }

    /// Toggle rule enabled state
    #[allow(dead_code)] // Public API method, may be used by external code or future features
    pub fn toggle_rule(&mut self, name: &str) {
        if self.disabled_rules.contains(name) {
            self.enable_rule(name);
        } else {
            self.disable_rule(name);
        }
    }

    /// Check if a rule is enabled
    #[allow(dead_code)] // Public API method, may be used by external code or future features
    pub fn is_rule_enabled(&self, name: &str) -> bool {
        !self.disabled_rules.contains(name)
    }

    /// Set search filter
    pub fn set_search_filter(&mut self, filter: String) {
        self.search_filter = filter;
    }

    /// Set category filter
    pub fn set_category_filter(&mut self, category: Option<String>) {
        self.filter_category = category;
    }

    /// Add tag filter
    pub fn add_tag_filter(&mut self, tag: String) {
        self.filter_tags.insert(tag);
    }

    /// Remove tag filter
    pub fn remove_tag_filter(&mut self, tag: &str) {
        self.filter_tags.remove(tag);
    }

    /// Clear all tag filters
    pub fn clear_tag_filters(&mut self) {
        self.filter_tags.clear();
    }

    /// Get all unique tags from all rules
    pub fn get_all_tags(&self) -> Vec<String> {
        let mut tags = HashSet::new();
        for rule in self.rules.values() {
            for tag in &rule.tags {
                tags.insert(tag.clone());
            }
        }
        let mut tags: Vec<String> = tags.into_iter().collect();
        tags.sort();
        tags
    }

    /// Get all unique categories from all rules
    pub fn get_all_categories(&self) -> Vec<String> {
        let mut categories = HashSet::new();
        for rule in self.rules.values() {
            if let Some(ref cat) = rule.category {
                categories.insert(cat.clone());
            }
        }
        let mut categories: Vec<String> = categories.into_iter().collect();
        categories.sort();
        categories
    }

    /// Update rule metrics
    pub fn update_metrics(&mut self, name: &str, duration: Duration, matched: bool) {
        if let Some(rule) = self.rules.get_mut(name) {
            rule.metrics.record_evaluation(duration, matched);
        }
    }

    /// Get enabled rule names (for YARA compilation)
    #[allow(dead_code)] // Public API method, may be used for filtering rules during compilation
    pub fn get_enabled_rule_names(&self) -> HashSet<String> {
        self.rules.values()
            .filter(|rule| rule.enabled)
            .map(|rule| rule.name.clone())
            .collect()
    }
}

impl Default for RuleManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract rule information from YARA rules
#[cfg(feature = "yara")]
#[allow(dead_code)] // Public API function, may be used to extract rule info from compiled rules
pub fn extract_rule_info_from_rules(rules: &yara::Rules, source_file: Option<PathBuf>) -> Vec<RuleInfo> {
    let mut rule_infos = Vec::new();
    
    for rule in rules.get_rules() {
        let name = rule.identifier.to_string();
        let namespace: Option<String> = if rule.namespace.is_empty() {
            None
        } else {
            Some(rule.namespace.to_string())
        };
        
        // Extract metadata
        let mut category = None;
        let mut tags = Vec::new();
        let mut description = None;
        let mut severity = None;
        
        for meta in &rule.metadatas {
            let key = meta.identifier.to_string();
            let value: String = match &meta.value {
                yara::MetadataValue::String(s) => s.to_string(),
                yara::MetadataValue::Integer(i) => i.to_string(),
                yara::MetadataValue::Boolean(b) => b.to_string(),
            };
            
            match key.as_str() {
                "category" => category = Some(value),
                "tags" => {
                    // Tags might be comma-separated
                    for tag in value.split(',') {
                        tags.push(tag.trim().to_string());
                    }
                },
                "description" => description = Some(value),
                "severity" => severity = Some(value),
                _ => {}
            }
        }
        
        // Also check rule tags (YARA's built-in tag system)
        for tag in &rule.tags {
            tags.push(tag.to_string());
        }
        
        rule_infos.push(RuleInfo {
            name,
            namespace,
            category,
            tags,
            description,
            severity,
            source_file: source_file.clone(),
            enabled: true,
            metrics: RuleMetrics::new(),
            content: None, // Rule content would need to be extracted separately
        });
    }
    
    rule_infos
}
