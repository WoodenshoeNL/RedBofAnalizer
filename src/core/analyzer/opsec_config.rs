//! OpSec scoring configuration module
//!
//! This module provides configurable scoring profiles for OpSec analysis,
//! allowing customization of risk weights, environment-specific profiles,
//! and whitelisting of APIs and combinations.

use crate::core::analyzer::opsec::{OpsecCategory, PatternType};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};

/// Scoring configuration profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringProfile {
    /// Profile name
    pub name: String,
    /// Profile description
    pub description: String,
    /// Weights for risk categories
    pub category_weights: CategoryWeights,
    /// Weights for pattern types
    pub pattern_weights: PatternWeights,
    /// Weights for risky combinations
    pub combination_weights: CombinationWeights,
    /// Whitelisted APIs (these won't contribute to scoring)
    pub whitelisted_apis: HashSet<String>,
    /// Whitelisted API combinations (these won't contribute to scoring)
    pub whitelisted_combinations: Vec<Vec<String>>,
    /// Whitelisted patterns (these won't contribute to scoring)
    pub whitelisted_patterns: HashSet<PatternType>,
}

/// Weights for risk categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryWeights {
    pub low_risk: i32,
    pub medium_risk: i32,
    pub high_risk: i32,
    pub critical_risk: i32,
}

/// Weights for pattern types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternWeights {
    pub direct_syscall: i32,
    pub process_injection: i32,
    pub token_manipulation: i32,
    pub unhooking: i32,
    pub anti_debugging: i32,
    pub string_obfuscation: i32,
    pub high_entropy: i32,
    pub suspicious_dll: i32,
    pub network_activity: i32,
    pub file_system_access: i32,
    pub persistence: i32,
}

/// Weights for risky combinations based on risk level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinationWeights {
    pub low_risk: i32,
    pub medium_risk: i32,
    pub high_risk: i32,
    pub critical_risk: i32,
}

impl Default for CategoryWeights {
    fn default() -> Self {
        Self {
            low_risk: 1,
            medium_risk: 5,
            high_risk: 10,
            critical_risk: 20,
        }
    }
}

impl Default for PatternWeights {
    fn default() -> Self {
        Self {
            direct_syscall: 12,
            process_injection: 20,
            token_manipulation: 12,
            unhooking: 12,
            anti_debugging: 7,
            string_obfuscation: 3,
            high_entropy: 3,
            suspicious_dll: 7,
            network_activity: 3,
            file_system_access: 3,
            persistence: 12,
        }
    }
}

impl Default for CombinationWeights {
    fn default() -> Self {
        Self {
            low_risk: 5,
            medium_risk: 10,
            high_risk: 15,
            critical_risk: 25,
        }
    }
}

impl Default for ScoringProfile {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            description: "Default scoring profile with balanced weights".to_string(),
            category_weights: CategoryWeights::default(),
            pattern_weights: PatternWeights::default(),
            combination_weights: CombinationWeights::default(),
            whitelisted_apis: HashSet::new(),
            whitelisted_combinations: Vec::new(),
            whitelisted_patterns: HashSet::new(),
        }
    }
}

impl ScoringProfile {
    /// Create a new scoring profile
    #[allow(dead_code)] // Public API - may be used by external code
    pub fn new(name: String, description: String) -> Self {
        Self {
            name,
            description,
            ..Default::default()
        }
    }

    /// Get weight for a risk category
    pub fn get_category_weight(&self, category: OpsecCategory) -> i32 {
        match category {
            OpsecCategory::LowRisk => self.category_weights.low_risk,
            OpsecCategory::MediumRisk => self.category_weights.medium_risk,
            OpsecCategory::HighRisk => self.category_weights.high_risk,
            OpsecCategory::CriticalRisk => self.category_weights.critical_risk,
        }
    }

    /// Get weight for a pattern type
    pub fn get_pattern_weight(&self, pattern_type: &PatternType) -> i32 {
        match pattern_type {
            PatternType::DirectSyscall => self.pattern_weights.direct_syscall,
            PatternType::ProcessInjection => self.pattern_weights.process_injection,
            PatternType::TokenManipulation => self.pattern_weights.token_manipulation,
            PatternType::Unhooking => self.pattern_weights.unhooking,
            PatternType::AntiDebugging => self.pattern_weights.anti_debugging,
            PatternType::StringObfuscation => self.pattern_weights.string_obfuscation,
            PatternType::HighEntropy => self.pattern_weights.high_entropy,
            PatternType::SuspiciousDll => self.pattern_weights.suspicious_dll,
            PatternType::NetworkActivity => self.pattern_weights.network_activity,
            PatternType::FileSystemAccess => self.pattern_weights.file_system_access,
            PatternType::Persistence => self.pattern_weights.persistence,
        }
    }

    /// Get weight for a combination risk level
    pub fn get_combination_weight(&self, risk_level: OpsecCategory) -> i32 {
        match risk_level {
            OpsecCategory::LowRisk => self.combination_weights.low_risk,
            OpsecCategory::MediumRisk => self.combination_weights.medium_risk,
            OpsecCategory::HighRisk => self.combination_weights.high_risk,
            OpsecCategory::CriticalRisk => self.combination_weights.critical_risk,
        }
    }

    /// Check if an API is whitelisted
    pub fn is_api_whitelisted(&self, api_name: &str) -> bool {
        self.whitelisted_apis.contains(api_name)
    }

    /// Check if a combination is whitelisted
    pub fn is_combination_whitelisted(&self, apis: &[String]) -> bool {
        for whitelisted in &self.whitelisted_combinations {
            // Check if all APIs in the whitelisted combination are present
            if whitelisted.iter().all(|api| apis.contains(api)) {
                return true;
            }
        }
        false
    }

    /// Check if a pattern type is whitelisted
    pub fn is_pattern_whitelisted(&self, pattern_type: &PatternType) -> bool {
        self.whitelisted_patterns.contains(pattern_type)
    }
}

/// Predefined scoring profiles
pub struct ScoringProfiles;

impl ScoringProfiles {
    /// Get the default profile
    pub fn default() -> ScoringProfile {
        ScoringProfile::default()
    }

    /// Get an "aggressive EDR" profile - higher weights for risky operations
    pub fn aggressive_edr() -> ScoringProfile {
        ScoringProfile {
            name: "aggressive_edr".to_string(),
            description: "Profile for environments with aggressive EDR - higher penalties for risky operations".to_string(),
            category_weights: CategoryWeights {
                low_risk: 2,
                medium_risk: 8,
                high_risk: 18,
                critical_risk: 35,
            },
            pattern_weights: PatternWeights {
                direct_syscall: 18,
                process_injection: 30,
                token_manipulation: 18,
                unhooking: 18,
                anti_debugging: 12,
                string_obfuscation: 5,
                high_entropy: 5,
                suspicious_dll: 12,
                network_activity: 5,
                file_system_access: 5,
                persistence: 18,
            },
            combination_weights: CombinationWeights {
                low_risk: 8,
                medium_risk: 15,
                high_risk: 25,
                critical_risk: 40,
            },
            whitelisted_apis: HashSet::new(),
            whitelisted_combinations: Vec::new(),
            whitelisted_patterns: HashSet::new(),
        }
    }

    /// Get a "lab" profile - lower weights, more permissive
    pub fn lab() -> ScoringProfile {
        ScoringProfile {
            name: "lab".to_string(),
            description: "Profile for lab/testing environments - lower penalties, more permissive".to_string(),
            category_weights: CategoryWeights {
                low_risk: 0,
                medium_risk: 2,
                high_risk: 5,
                critical_risk: 10,
            },
            pattern_weights: PatternWeights {
                direct_syscall: 5,
                process_injection: 10,
                token_manipulation: 5,
                unhooking: 5,
                anti_debugging: 3,
                string_obfuscation: 1,
                high_entropy: 1,
                suspicious_dll: 3,
                network_activity: 1,
                file_system_access: 1,
                persistence: 5,
            },
            combination_weights: CombinationWeights {
                low_risk: 2,
                medium_risk: 5,
                high_risk: 8,
                critical_risk: 12,
            },
            whitelisted_apis: HashSet::new(),
            whitelisted_combinations: Vec::new(),
            whitelisted_patterns: HashSet::new(),
        }
    }

    /// Get a "mature SOC" profile - balanced but with focus on stealth
    pub fn mature_soc() -> ScoringProfile {
        ScoringProfile {
            name: "mature_soc".to_string(),
            description: "Profile for mature SOC environments - balanced weights with focus on stealth".to_string(),
            category_weights: CategoryWeights {
                low_risk: 1,
                medium_risk: 6,
                high_risk: 12,
                critical_risk: 25,
            },
            pattern_weights: PatternWeights {
                direct_syscall: 15,
                process_injection: 25,
                token_manipulation: 15,
                unhooking: 15,
                anti_debugging: 8,
                string_obfuscation: 4,
                high_entropy: 4,
                suspicious_dll: 8,
                network_activity: 4,
                file_system_access: 4,
                persistence: 15,
            },
            combination_weights: CombinationWeights {
                low_risk: 6,
                medium_risk: 12,
                high_risk: 20,
                critical_risk: 35,
            },
            whitelisted_apis: HashSet::new(),
            whitelisted_combinations: Vec::new(),
            whitelisted_patterns: HashSet::new(),
        }
    }

    /// Get all predefined profiles
    pub fn all() -> Vec<ScoringProfile> {
        vec![
            Self::default(),
            Self::aggressive_edr(),
            Self::lab(),
            Self::mature_soc(),
        ]
    }

    /// Get a profile by name
    #[allow(dead_code)] // Public API - may be used by external code
    pub fn get_by_name(name: &str) -> Option<ScoringProfile> {
        match name {
            "default" => Some(Self::default()),
            "aggressive_edr" | "aggressive-edr" => Some(Self::aggressive_edr()),
            "lab" => Some(Self::lab()),
            "mature_soc" | "mature-soc" => Some(Self::mature_soc()),
            _ => None,
        }
    }
}

/// Profile manager for loading and managing scoring profiles
#[derive(Debug, Clone)]
pub struct ProfileManager {
    profiles: HashMap<String, ScoringProfile>,
    #[allow(dead_code)] // Used internally by current() and set_current() methods
    current_profile: String,
}

impl ProfileManager {
    /// Create a new profile manager with default profiles
    pub fn new() -> Self {
        let mut profiles = HashMap::new();
        for profile in ScoringProfiles::all() {
            profiles.insert(profile.name.clone(), profile);
        }
        
        Self {
            profiles,
            current_profile: "default".to_string(),
        }
    }

    /// Get the current profile
    #[allow(dead_code)] // Public API - may be used by external code
    pub fn current(&self) -> &ScoringProfile {
        self.profiles.get(&self.current_profile)
            .unwrap_or_else(|| self.profiles.get("default").unwrap())
    }

    /// Set the current profile
    #[allow(dead_code)] // Public API - may be used by external code
    pub fn set_current(&mut self, name: &str) -> Result<(), String> {
        if self.profiles.contains_key(name) {
            self.current_profile = name.to_string();
            Ok(())
        } else {
            Err(format!("Profile '{}' not found", name))
        }
    }

    /// Add or update a profile
    pub fn add_profile(&mut self, profile: ScoringProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Get a profile by name
    pub fn get_profile(&self, name: &str) -> Option<&ScoringProfile> {
        self.profiles.get(name)
    }

    /// List all available profile names
    pub fn list_profiles(&self) -> Vec<String> {
        self.profiles.keys().cloned().collect()
    }

    /// Remove a profile (cannot remove default)
    #[allow(dead_code)] // Public API - may be used by external code
    pub fn remove_profile(&mut self, name: &str) -> Result<(), String> {
        if name == "default" {
            return Err("Cannot remove default profile".to_string());
        }
        if self.profiles.remove(name).is_some() {
            if self.current_profile == name {
                self.current_profile = "default".to_string();
            }
            Ok(())
        } else {
            Err(format!("Profile '{}' not found", name))
        }
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileManager {
    /// Load a profile from a JSON file
    pub fn load_profile_from_file(&mut self, path: &Path) -> Result<ScoringProfile> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read profile file: {}", path.display()))?;
        let profile: ScoringProfile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse profile JSON: {}", path.display()))?;
        Ok(profile)
    }

    /// Save a profile to a JSON file
    #[allow(dead_code)] // Public API - may be used by external code
    pub fn save_profile_to_file(&self, profile: &ScoringProfile, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(profile)
            .context("Failed to serialize profile to JSON")?;
        fs::write(path, json)
            .with_context(|| format!("Failed to write profile file: {}", path.display()))?;
        Ok(())
    }

    /// Load all profiles from a directory
    pub fn load_profiles_from_directory(&mut self, dir: &Path) -> Result<Vec<String>> {
        let mut loaded = Vec::new();
        
        if !dir.exists() {
            return Ok(loaded);
        }
        
        let entries = fs::read_dir(dir)
            .with_context(|| format!("Failed to read directory: {}", dir.display()))?;
        
        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                match self.load_profile_from_file(&path) {
                    Ok(profile) => {
                        let name = profile.name.clone();
                        self.add_profile(profile);
                        loaded.push(name);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to load profile from {}: {}", path.display(), e);
                    }
                }
            }
        }
        
        Ok(loaded)
    }

    /// Get the default profile directory path (in user's config directory)
    pub fn default_profile_directory() -> PathBuf {
        #[cfg(windows)]
        {
            let mut path = PathBuf::from(std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string()));
            path.push("RedBofAnalizer");
            path.push("profiles");
            path
        }
        
        #[cfg(not(windows))]
        {
            let mut path = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
            path.push(".config");
            path.push("RedBofAnalizer");
            path.push("profiles");
            path
        }
    }

    /// Initialize profile manager and load profiles from default directory
    pub fn with_default_profiles() -> Self {
        let mut manager = Self::new();
        
        // Try to load profiles from default directory (ignore errors)
        let default_dir = Self::default_profile_directory();
        if default_dir.exists() {
            let _ = manager.load_profiles_from_directory(&default_dir);
        }
        
        manager
    }
}

