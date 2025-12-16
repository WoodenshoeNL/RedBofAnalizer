# Configurable OpSec Scoring

This document provides detailed information about the configurable OpSec scoring system in RedBofAnalizer.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Profile Structure](#profile-structure)
- [Predefined Profiles](#predefined-profiles)
- [Creating Custom Profiles](#creating-custom-profiles)
- [Whitelisting](#whitelisting)
- [Profile Management](#profile-management)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

The configurable scoring system allows you to customize how OpSec scores are calculated for BOFs. This is essential for:

- **Environment-specific tuning**: Different EDR/SOC environments have different detection capabilities
- **Known-safe helpers**: Whitelist legitimate helper functions that would otherwise lower scores
- **Custom risk models**: Match your organization's specific risk assessment criteria

### Key Features

- ✅ Custom weights for risk categories (Low/Medium/High/Critical)
- ✅ Custom weights for pattern types (DirectSyscall, ProcessInjection, etc.)
- ✅ Custom weights for risky API combinations
- ✅ Whitelisting of individual APIs
- ✅ Whitelisting of API combinations
- ✅ Whitelisting of pattern types
- ✅ JSON-based profile format
- ✅ Automatic profile loading from directory
- ✅ GUI integration with profile selection

## Quick Start

### Using Profiles in the GUI

1. Open RedBofAnalizer GUI
2. Load a BOF file
3. Navigate to the **OpSec** tab
4. Use the **"Scoring Profile"** dropdown at the top to select a profile
5. The analysis automatically re-runs with the selected profile

### Creating Your First Custom Profile

1. Create a JSON file in the profile directory:
   - **Windows**: `%APPDATA%\RedBofAnalizer\profiles\my_profile.json`
   - **Linux/macOS**: `~/.config/RedBofAnalizer/profiles/my_profile.json`

2. Use this template:

```json
{
  "name": "my_profile",
  "description": "My custom scoring profile",
  "category_weights": {
    "low_risk": 1,
    "medium_risk": 5,
    "high_risk": 10,
    "critical_risk": 20
  },
  "pattern_weights": {
    "direct_syscall": 12,
    "process_injection": 20,
    "token_manipulation": 12,
    "unhooking": 12,
    "anti_debugging": 7,
    "string_obfuscation": 3,
    "high_entropy": 3,
    "suspicious_dll": 7,
    "network_activity": 3,
    "file_system_access": 3,
    "persistence": 12
  },
  "combination_weights": {
    "low_risk": 5,
    "medium_risk": 10,
    "high_risk": 15,
    "critical_risk": 25
  },
  "whitelisted_apis": [],
  "whitelisted_combinations": [],
  "whitelisted_patterns": []
}
```

3. Restart the GUI or reload profiles (profiles are loaded on startup)

4. Select your profile from the dropdown

## Profile Structure

### Complete Profile Schema

```json
{
  "name": "string",                    // Profile identifier (must be unique)
  "description": "string",              // Human-readable description
  "category_weights": {                // Weights for API risk categories
    "low_risk": 0,                     // Integer, typically 0-5
    "medium_risk": 0,                  // Integer, typically 5-10
    "high_risk": 0,                    // Integer, typically 10-20
    "critical_risk": 0                  // Integer, typically 20-40
  },
  "pattern_weights": {                 // Weights for suspicious patterns
    "direct_syscall": 0,
    "process_injection": 0,
    "token_manipulation": 0,
    "unhooking": 0,
    "anti_debugging": 0,
    "string_obfuscation": 0,
    "high_entropy": 0,
    "suspicious_dll": 0,
    "network_activity": 0,
    "file_system_access": 0,
    "persistence": 0
  },
  "combination_weights": {             // Weights for risky combinations
    "low_risk": 0,
    "medium_risk": 0,
    "high_risk": 0,
    "critical_risk": 0
  },
  "whitelisted_apis": [                // APIs to exclude from scoring
    "string"                           // API names (case-sensitive)
  ],
  "whitelisted_combinations": [         // API combinations to exclude
    ["string", "string"]                // Arrays of API names
  ],
  "whitelisted_patterns": [            // Pattern types to exclude
    "string"                           // Pattern type names
  ]
}
```

### Field Descriptions

#### `name` (required)
- Unique identifier for the profile
- Used in the GUI dropdown
- Should match the filename (without `.json` extension) for clarity

#### `description` (required)
- Human-readable description shown in the GUI
- Explain the profile's purpose and when to use it

#### `category_weights` (required)
- Defines how much each API risk category deducts from the score
- Higher values = more penalty
- Applied per API found

#### `pattern_weights` (required)
- Defines penalties for different suspicious patterns
- Higher values = more penalty
- Applied per pattern detected

#### `combination_weights` (required)
- Defines penalties for risky API combinations
- Higher values = more penalty
- Applied per combination detected

#### `whitelisted_apis` (optional)
- Array of API names to exclude from scoring
- APIs are still detected and shown, but don't affect the score
- Case-sensitive matching

#### `whitelisted_combinations` (optional)
- Array of API combination arrays
- All APIs in a combination must be present for it to be whitelisted
- Case-sensitive matching

#### `whitelisted_patterns` (optional)
- Array of pattern type names to exclude from scoring
- Patterns are still detected and shown, but don't affect the score
- Must match exact pattern type names (see [Pattern Types](#pattern-types))

## Predefined Profiles

RedBofAnalizer includes four predefined profiles:

### 1. `default`
**Purpose**: Balanced weights suitable for general use

**Weights**:
- Categories: Low=1, Medium=5, High=10, Critical=20
- Patterns: DirectSyscall=12, ProcessInjection=20, etc.
- Combinations: Low=5, Medium=10, High=15, Critical=25

**Use when**: You want a balanced assessment without special requirements

### 2. `aggressive_edr`
**Purpose**: Higher penalties for risky operations, designed for aggressive EDR environments

**Weights**:
- Categories: Low=2, Medium=8, High=18, Critical=35
- Patterns: DirectSyscall=18, ProcessInjection=30, etc.
- Combinations: Low=8, Medium=15, High=25, Critical=40

**Use when**: Your target environment has very aggressive EDR (e.g., CrowdStrike, SentinelOne)

### 3. `lab`
**Purpose**: Lower penalties, more permissive, suitable for lab/testing environments

**Weights**:
- Categories: Low=0, Medium=2, High=5, Critical=10
- Patterns: DirectSyscall=5, ProcessInjection=10, etc.
- Combinations: Low=2, Medium=5, High=8, Critical=12

**Use when**: Testing in lab environments where detection is less of a concern

### 4. `mature_soc`
**Purpose**: Balanced weights with focus on stealth, designed for mature SOC environments

**Weights**:
- Categories: Low=1, Medium=6, High=12, Critical=25
- Patterns: DirectSyscall=15, ProcessInjection=25, etc.
- Combinations: Low=6, Medium=12, High=20, Critical=35

**Use when**: Your target environment has a mature SOC with advanced detection capabilities

## Creating Custom Profiles

### Step-by-Step Guide

1. **Choose a base profile**: Start with a predefined profile that's closest to your needs

2. **Copy the profile**: Save it as a new JSON file in the profile directory

3. **Modify weights**: Adjust weights based on your environment's detection capabilities

4. **Add whitelists**: Whitelist known-safe APIs/combinations/patterns

5. **Test**: Load a BOF and verify the scores match your expectations

6. **Document**: Add a clear description explaining the profile's purpose

### Weight Guidelines

- **Low risk APIs**: Typically 0-3 points
  - Standard operations, unlikely to be flagged
  - Examples: `GetProcessHeap`, `HeapAlloc`

- **Medium risk APIs**: Typically 3-8 points
  - Potentially detectable, somewhat suspicious
  - Examples: `LoadLibraryA`, `IsDebuggerPresent`

- **High risk APIs**: Typically 8-20 points
  - Clearly suspicious, commonly abused
  - Examples: `CreateRemoteThread`, `WriteProcessMemory`

- **Critical risk APIs**: Typically 20-40 points
  - Very likely to be flagged
  - Examples: `NtCreateThreadEx`, `EtwEventWrite`

### Pattern Types

Available pattern types for whitelisting:

- `DirectSyscall` - Direct syscall usage (bypasses API hooks)
- `ProcessInjection` - Process injection techniques
- `TokenManipulation` - Token manipulation for privilege escalation
- `Unhooking` - API unhooking techniques
- `AntiDebugging` - Anti-debugging checks
- `StringObfuscation` - String obfuscation patterns
- `HighEntropy` - High entropy regions (packed/obfuscated)
- `SuspiciousDll` - Suspicious DLL usage
- `NetworkActivity` - Network-related behavior
- `FileSystemAccess` - File system access patterns
- `Persistence` - Persistence mechanisms

## Whitelisting

### When to Whitelist

Whitelisting should be used sparingly and only when:

1. **Known-safe helpers**: You have helper functions that are known to be safe in your environment
2. **False positives**: Legitimate patterns that are incorrectly flagged
3. **Environment-specific**: APIs/patterns that are safe in your specific environment

### Whitelisting Individual APIs

```json
"whitelisted_apis": [
  "GetProcessHeap",
  "HeapAlloc",
  "HeapFree",
  "MyCustomHelper"
]
```

**Important**: 
- API names are case-sensitive
- Must match the exact function name as imported
- Whitelisted APIs still appear in the API classifications table
- They don't contribute to the score but are still considered for combinations

### Whitelisting API Combinations

```json
"whitelisted_combinations": [
  ["VirtualAlloc", "WriteProcessMemory"],
  ["OpenProcessToken", "DuplicateTokenEx", "SetThreadToken"]
]
```

**Important**:
- All APIs in the combination must be present for it to match
- Order doesn't matter
- Case-sensitive matching
- The entire combination is excluded from scoring

### Whitelisting Pattern Types

```json
"whitelisted_patterns": [
  "StringObfuscation",
  "HighEntropy"
]
```

**Important**:
- Must match exact pattern type names (see list above)
- Patterns are still detected and shown, but don't affect scoring
- Useful for environments where certain patterns are acceptable

## Profile Management

### Profile Directory

Profiles are automatically loaded from:

- **Windows**: `%APPDATA%\RedBofAnalizer\profiles\`
- **Linux/macOS**: `~/.config/RedBofAnalizer/profiles/`

### Loading Profiles

Profiles are loaded automatically on GUI startup. To reload:

1. Restart the GUI, or
2. Place new profiles in the directory and restart

### Profile File Naming

- Use descriptive names: `my_environment_profile.json`
- Avoid special characters
- The `name` field in JSON should match the filename (without extension)

### Programmatic Access

```rust
use redbofanalyzer::core::analyzer::opsec_config::{
    ProfileManager, ScoringProfiles, ScoringProfile
};

// Create manager with default profiles
let mut manager = ProfileManager::with_default_profiles();

// Add a predefined profile
let lab_profile = ScoringProfiles::lab();
manager.add_profile(lab_profile);

// Load from file
let custom = manager.load_profile_from_file(Path::new("custom.json"))?;
manager.add_profile(custom);

// Set current profile
manager.set_current("custom")?;

// Get current profile
let profile = manager.current();

// Use in analysis
use redbofanalyzer::core::analyzer::opsec::analyze_api_opsec_with_bof;
let analysis = analyze_api_opsec_with_bof(&imports, Some(&bof), Some(profile));
```

## Examples

### Example 1: Whitelisting Helper Functions

```json
{
  "name": "helpers_whitelist",
  "description": "Whitelists known-safe helper functions",
  "category_weights": {
    "low_risk": 1,
    "medium_risk": 5,
    "high_risk": 10,
    "critical_risk": 20
  },
  "pattern_weights": {
    "direct_syscall": 12,
    "process_injection": 20,
    "token_manipulation": 12,
    "unhooking": 12,
    "anti_debugging": 7,
    "string_obfuscation": 3,
    "high_entropy": 3,
    "suspicious_dll": 7,
    "network_activity": 3,
    "file_system_access": 3,
    "persistence": 12
  },
  "combination_weights": {
    "low_risk": 5,
    "medium_risk": 10,
    "high_risk": 15,
    "critical_risk": 25
  },
  "whitelisted_apis": [
    "MyHelperFunction",
    "SafeUtilityFunction",
    "GetProcessHeap"
  ],
  "whitelisted_combinations": [],
  "whitelisted_patterns": []
}
```

### Example 2: Strict Production Environment

```json
{
  "name": "strict_production",
  "description": "Very strict profile for production environments",
  "category_weights": {
    "low_risk": 2,
    "medium_risk": 8,
    "high_risk": 20,
    "critical_risk": 40
  },
  "pattern_weights": {
    "direct_syscall": 25,
    "process_injection": 35,
    "token_manipulation": 25,
    "unhooking": 25,
    "anti_debugging": 15,
    "string_obfuscation": 5,
    "high_entropy": 5,
    "suspicious_dll": 15,
    "network_activity": 5,
    "file_system_access": 5,
    "persistence": 25
  },
  "combination_weights": {
    "low_risk": 10,
    "medium_risk": 20,
    "high_risk": 35,
    "critical_risk": 50
  },
  "whitelisted_apis": [],
  "whitelisted_combinations": [],
  "whitelisted_patterns": []
}
```

### Example 3: Development Environment with Whitelists

```json
{
  "name": "dev_environment",
  "description": "Permissive profile for development with whitelisted debug helpers",
  "category_weights": {
    "low_risk": 0,
    "medium_risk": 2,
    "high_risk": 5,
    "critical_risk": 10
  },
  "pattern_weights": {
    "direct_syscall": 5,
    "process_injection": 10,
    "token_manipulation": 5,
    "unhooking": 5,
    "anti_debugging": 2,
    "string_obfuscation": 1,
    "high_entropy": 1,
    "suspicious_dll": 2,
    "network_activity": 1,
    "file_system_access": 1,
    "persistence": 5
  },
  "combination_weights": {
    "low_risk": 2,
    "medium_risk": 5,
    "high_risk": 8,
    "critical_risk": 12
  },
  "whitelisted_apis": [
    "OutputDebugStringA",
    "IsDebuggerPresent"
  ],
  "whitelisted_combinations": [
    ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]
  ],
  "whitelisted_patterns": [
    "AntiDebugging"
  ]
}
```

## Best Practices

1. **Start with predefined profiles**: Don't create custom profiles from scratch unless necessary

2. **Document your choices**: Always include a clear description explaining why weights were chosen

3. **Whitelist conservatively**: Only whitelist APIs/combinations you're certain are safe

4. **Test thoroughly**: Verify that profile changes produce expected results with real BOFs

5. **Version control**: Keep profile files in version control for reproducibility

6. **Regular review**: Periodically review and update profiles as your environment changes

7. **Share profiles**: If you create useful profiles, consider sharing them with your team

8. **Environment-specific**: Create separate profiles for different environments (dev, staging, prod)

## Troubleshooting

### Profile Not Appearing in Dropdown

**Possible causes:**
- Invalid JSON syntax
- File not in correct directory
- `name` field missing or invalid

**Solutions:**
1. Validate JSON syntax (use a JSON validator)
2. Check file location matches profile directory
3. Ensure `name` field is present and is a valid string

### Profile Not Affecting Scores

**Possible causes:**
- Profile not selected in GUI
- Profile not loaded correctly
- Weights set to zero

**Solutions:**
1. Verify profile is selected in the dropdown
2. Check console/logs for loading errors
3. Verify weights are non-zero values

### Whitelisting Not Working

**Possible causes:**
- Case sensitivity mismatch
- API name doesn't match exactly
- For combinations: not all APIs present

**Solutions:**
1. Ensure exact case match (API names are case-sensitive)
2. Check API names match exactly as imported
3. For combinations, verify all APIs are present in the BOF

### Profile Loading Errors

**Possible causes:**
- Invalid JSON structure
- Missing required fields
- Invalid weight values

**Solutions:**
1. Validate JSON against the schema
2. Ensure all required fields are present
3. Verify weights are integers (can be negative, but typically 0-50)

## Related Documentation

- [OpSec Tab Guide](OPSEC_TAB.md) - GUI usage and interpretation
- [Advanced Features](ADVANCED_FEATURES.md) - CLI usage
- [User Guide](USER_GUIDE.md) - General usage

