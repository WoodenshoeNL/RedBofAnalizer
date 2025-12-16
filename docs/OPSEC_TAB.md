## OpSec Tab (GUI)

This page documents the **OpSec** tab in the RedBofAnalizer GUI.  
It explains what is analyzed, how the score is calculated, and how to interpret the findings for a given BOF.

---

## Overview

The OpSec tab provides a **static operational security assessment** of a BOF based on its **imported APIs**.

It focuses on:

- **API OpSec classification** (per‑API risk)
- **Risky API combinations** (multi‑API patterns)
- **Suspicious patterns** (higher‑level signals)
- **Overall OpSec score (0–100)** and **recommendations**
- **Related views**: compatibility and calling‑convention analysis

It does **not** run the BOF or monitor live behavior. All results are derived from parsing the BOF and examining its imports.

---

## Data Source and Scope

- The analyzer inspects the **import table** of the BOF.
- All non‑`Beacon` APIs are analyzed; `Beacon` APIs are treated as generally safe and excluded from OpSec risk calculations.
- Each API is looked up in an internal database that assigns:
  - **Risk category**
  - **Description** (why it may be noisy or suspicious)
  - **Detection vectors** (ETW, process monitoring, network monitoring, registry monitoring, etc.)
- Unknown APIs (not in the database) are conservatively treated as **medium‑risk**.

This is a **static OpSec model**, best used as an early warning system and design aid rather than a guarantee of stealth.

---

## Layout of the OpSec Tab

The OpSec tab is split into three main sections:

1. **OpSec Analysis**
2. **Compatibility Analysis**
3. **Calling Convention Analysis**

All three are read‑only views driven by the current analysis results for the loaded BOF.

### 1. OpSec Analysis Section

This section contains the **core OpSec information**.

#### OpSec Score

- Displayed at the top as **“OpSec Score: X/100”**.
- **Higher is better** (stealthier / less noisy).
- Color coding:
  - **Green**: score ≥ 70
  - **Yellow**: 40–69
  - **Red**: < 40

#### API Classifications

This table shows **each imported API** and its **OpSec classification**.

- **Columns**
  - **API**: Imported function name (e.g. `CreateRemoteThread`).
  - **Category**: One of:
    - **LowRisk** – Standard operations, relatively low detection concern.
    - **MediumRisk** – Potentially detectable or somewhat suspicious.
    - **HighRisk** – Clearly suspicious or commonly abused by offensive tools.
    - **CriticalRisk** – Very likely to be flagged by AV/EDR/HIPS.
  - **Description**: Short explanation of why the API is classified at that level.

- **Filters**
  - **Filter by name**: Text box to filter APIs by substring (case‑insensitive).
  - **Filter by risk**: Dropdown to limit the view to a specific risk category or show all.
  - **Clear Filters**: Resets both filters.

If an API is unknown to the internal database, it is listed as **medium‑risk** with a description like:

> `Unknown API: <name>`

#### Risky API Combinations

This section lists **multi‑API patterns** that are known to be **particularly noisy or suspicious**:

1. **Process Injection Pattern**
   - APIs: `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
   - Risk: **CriticalRisk**
   - Description: Classic remote process injection technique.
   - Recommendation: Consider alternative techniques or stronger OpSec measures.

2. **Token Manipulation Pattern**
   - APIs: `OpenProcessToken` + `DuplicateTokenEx` + `SetThreadToken`
   - Risk: **HighRisk**
   - Description: Token manipulation chain for privilege escalation / impersonation.
   - Recommendation: Monitor token operations and consider logging or alternative approaches.

3. **Unhooking Pattern**
   - APIs: `NtProtectVirtualMemory` + `NtWriteVirtualMemory`
   - Risk: **HighRisk**
   - Description: Memory protection changes combined with direct memory writes (often used for unhooking).
   - Recommendation: Direct syscall‑style unhooking can bypass API hooks but is highly detectable.

4. **Anti‑Debugging Pattern**
   - APIs: `IsDebuggerPresent` + `CheckRemoteDebuggerPresent`
   - Risk: **MediumRisk**
   - Description: Multiple anti‑debugging checks.
   - Recommendation: Consider less noisy anti‑debugging techniques when OpSec is critical.

Each combination is displayed with:

- Risk level (colored)
- Short description
- List of APIs involved
- Recommendation text

#### Suspicious Patterns

This section aggregates **higher‑level OpSec signals** derived from the imports:

- **DirectSyscall**
  - Trigger: `NtCreateThreadEx` or `NtWriteVirtualMemory`.
  - Severity: **HighRisk**.
  - Meaning: Direct syscalls to bypass API hooks; easier to spot in ETW and telemetry.
  - Recommendation: Prefer indirect syscalls or more subtle techniques if stealth is a priority.

- **ProcessInjection**
  - Trigger: `CreateRemoteThread` and `WriteProcessMemory`.
  - Severity: **CriticalRisk**.
  - Meaning: Clear process injection behavior.

- **TokenManipulation**
  - Trigger: `OpenProcessToken` and `DuplicateTokenEx`.
  - Severity: **HighRisk**.
  - Meaning: Token / privilege manipulation behavior.

- **Unhooking**
  - Trigger: `NtProtectVirtualMemory` and `NtWriteVirtualMemory`.
  - Severity: **HighRisk**.
  - Meaning: Likely code / hook tampering or unhooking logic.

Each pattern shows:

- Pattern type (e.g. `DirectSyscall`, `ProcessInjection`) and severity (colored)
- Description of why it matters for OpSec
- Optional location (currently not populated; reserved for future enhancements)

---

### 2. Compatibility Analysis Section

Below the OpSec analysis, the tab also shows **compatibility information** for the BOF:

- **Compatible with**: Lists Cobalt Strike versions that are considered compatible.
- **Version‑Specific Features**: Shows which features require newer CS versions.
- **Compatibility Issues**:
  - Filterable by severity (Info, Warning, Error).
  - Each issue includes affected versions and a recommendation.
- **Recommendations**: Summary of steps to improve or ensure compatibility.

This is a GUI view of the same compatibility analysis described in `ADVANCED_FEATURES.md`.

---

### 3. Calling Convention Analysis Section

The final section summarizes **calling convention analysis**:

- **Detected Convention**: The calling convention inferred for the BOF entry point.
- **Issues**:
  - Severity (Info, Warning, Error)
  - Location (symbol / section)
  - Optional “Detected vs Expected” details
- **Recommendations**: Guidance to fix mismatches or unsafe conventions.

This is provided alongside OpSec information to make it easy to check **stealth**, **compatibility**, and **correctness** from a single tab.

---

## OpSec Score Calculation

The **OpSec score** starts at **100** and is reduced according to what is found. The scoring weights are **configurable** via scoring profiles, allowing you to customize the analysis for different environments.

### Default Scoring Weights

By default, the following weights are used:

- **Per API classification**
  - LowRisk: −1 point
  - MediumRisk: −5 points
  - HighRisk: −10 points
  - CriticalRisk: −20 points

- **Per risky combination**
  - LowRisk: −5 points
  - MediumRisk: −10 points
  - HighRisk: −15 points
  - CriticalRisk: −25 points

- **Per suspicious pattern**
  - LowRisk: −3 points
  - MediumRisk: −7 points
  - HighRisk: −12 points
  - CriticalRisk: −20 points

The final score is **clamped to 0–100** and then color‑coded in the UI.

If the final score is **below 50**, additional general recommendations are added, such as:

- Review API usage and reduce high‑risk operations.
- Prefer alternative techniques with better OpSec properties.

### Configurable Scoring Profiles

RedBofAnalizer supports **configurable scoring profiles** that allow you to customize risk weights and whitelist specific APIs or patterns. This is particularly useful for:

- **Environment-specific tuning**: Adjust weights for different EDR/SOC maturity levels
- **Known-safe helpers**: Whitelist legitimate helper functions that would otherwise lower the score
- **Custom risk models**: Create profiles that match your organization's risk assessment criteria

#### Using Scoring Profiles in the GUI

1. **Select a Profile**: At the top of the OpSec tab, use the "Scoring Profile" dropdown to select a profile
2. **Automatic Re-analysis**: When you change profiles, the analysis automatically re-runs with the new weights
3. **Profile Description**: Each profile shows a brief description of its purpose

#### Available Predefined Profiles

- **default**: Balanced weights suitable for general use
- **aggressive_edr**: Higher penalties for risky operations, designed for environments with aggressive EDR
- **lab**: Lower penalties, more permissive, suitable for lab/testing environments
- **mature_soc**: Balanced weights with focus on stealth, designed for mature SOC environments

#### Creating Custom Profiles

You can create custom profiles by saving them as JSON files. See the [Configurable Scoring Guide](#configurable-scoring-guide) section below for details.

---

## How to Use the OpSec Tab Effectively

- **Design phase**
  - Use the OpSec tab while iterating on a BOF to quickly see how changes in API usage affect the score and patterns.
  - Prefer lower‑risk APIs or less noisy patterns where possible.

- **Pre‑deployment review**
  - Check that the OpSec score is acceptable for the intended environment.
  - Review any **CriticalRisk** or **HighRisk** APIs and combinations.
  - Confirm that compatibility issues are resolved for the target CS version(s).

- **Triage and comparison**
  - Compare scores and patterns between different BOFs or versions of the same BOF.
  - Use the detailed API and pattern lists to explain why one implementation is more/less stealthy than another.

---

---

## Recognized APIs

The OpSec analyzer maintains an internal database of **125 recognized APIs** with their risk classifications and descriptions. APIs not found in this database are conservatively treated as **MediumRisk** with an "Unknown API:" description.

### API Categories by Risk Level

#### CriticalRisk APIs (9 APIs)
These APIs are very likely to be flagged by AV/EDR/HIPS:

- **Process Injection / Direct Syscalls:**
  - `NtCreateThreadEx` - Direct syscall for thread creation - bypasses hooks
  - `NtWriteVirtualMemory` - Direct syscall for memory write - bypasses hooks
  - `NtAllocateVirtualMemory` - Allocates virtual memory via syscall - injection primitive
  - `NtQueueApcThread` - Queues an APC via direct syscall - stealthy APC-based injection
  - `NtCreateSection` - Creates a section object - used in section mapping injection
  - `NtMapViewOfSection` - Maps a view of a section - section mapping injection technique

- **ETW / AMSI Bypass:**
  - `EtwEventWrite` - ETW event writing - can be used to disable ETW
  - `EtwEventWriteFull` - ETW full event writing - can be used to disable ETW

- **Credential Access:**
  - `LsaRetrievePrivateData` - Retrieves LSA private data - credential access

#### HighRisk APIs (35 APIs)
These APIs are clearly suspicious or commonly abused by offensive tools:

- **Process Injection:**
  - `CreateRemoteThread` - Creates a thread in another process - common injection technique
  - `WriteProcessMemory` - Writes to another process memory - injection technique
  - `VirtualAllocEx` - Allocates memory in another process - injection technique
  - `NtUnmapViewOfSection` - Unmaps a view of a section - used in process hollowing
  - `MapViewOfFile` - Maps a view of a file mapping - section mapping injection
  - `NtResumeThread` - Resumes a suspended thread - used in process hollowing/early bird
  - `ResumeThread` - Resumes a suspended thread - used in process hollowing/early bird
  - `GetThreadContext` - Gets thread context - used in process hollowing/injection
  - `NtGetContextThread` - Gets thread context via syscall - used in process hollowing/injection
  - `NtReadVirtualMemory` - Reads virtual memory via syscall - used in injection/reconnaissance
  - `NtOpenProcess` - Opens a process via syscall - injection prerequisite
  - `NtOpenThread` - Opens a thread via syscall - injection prerequisite
  - `LdrLoadDll` - Low-level DLL loader - used in advanced injection
  - `LdrGetProcedureAddress` - Gets procedure address from DLL - used in manual mapping

- **Token Manipulation:**
  - `DuplicateTokenEx` - Duplicates token with impersonation - privilege escalation
  - `SetThreadToken` - Sets thread token - impersonation technique

- **Unhooking:**
  - `NtProtectVirtualMemory` - Changes memory protection - unhooking technique
  - `VirtualProtect` - Changes memory protection - unhooking technique
  - `VirtualProtectEx` - Changes memory protection in remote process - unhooking

- **Thread Manipulation:**
  - `QueueUserAPC` - Queues an APC to a thread - APC-based code injection
  - `SetThreadContext` - Manipulates thread context - code injection / hollowing primitive
  - `NtSetContextThread` - Direct syscall to change thread context - injection / hollowing primitive
  - `NtSetInformationThread` - Can be used to hide threads from debuggers

- **Persistence:**
  - `CreateServiceA` - Creates a Windows service - strong persistence indicator
  - `CreateServiceW` - Creates a Windows service (Unicode) - strong persistence
  - `ChangeServiceConfigA` - Changes service configuration - persistence / defense evasion
  - `StartServiceA` - Starts a service - service-based execution
  - `StartServiceW` - Starts a service (Unicode) - service-based execution
  - `ITaskScheduler` - Task Scheduler COM interface - scheduled task persistence
  - `SchRpcRegisterTask` - Registers a scheduled task - persistence mechanism
  - `IWbemServices` - WMI services interface - WMI event subscription persistence
  - `IWbemEventConsumerProvider` - WMI event consumer - WMI persistence mechanism

- **AMSI Bypass:**
  - `AmsiScanBuffer` - AMSI buffer scanning - target for AMSI bypass

- **Anti-Debug / Evasion:**
  - `NtQuerySystemInformation` - Queries system information - anti-debug / evasion

- **Credential Access:**
  - `CredEnumerateA` - Enumerates stored credentials - credential access
  - `CredEnumerateW` - Enumerates stored credentials (Unicode) - credential access
  - `CredReadA` - Reads stored credential - credential access
  - `CredReadW` - Reads stored credential (Unicode) - credential access
  - `SamEnumerateDomainsInSamServer` - Enumerates domains in SAM - credential access

#### MediumRisk APIs (40 APIs)
These APIs are potentially detectable or somewhat suspicious:

- **Token Manipulation:**
  - `OpenProcessToken` - Opens process token - privilege escalation indicator

- **Anti-Debugging:**
  - `IsDebuggerPresent` - Checks for debugger - anti-debugging technique
  - `CheckRemoteDebuggerPresent` - Checks for remote debugger - anti-debugging
  - `NtQueryInformationProcess` - Queries process information - anti-debugging
  - `OutputDebugStringA` - Sends string to debugger - often used in anti-debug logic
  - `QueryPerformanceCounter` - High-resolution performance counter - used in timing-based anti-debug
  - `SetUnhandledExceptionFilter` - Sets unhandled exception filter - anti-debug / evasion
  - `AddVectoredExceptionHandler` - Adds vectored exception handler - anti-debug / evasion
  - `NtQueryInformationThread` - Queries thread information - anti-debugging
  - `NtQueryObject` - Queries object information - anti-debug / evasion

- **Process Injection:**
  - `CreateFileMappingA` - Creates a file mapping object - used in section mapping
  - `CreateFileMappingW` - Creates a file mapping object (Unicode) - used in section mapping
  - `NtSuspendThread` - Suspends a thread - used in process hollowing
  - `SuspendThread` - Suspends a thread - used in process hollowing
  - `LoadLibraryA` - Loads a DLL - DLL injection technique
  - `LoadLibraryW` - Loads a DLL (Unicode) - DLL injection technique
  - `LoadLibraryExA` - Loads a DLL with extended options - DLL injection
  - `LoadLibraryExW` - Loads a DLL with extended options (Unicode) - DLL injection
  - `ReadProcessMemory` - Reads process memory - used in reconnaissance/injection
  - `FlushInstructionCache` - Flushes instruction cache - used after unhooking

- **Persistence:**
  - `RegSetValueExA` - Sets registry value - persistence indicator
  - `RegCreateKeyExA` - Creates registry key - potential persistence mechanism
  - `RegSetValueExW` - Sets registry value (Unicode) - persistence indicator
  - `RegCreateKeyExW` - Creates registry key (Unicode) - persistence mechanism
  - `RegDeleteValueA` - Deletes registry value - defense evasion / cleanup
  - `RegDeleteValueW` - Deletes registry value (Unicode) - defense evasion / cleanup
  - `OpenSCManagerA` - Opens Service Control Manager - potential service-based persistence
  - `OpenSCManagerW` - Opens Service Control Manager (Unicode) - service persistence
  - `DeleteService` - Deletes a service - cleanup / defense evasion
  - `SHGetSpecialFolderPathA` - Gets special folder path - used for startup folder persistence
  - `SHGetSpecialFolderPathW` - Gets special folder path (Unicode) - startup folder persistence
  - `CoCreateInstance` - Creates COM instance - used in COM hijacking persistence
  - `CoGetClassObject` - Gets COM class object - used in COM hijacking

- **AMSI:**
  - `AmsiInitialize` - AMSI initialization - AMSI bypass target

- **Discovery:**
  - `CreateToolhelp32Snapshot` - Creates process/thread snapshot - process enumeration
  - `Process32First` - Gets first process in snapshot - process enumeration
  - `Process32Next` - Gets next process in snapshot - process enumeration
  - `EnumProcesses` - Enumerates processes - process discovery
  - `EnumServicesStatusA` - Enumerates services - service discovery
  - `EnumServicesStatusW` - Enumerates services (Unicode) - service discovery

#### LowRisk APIs (41 APIs)
These APIs represent standard operations with relatively low detection concern:

- **Network Operations:**
  - `InternetOpenA` - Opens internet connection - network activity
  - `HttpOpenRequestA` - Opens HTTP request - network activity
  - `WinHttpConnect` - Connects via WinHTTP - network activity
  - `GetAdaptersInfo` - Gets network adapter information - network discovery
  - `GetAdaptersAddresses` - Gets network adapter addresses - network discovery
  - `GetIpNetTable` - Gets ARP table - network discovery
  - `NetGetAadJoinInformation` - Gets Azure AD join information - domain/network information query
  - `NetFreeAadJoinInformation` - Frees Azure AD join information buffer - standard cleanup function

- **File Operations:**
  - `CreateFileA` - Creates/opens file - file system access
  - `WriteFile` - Writes to file - file system access
  - `FindFirstFileA` - Finds first file matching pattern - file system discovery
  - `FindFirstFileW` - Finds first file matching pattern (Unicode) - file system discovery
  - `FindNextFileA` - Finds next file matching pattern - file system discovery
  - `FindNextFileW` - Finds next file matching pattern (Unicode) - file system discovery

- **Registry Operations:**
  - `RegOpenKeyExA` - Opens registry key - registry access
  - `RegOpenKeyExW` - Opens registry key (Unicode) - registry access
  - `RegEnumKeyExA` - Enumerates registry subkeys - registry discovery
  - `RegEnumKeyExW` - Enumerates registry subkeys (Unicode) - registry discovery
  - `RegEnumValueA` - Enumerates registry values - registry discovery
  - `RegEnumValueW` - Enumerates registry values (Unicode) - registry discovery

- **Anti-Debug / Timing:**
  - `GetTickCount` - Gets tick count - used in timing-based anti-debug
  - `GetTickCount64` - Gets tick count (64-bit) - used in timing-based anti-debug
  - `RaiseException` - Raises an exception - used in exception-based anti-debug
  - `NtQueryAttributesFile` - Queries file attributes - evasion / reconnaissance
  - `NtClose` - Closes a handle via syscall - common operation
  - `NtDelayExecution` - Delays execution via syscall - timing-based evasion
  - `NtWaitForSingleObject` - Waits for object via syscall - timing-based evasion

- **Standard Memory Management:**
  - `GetProcessHeap` - Gets handle to default process heap - standard memory management
  - `HeapAlloc` - Allocates memory from heap - standard memory management
  - `HeapFree` - Frees memory from heap - standard memory management

- **Standard C Runtime:**
  - `calloc` - Allocates and zero-initializes memory - standard C runtime function
  - `free` - Frees allocated memory - standard C runtime function
  - `vsnprintf` - Formats string with variable arguments - standard C runtime function
  - `wcschr` - Finds first occurrence of character in wide string - standard C runtime function
  - `wcsncpy_s` - Copies wide string with bounds checking - standard C runtime function

- **String Conversion:**
  - `WideCharToMultiByte` - Converts wide character string to multibyte string - standard string conversion

### Summary

- **Total Recognized APIs:** 125
- **CriticalRisk:** 9 APIs
- **HighRisk:** 35 APIs
- **MediumRisk:** 40 APIs
- **LowRisk:** 41 APIs

### Unknown APIs

Any API not found in the database is automatically classified as **MediumRisk** with a description format:
> `Unknown API: <API_NAME>`

This conservative approach ensures that unrecognized APIs are not ignored, but also not over-penalized. If you encounter APIs that should be recognized, they can be added to the database in future updates.

---

## Configurable Scoring Guide

### Overview

The configurable scoring system allows you to customize how OpSec scores are calculated by:

1. **Adjusting risk category weights**: Change how much each risk level (Low/Medium/High/Critical) affects the score
2. **Adjusting pattern weights**: Customize penalties for different suspicious patterns
3. **Adjusting combination weights**: Modify penalties for risky API combinations
4. **Whitelisting**: Exclude specific APIs, combinations, or patterns from scoring

### Profile File Format

Scoring profiles are stored as JSON files. Here's the structure:

```json
{
  "name": "my_custom_profile",
  "description": "Custom profile for my environment",
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
    "GetProcessHeap",
    "HeapAlloc"
  ],
  "whitelisted_combinations": [
    ["VirtualAlloc", "WriteProcessMemory"]
  ],
  "whitelisted_patterns": [
    "StringObfuscation"
  ]
}
```

### Profile Locations

Profiles are automatically loaded from:

- **Windows**: `%APPDATA%\RedBofAnalizer\profiles\`
- **Linux/macOS**: `~/.config/RedBofAnalizer/profiles/`

Place your JSON profile files in this directory, and they will be available in the GUI dropdown.

### Creating a Custom Profile

#### Example: Whitelisting Known-Safe Helper Functions

If you have a BOF that uses helper functions that are known to be safe in your environment, you can whitelist them:

```json
{
  "name": "my_helpers_whitelist",
  "description": "Profile that whitelists known-safe helper functions",
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
    "AnotherHelperFunction"
  ],
  "whitelisted_combinations": [],
  "whitelisted_patterns": []
}
```

#### Example: Aggressive EDR Profile

For environments with very aggressive EDR, you might want to increase penalties:

```json
{
  "name": "very_aggressive_edr",
  "description": "Strict profile for very aggressive EDR environments",
  "category_weights": {
    "low_risk": 3,
    "medium_risk": 10,
    "high_risk": 25,
    "critical_risk": 40
  },
  "pattern_weights": {
    "direct_syscall": 25,
    "process_injection": 35,
    "token_manipulation": 25,
    "unhooking": 25,
    "anti_debugging": 15,
    "string_obfuscation": 8,
    "high_entropy": 8,
    "suspicious_dll": 15,
    "network_activity": 8,
    "file_system_access": 8,
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

### Whitelisting

#### Whitelisting Individual APIs

Add API names to the `whitelisted_apis` array. Whitelisted APIs:
- Are still detected and shown in the API classifications table
- Do not contribute to the OpSec score
- Are still considered for combination detection (but the combination itself can be whitelisted)

Example:
```json
"whitelisted_apis": [
  "GetProcessHeap",
  "HeapAlloc",
  "HeapFree"
]
```

#### Whitelisting API Combinations

Add arrays of API names to `whitelisted_combinations`. All APIs in the combination must be present for it to match.

Example:
```json
"whitelisted_combinations": [
  ["VirtualAlloc", "WriteProcessMemory"],
  ["OpenProcessToken", "DuplicateTokenEx"]
]
```

#### Whitelisting Pattern Types

Add pattern type names to `whitelisted_patterns`. Available pattern types:
- `DirectSyscall`
- `ProcessInjection`
- `TokenManipulation`
- `Unhooking`
- `AntiDebugging`
- `StringObfuscation`
- `HighEntropy`
- `SuspiciousDll`
- `NetworkActivity`
- `FileSystemAccess`
- `Persistence`

Example:
```json
"whitelisted_patterns": [
  "StringObfuscation",
  "HighEntropy"
]
```

### Programmatic Profile Management

Profiles can also be managed programmatically using the `ProfileManager` API:

```rust
use redbofanalyzer::core::analyzer::opsec_config::{ProfileManager, ScoringProfiles};

// Create a profile manager
let mut manager = ProfileManager::with_default_profiles();

// Get a predefined profile
let aggressive_profile = ScoringProfiles::aggressive_edr();
manager.add_profile(aggressive_profile);

// Load a profile from file
let custom_profile = manager.load_profile_from_file(Path::new("my_profile.json"))?;
manager.add_profile(custom_profile);

// Set current profile
manager.set_current("my_custom_profile")?;

// Use in analysis
let profile = manager.current();
let analysis = analyze_api_opsec_with_bof(&imports, Some(&bof), Some(profile));
```

### Best Practices

1. **Start with a predefined profile**: Use `default`, `aggressive_edr`, `lab`, or `mature_soc` as a starting point
2. **Whitelist conservatively**: Only whitelist APIs/combinations you're certain are safe in your environment
3. **Document your profiles**: Include clear descriptions explaining why weights were chosen
4. **Test thoroughly**: Verify that profile changes produce expected results
5. **Version control**: Keep profile files in version control for reproducibility

### Troubleshooting

**Profile not appearing in dropdown:**
- Ensure the JSON file is valid
- Check that the file is in the correct profile directory
- Verify the `name` field matches the filename (without extension)

**Profile not affecting scores:**
- Ensure you've selected the profile in the GUI dropdown
- Check that the profile was loaded without errors (check console/logs)
- Verify weights are set correctly (non-zero values)

**Whitelisting not working:**
- Ensure API names match exactly (case-sensitive)
- For combinations, all APIs must be present in the BOF
- Pattern names must match exactly (see list above)

## Related Documentation

- **CLI OpSec / advanced analysis**: `ADVANCED_FEATURES.md` (Enhanced OpSec Analysis section)
- **General GUI overview**: `GUI_GUIDE.md`


