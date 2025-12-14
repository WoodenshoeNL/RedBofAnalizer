# Advanced Features Guide

This document describes the advanced analysis features available in RedBofAnalizer.

## Enhanced OpSec Analysis

### Overview

Enhanced OpSec analysis provides detailed operational security assessment by:
- Categorizing APIs by OpSec risk level
- Detecting risky API combinations
- Identifying suspicious patterns
- Calculating comprehensive OpSec scores

### Usage

```bash
# Enable enhanced OpSec analysis
redbofanalyzer analyze bof.o --opsec

# Or enable with security assessment
redbofanalyzer analyze bof.o --security --opsec
```

### API Categories

APIs are categorized into four risk levels:

- **Low Risk**: Standard operations (file access, network activity)
- **Medium Risk**: Potentially detectable (registry writes, anti-debugging)
- **High Risk**: Highly detectable (process injection, token manipulation)
- **Critical Risk**: Very likely to be detected (direct syscalls, unhooking)

### Risky API Combinations

The analyzer detects known risky API combinations:

1. **Process Injection Pattern**
   - `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
   - Risk: Critical
   - Description: Classic process injection technique

2. **Token Manipulation Pattern**
   - `OpenProcessToken` + `DuplicateTokenEx` + `SetThreadToken`
   - Risk: High
   - Description: Privilege escalation via token manipulation

3. **Unhooking Pattern**
   - `NtProtectVirtualMemory` + `NtWriteVirtualMemory`
   - Risk: High
   - Description: Unhooking technique to bypass API hooks

4. **Anti-Debugging Pattern**
   - `IsDebuggerPresent` + `CheckRemoteDebuggerPresent`
   - Risk: Medium
   - Description: Multiple anti-debugging checks

### Suspicious Patterns

The analyzer detects various suspicious patterns:

- **Direct Syscalls**: Bypasses API hooks but more detectable
- **Process Injection**: Highly detectable technique
- **Token Manipulation**: Privilege escalation indicator
- **Unhooking**: Bypass detection technique
- **Anti-Debugging**: Evasion technique

### OpSec Scoring

OpSec score (0-100, higher is better) is calculated based on:

- API risk categories (deducts 1-20 points per API)
- Risky combinations (deducts 5-25 points per combination)
- Suspicious patterns (deducts 3-20 points per pattern)
- Lint findings (deducts 2-15 points per finding)

### Recommendations

The analyzer provides actionable recommendations:

- Alternative techniques with better OpSec
- Specific API usage warnings
- Pattern-specific guidance
- General OpSec improvements

## Compatibility Analysis

### Overview

Compatibility analysis determines which Cobalt Strike versions a BOF is compatible with by:
- Detecting version-specific Beacon APIs
- Checking architecture requirements
- Identifying compatibility issues
- Providing version recommendations

### Usage

```bash
# Enable compatibility analysis
redbofanalyzer analyze bof.o --compatibility
```

### Cobalt Strike Versions

The analyzer checks compatibility with:

- **CS 4.0**: Base version
- **CS 4.1**: Added Format APIs
- **CS 4.2**: Added extended memory APIs
- **CS 4.3+**: Added syscall information APIs

### Version-Specific Features

#### CS 4.1+ Features
- `BeaconFormatAlloc`
- `BeaconFormatPrintf`
- `BeaconFormatToString`
- `BeaconFormatInt`

#### CS 4.2+ Features
- `BeaconVirtualAllocEx`
- `BeaconVirtualProtectEx`

#### CS 4.3+ Features
- `BeaconGetSyscallInformation`

### Compatibility Issues

Issues are categorized by severity:

- **Info**: Informational notes
- **Warning**: May cause issues in some versions
- **Error**: Will not work in affected versions

### Recommendations

The analyzer provides:
- Minimum required CS version
- Affected versions for each issue
- Specific recommendations for compatibility

## Calling Convention Analysis

### Overview

Calling convention analysis verifies that BOFs use the correct calling conventions for their architecture.

### Usage

```bash
# Enable calling convention analysis
redbofanalyzer analyze bof.o --calling-convention
```

### Supported Conventions

- **Microsoft x64**: Standard for Windows x64 (default)
- **System V AMD64**: Linux convention (not supported)
- **cdecl**: x86 convention (may cause issues on x64)
- **stdcall**: x86 Windows convention
- **fastcall**: x86 optimization convention

### Analysis Checks

- Entry point signature verification
- Calling convention mismatches
- Architecture-specific requirements

### Issues

Issues are reported with:
- Severity (Info, Warning, Error)
- Location (symbol, section)
- Expected vs detected convention
- Recommendations

## Combined Analysis

### Full Advanced Analysis

Enable all advanced features:

```bash
# All advanced features
redbofanalyzer analyze bof.o --security --opsec --compatibility --calling-convention
```

### Output

When advanced features are enabled, the output includes:

1. **Enhanced OpSec Analysis**
   - OpSec score
   - Risky API combinations
   - Suspicious patterns
   - Recommendations

2. **Compatibility Analysis**
   - Compatible CS versions
   - Version-specific features
   - Compatibility issues
   - Recommendations

3. **Calling Convention Analysis**
   - Detected convention
   - Issues found
   - Recommendations

## Examples

### Example 1: OpSec Analysis

```bash
redbofanalyzer analyze injection_bof.o --opsec

# Output shows:
# - OpSec Score: 45/100
# - Risky API Combinations:
#     [!] CRITICAL: Classic process injection pattern
#         APIs: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
#         Recommendation: Consider using alternative techniques...
# - Suspicious Patterns:
#     [!] HIGH: Process injection pattern detected
```

### Example 2: Compatibility Analysis

```bash
redbofanalyzer analyze modern_bof.o --compatibility

# Output shows:
# - Compatible with: CS 4.3+
# - Version-Specific Features:
#     - BeaconGetSyscallInformation (CS 4.3+)
# - Compatibility Issues:
#     [WARN] Uses BeaconGetSyscallInformation - requires CS 4.3+
#            (affects: CS 4.0, CS 4.1, CS 4.2)
#            Recommendation: Upgrade to CS 4.3+ or remove this API call
```

### Example 3: Full Analysis

```bash
redbofanalyzer analyze bof.o --security --opsec --compatibility --calling-convention

# Provides comprehensive analysis with all advanced features
```

## Integration with Security Assessment

Enhanced OpSec analysis is automatically integrated into the security assessment when `--security` is enabled. The OpSec score and findings are included in the standard security report.

## Best Practices

1. **Always run OpSec analysis** for BOFs that will be used in production
2. **Check compatibility** before deploying to ensure CS version support
3. **Review calling conventions** for cross-platform or mixed-architecture scenarios
4. **Follow recommendations** to improve OpSec characteristics
5. **Combine with linting** for comprehensive analysis

## See Also

- [USER_GUIDE.md](USER_GUIDE.md) - General usage guide
- [CLI_REFERENCE.md](CLI_REFERENCE.md) - Command reference
- [README.md](../README.md) - Project overview

