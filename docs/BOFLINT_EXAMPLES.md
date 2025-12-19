# BOF Lint Examples - New Rules (BOF009-BOF012)

This document demonstrates the new lint rules added to RedBofAnalizer that mirror the validation rules from `boflint.py`. These rules help ensure BOF compatibility and catch common issues.

## Overview of New Rules

- **BOF009**: Undefined symbols detection (stack checks, exception handlers, CRT functions)
- **BOF010**: Unexpected relocation types
- **BOF011**: Loader-unfriendly sections (.bss, .rdata, .pdata)
- **BOF012**: Beacon API import whitelist enforcement

## CLI Usage

### Basic Analysis with Lints

```bash
# Analyze a BOF file with all lints enabled (default)
redbofanalyzer analyze example.o --lints

# Analyze with specific output format
redbofanalyzer analyze example.o --lints --format json

# Analyze and save report
redbofanalyzer analyze example.o --lints --output report.json --format json
```

### Example Output

When you run analysis with lints enabled, you'll see findings like this:

```
=== Lint Findings ===

[ERROR] BOF009: Stack check function detected: ___chkstk_ms
  Location: symbol=___chkstk_ms, section=None, address=0x00000000
  Explanation: Symbol '___chkstk_ms' is a stack check function. You may have a stack variable that is too large. Disable stack protections or reduce stack usage.
  Suggestion: Disable stack protections (/GS- flag) or reduce stack variable sizes.

[WARN] BOF010: Found 3 unknown relocation type(s)
  Location: section=.text, address=None
  Explanation: Found 3 relocation(s) with unknown/unsupported types (first unknown type: 0x0015). Some BOF loaders may not support non-standard relocation types.
  Suggestion: Review your toolchain and linker flags. Ensure you're using standard relocation types (REL32, ADDR32, ADDR64).

[WARN] BOF011: Section '.bss' contains data
  Location: section=.bss, address=None
  Explanation: Section '.bss' has non-zero size (raw_size=1024, virtual_size=1024). Not all BOF loaders support uninitialized data sections.
  Suggestion: Consider initializing variables or using .data section instead. Some loaders may ignore .bss sections.

[ERROR] BOF012: Imported symbol 'BeaconInvalidAPI' is not a recognized Beacon/loader API
  Location: symbol=__imp_BeaconInvalidAPI, section=None, address=None
  Explanation: The function 'BeaconInvalidAPI' is imported from 'Beacon' library but is not in the whitelist of recognized Beacon/loader APIs. This may cause runtime errors.
  Suggestion: Verify the API name is correct. If this is a custom function, ensure it's imported from the correct library (e.g., KERNEL32, msvcrt) rather than Beacon.
```

## Code Examples

### Example 1: Using the Analyzer Programmatically

```rust
use redbofanalyzer::core;

fn main() -> anyhow::Result<()> {
    // Load a BOF file
    let bof = core::parser::load_bof("example.o")?;
    
    // Run all lints
    let lint_findings = core::analyzer::linter::run_lints(&bof);
    
    // Filter by new rules
    let new_rules = lint_findings.iter()
        .filter(|f| f.code.starts_with("BOF009") || 
                    f.code.starts_with("BOF010") || 
                    f.code.starts_with("BOF011") || 
                    f.code.starts_with("BOF012"))
        .collect::<Vec<_>>();
    
    println!("Found {} issues from new lint rules:", new_rules.len());
    for finding in new_rules {
        println!("[{}] {}: {}", 
            match finding.severity {
                core::models::lint::Severity::Error => "ERROR",
                core::models::lint::Severity::Warning => "WARN",
                core::models::lint::Severity::Info => "INFO",
            },
            finding.code,
            finding.message
        );
        if let Some(ref suggestion) = finding.suggestion {
            println!("  → {}", suggestion);
        }
    }
    
    Ok(())
}
```

### Example 2: Filtering Specific Lint Types

```rust
use redbofanalyzer::core::analyzer::linter;
use redbofanalyzer::core::models::lint::Severity;

fn check_undefined_symbols(bof: &core::models::bof::BofFile) {
    let findings = linter::run_lints(bof);
    
    // Get only undefined symbol errors (BOF009)
    let undefined_symbols = findings.iter()
        .filter(|f| f.code == "BOF009" && f.severity == Severity::Error)
        .collect::<Vec<_>>();
    
    if !undefined_symbols.is_empty() {
        println!("⚠️  Found {} undefined symbol(s):", undefined_symbols.len());
        for finding in undefined_symbols {
            if let Some(ref sym) = finding.location.symbol {
                println!("  - {}", sym);
            }
        }
    }
}

fn check_beacon_imports(bof: &core::models::bof::BofFile) {
    let findings = linter::run_lints(bof);
    
    // Get only Beacon import whitelist violations (BOF012)
    let invalid_beacon_imports = findings.iter()
        .filter(|f| f.code == "BOF012")
        .collect::<Vec<_>>();
    
    if !invalid_beacon_imports.is_empty() {
        println!("❌ Found {} invalid Beacon import(s):", invalid_beacon_imports.len());
        for finding in invalid_beacon_imports {
            println!("  - {}", finding.message);
            if let Some(ref suggestion) = finding.suggestion {
                println!("    Fix: {}", suggestion);
            }
        }
    }
}
```

## Detailed Rule Examples

### BOF009: Undefined Symbols

**What it detects:**
- Stack check functions: `___chkstk_ms`, `__chkstk`, `__stack_chk_fail`, `__security_init_cookie`
- Exception handling: `__C_specific_handler`, `__cxa_begin_catch`, `except_handler*`, `CxxFrameHandler*`
- CRT memory functions: `memset`, `memmove`, `memcpy`
- Any other undefined symbols

**Example scenarios:**

```c
// This will trigger BOF009 ERROR for ___chkstk_ms
void go(char* args, int len) {
    char large_buffer[8192];  // Large stack allocation triggers stack check
    // ...
}

// This will trigger BOF009 ERROR for __stack_chk_fail
// (if compiled with /GS stack protection)
void vulnerable_function() {
    char buffer[256];
    // Potential buffer overflow triggers security cookie check
}

// This will trigger BOF009 WARN for __C_specific_handler
// (if using C++ exception handling)
void cpp_function() {
    try {
        // ...
    } catch (...) {
        // ...
    }
}

// This will trigger BOF009 ERROR for undefined_function
// (if function is declared but not defined)
extern void undefined_function();
void go(char* args, int len) {
    undefined_function();  // Linker error, but lint catches it early
}
```

### BOF010: Unexpected Relocation Types

**What it detects:**
- Relocations that couldn't be normalized to standard types (REL32, ADDR32, ADDR64)
- Non-standard relocation types that some loaders may not support

**Example scenarios:**

```c
// If your linker produces non-standard relocations, you'll see:
// [WARN] BOF010: Found N unknown relocation type(s)

// Common causes:
// - Using unusual linker flags
// - Custom linker scripts
// - Unsupported architecture-specific relocations
```

**How to fix:**
- Use standard linker flags for COFF object files
- Avoid custom linker scripts that introduce non-standard relocations
- Ensure you're targeting x86 or x64 (not ARM, etc.)

### BOF011: Loader-Unfriendly Sections

**What it detects:**
- `.bss` sections with data (uninitialized data)
- `.rdata` sections with data (read-only data)
- `.pdata` sections with data (exception handling metadata)

**Example scenarios:**

```c
// This will trigger BOF011 WARN for .bss
int uninitialized_array[1024];  // Goes to .bss

// This will trigger BOF011 WARN for .rdata
const char* read_only_string = "Hello, World!";  // Goes to .rdata

// This will trigger BOF011 WARN for .pdata (if using C++ exceptions)
void cpp_function_with_exceptions() {
    try {
        // ...
    } catch (...) {
        // ...
    }
}
```

**How to fix:**
- For `.bss`: Initialize variables or use `.data` section
- For `.rdata`: Some loaders ignore read-only data; consider if it's necessary
- For `.pdata`: Avoid C++ exception handling in BOFs (use C or disable exceptions)

### BOF012: Beacon API Import Whitelist

**What it detects:**
- Functions imported from "Beacon" library that aren't in the whitelist
- Typos in Beacon API names
- Custom functions mistakenly imported as Beacon APIs

**Example scenarios:**

```c
// This will trigger BOF012 ERROR
// (if you typo the API name)
extern void BeaconDataParce(void* parser, char* buffer, int len);  // Typo: Parce vs Parse

// This will trigger BOF012 ERROR
// (if you import a non-Beacon function as Beacon)
extern void MyCustomFunction(void);  // Not a Beacon API

// Valid Beacon imports (won't trigger BOF012):
extern void BeaconDataParse(void* parser, char* buffer, int len);
extern void BeaconPrintf(int type, char* fmt, ...);
extern void BeaconOutput(int type, char* data, int len);
```

**Whitelisted Beacon APIs include:**
- All `BeaconData*` functions (Parse, Int, Short, Extract, etc.)
- All `BeaconFormat*` functions (Alloc, Reset, Append, Printf, etc.)
- All `Beacon*` output functions (Printf, Output)
- Token functions (BeaconUseToken, BeaconRevertToken, BeaconIsAdmin)
- Process functions (BeaconInjectProcess, BeaconSpawnTemporaryProcess, etc.)
- Memory functions (BeaconVirtualAlloc, BeaconVirtualFree, etc.)
- Standard OS helpers (GetProcAddress, GetModuleHandleA/W, LoadLibraryA/W, FreeLibrary)

## Integration with Full Analysis

When running full analysis, the new lints are automatically included:

```rust
use redbofanalyzer::core;

let bof = core::parser::load_bof("example.o")?;
let report = core::analyzer::analyze(
    &bof,
    false,  // security
    false,  // disasm
    true,   // apis
    true,   // dependencies
    true,   // lints ← enables all lints including BOF009-BOF012
    false,  // relocs
    &[],    // yara_rules
    true,   // use_default_rules
)?;

// Access lint findings
for finding in &report.lints {
    if finding.code.starts_with("BOF009") {
        println!("Undefined symbol issue: {}", finding.message);
    }
}
```

## JSON Output Example

When using `--format json`, lint findings are structured like this:

```json
{
  "lints": [
    {
      "code": "BOF009",
      "severity": "Error",
      "message": "Stack check function detected: ___chkstk_ms",
      "location": {
        "symbol": "___chkstk_ms",
        "section": null,
        "address": null,
        "line": null
      },
      "explanation": "Symbol '___chkstk_ms' is a stack check function...",
      "suggestion": "Disable stack protections (/GS- flag)..."
    },
    {
      "code": "BOF012",
      "severity": "Error",
      "message": "Imported symbol 'BeaconInvalidAPI' is not a recognized Beacon/loader API",
      "location": {
        "symbol": "__imp_BeaconInvalidAPI",
        "section": null,
        "address": null,
        "line": null
      },
      "explanation": "The function 'BeaconInvalidAPI' is imported from 'Beacon' library...",
      "suggestion": "Verify the API name is correct..."
    }
  ]
}
```

## Summary

The new lint rules (BOF009-BOF012) help catch compatibility issues early:

- **BOF009**: Prevents undefined symbol linker errors
- **BOF010**: Ensures standard relocation types for loader compatibility
- **BOF011**: Warns about sections some loaders can't handle
- **BOF012**: Enforces correct Beacon API usage

These rules complement the existing lints (BOF001-BOF008) to provide comprehensive BOF validation similar to `boflint.py`.

