# Cobalt Strike Compatible Argument Mode - Implementation Plan

## Overview

Add a feature to support Cobalt Strike's argument passing format, which differs from the standard Beacon packed format for simple cases. This will allow the tool to execute BOFs from the official Cobalt Strike repository without modification.

## Problem Statement

The official Cobalt Strike `helloWorld` BOF example expects arguments to be passed as a simple null-terminated string directly in the `args` buffer, rather than in the packed Beacon format (length-prefixed). 

**Current behavior:**
- Tool packs arguments: `z:test` → `[4-byte length][t][e][s][t][\0]` (9 bytes total)
- BOF expects: `[t][e][s][t][\0]` (5 bytes total)

**Cobalt Strike behavior:**
- For simple string arguments, passes them as null-terminated strings directly
- For complex arguments, uses `bof_pack()` which creates packed format

## Solution

Add a "Cobalt Strike Compatible" mode that:
1. Detects simple argument cases (single string argument)
2. Passes arguments as null-terminated strings directly (not packed)
3. Falls back to packed format for complex arguments or when explicitly needed

## Implementation Plan

### Phase 1: Argument Parser Enhancement

**File:** `RedBofAnalizer/src/core/executor/arguments.rs`

#### 1.1 Add Compatibility Mode Enum
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentMode {
    /// Standard Beacon format (packed with length prefixes)
    Standard,
    /// Cobalt Strike compatible (simple strings as null-terminated)
    CobaltStrike,
}
```

#### 1.2 Add Cobalt Strike Compatible Parsing Function
```rust
/// Parse arguments in Cobalt Strike compatible mode
/// 
/// For simple cases (single string argument), passes as null-terminated string
/// For complex cases, falls back to standard packed format
pub fn parse_arguments_cs_compat(arg_str: &str) -> Result<Vec<u8>> {
    if arg_str.is_empty() {
        return Ok(Vec::new());
    }
    
    // Check if it's a simple case: single string argument without type prefix
    // Examples: "test", "hello world", "C:\\Windows"
    if !arg_str.contains(':') && !arg_str.contains(' ') {
        // Simple string - pass as null-terminated
        let mut buffer = Vec::new();
        buffer.extend_from_slice(arg_str.as_bytes());
        buffer.push(0); // Null terminator
        return Ok(buffer);
    }
    
    // Check if it's a single typed string argument
    // Examples: "z:test", "Z:hello"
    let parts: Vec<&str> = arg_str.split_whitespace().collect();
    if parts.len() == 1 {
        if let Some((type_char, value)) = parts[0].split_once(':') {
            match type_char {
                "z" => {
                    // ANSI string - pass as null-terminated (CS compatible)
                    let mut buffer = Vec::new();
                    buffer.extend_from_slice(value.as_bytes());
                    buffer.push(0);
                    return Ok(buffer);
                }
                "Z" => {
                    // Wide string - pass as null-terminated UTF-16LE
                    let utf16: Vec<u16> = value.encode_utf16().collect();
                    let mut buffer: Vec<u8> = utf16.iter()
                        .flat_map(|&c| c.to_le_bytes())
                        .collect();
                    buffer.extend_from_slice(&[0u8, 0u8]); // Null terminator
                    return Ok(buffer);
                }
                _ => {
                    // Other types (i, s, b) - use standard packed format
                    return parse_arguments(arg_str);
                }
            }
        }
    }
    
    // Multiple arguments or complex format - use standard packed format
    parse_arguments(arg_str)
}
```

#### 1.3 Update Main Parse Function to Support Mode
```rust
/// Parse arguments with specified mode
pub fn parse_arguments_with_mode(arg_str: &str, mode: ArgumentMode) -> Result<Vec<u8>> {
    match mode {
        ArgumentMode::Standard => parse_arguments(arg_str),
        ArgumentMode::CobaltStrike => parse_arguments_cs_compat(arg_str),
    }
}
```

### Phase 2: GUI Integration

**File:** `RedBofAnalizer/src/gui/app.rs`

#### 2.1 Add State Variable
```rust
pub struct App {
    // ... existing fields ...
    pub execution_cs_compat: bool,  // Cobalt Strike compatible mode
}
```

#### 2.2 Update GUI Layout
In `render_execute_tab()`, add checkbox after "Options:" section:

```rust
ui.label("Options:");
ui.horizontal(|ui| {
    ui.checkbox(&mut self.execution_sandbox, "Sandbox");
    ui.checkbox(&mut self.execution_trace, "Trace API calls");
    ui.checkbox(&mut self.execution_cs_compat, "Cobalt Strike Compatible");
});
```

#### 2.3 Add Help Text
Add tooltip or help text explaining the mode:
```rust
if self.execution_cs_compat {
    ui.label(RichText::new("ℹ️ CS Compatible: Simple string arguments will be passed as null-terminated strings (like Cobalt Strike)")
        .small()
        .color(Colors::TEXT_MUTED));
}
```

#### 2.4 Update Execution Logic
In `execute_bof()`:
```rust
let args_result = if self.execution_args.is_empty() {
    Ok(Vec::new())
} else {
    let mode = if self.execution_cs_compat {
        executor::arguments::ArgumentMode::CobaltStrike
    } else {
        executor::arguments::ArgumentMode::Standard
    };
    executor::arguments::parse_arguments_with_mode(&self.execution_args, mode)
};
```

### Phase 3: CLI Integration

**File:** `RedBofAnalizer/src/cli/commands.rs`

#### 3.1 Add CLI Flag
Add to argument parser:
```rust
.arg(
    Arg::new("cs-compat")
        .long("cs-compat")
        .help("Use Cobalt Strike compatible argument format (simple strings as null-terminated)")
)
```

#### 3.2 Update Execution
```rust
let mode = if matches.get_flag("cs-compat") {
    executor::arguments::ArgumentMode::CobaltStrike
} else {
    executor::arguments::ArgumentMode::Standard
};

let args = if let Some(arg_str) = matches.get_one::<String>("args") {
    executor::arguments::parse_arguments_with_mode(arg_str, mode)?
} else {
    Vec::new()
};
```

### Phase 4: Testing

#### 4.1 Test Cases

**Test 1: Simple string (CS Compatible)**
- Input: `"test"`
- Expected: `[t][e][s][t][\0]` (5 bytes)
- BOF: `hello.x64.o` should print "Hello World: test"

**Test 2: Typed string (CS Compatible)**
- Input: `"z:test"`
- Expected: `[t][e][s][t][\0]` (5 bytes)
- BOF: `hello.x64.o` should print "Hello World: test"

**Test 3: Wide string (CS Compatible)**
- Input: `"Z:test"`
- Expected: UTF-16LE null-terminated
- BOF: Should handle wide strings correctly

**Test 4: Multiple arguments (CS Compatible)**
- Input: `"z:test i:123"`
- Expected: Falls back to standard packed format
- BOF: Should parse correctly

**Test 5: Standard mode (unchanged)**
- Input: `"z:test"`
- Expected: `[4-byte length][t][e][s][t][\0]` (9 bytes)
- BOF: Should work with BOFs expecting packed format

#### 4.2 Test BOFs
- `hello.x64.o` from official CS repo (should work with CS Compatible mode)
- Other BOFs from CS repo that expect simple string arguments
- Complex BOFs that need packed format (should work with Standard mode)

### Phase 5: Documentation

#### 5.1 Update README
Add section explaining the two modes:
- Standard mode: Full Beacon packed format (default)
- CS Compatible mode: Simple strings as null-terminated (for CS repo BOFs)

#### 5.2 Update GUI Help
Update "Argument Format Help" to mention CS Compatible mode:
- When enabled, simple string arguments are passed differently
- Use for BOFs from official Cobalt Strike repository

## Implementation Order

1. **Phase 1** - Core argument parsing logic (backend)
2. **Phase 2** - GUI integration (user-facing)
3. **Phase 3** - CLI integration (optional, for completeness)
4. **Phase 4** - Testing with real BOFs
5. **Phase 5** - Documentation updates

## Edge Cases to Handle

1. **Empty arguments**: Should return empty buffer in both modes
2. **Whitespace in strings**: CS Compatible should preserve whitespace
3. **Special characters**: Both modes should handle correctly
4. **Mixed arguments**: CS Compatible should detect and fall back to standard
5. **Integer arguments**: CS Compatible should use standard format for non-strings

## Future Enhancements

1. **Auto-detection**: Automatically detect if BOF needs CS Compatible mode
2. **Per-BOF settings**: Save compatibility mode preference per BOF
3. **Format detection**: Analyze BOF code to determine expected format
4. **Warning system**: Warn when wrong mode is used

## Notes

- CS Compatible mode is primarily for backward compatibility with simple BOFs
- Most modern BOFs use the standard packed format
- The mode can be toggled per execution, allowing flexibility
- Default remains Standard mode to maintain compatibility with most BOFs

