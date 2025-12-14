# RedBofAnalizer CLI Reference

Complete reference for all command-line options and commands.

## Global Options

These options apply to all commands:

- `--verbose` - Enable verbose output
- `--quiet` - Suppress non-error output
- `--help` - Show help message
- `--version` - Show version information
- `--gui` - Launch GUI mode (instead of CLI)

## Commands

### `analyze`

Analyze a BOF file and generate a detailed report.

#### Syntax

```bash
redbofanalyzer analyze <file> [OPTIONS]
```

#### Arguments

- `<file>` - Path to BOF file (.o or .obj)

#### Options

| Option | Description |
|--------|-------------|
| `--apis` | Show API usage (Beacon and Win32 APIs) |
| `--dependencies` | Show dependencies (required DLLs and functions) |
| `--security` | Show security assessment only |
| `--disasm` | Include disassembly (when implemented) |
| `--lints` | Show lint findings |
| `--format <format>` | Output format: `text`, `json`, `markdown` (default: `text`) |
| `--output <file>` | Write output to file (default: stdout) |
| `--verbose` | Verbose output |

#### Examples

```bash
# Basic analysis
redbofanalyzer analyze whoami.x64.o

# Full analysis with all details
redbofanalyzer analyze whoami.x64.o --apis --dependencies --security --lints

# Export to JSON
redbofanalyzer analyze whoami.x64.o --format json --output report.json

# Export to Markdown
redbofanalyzer analyze whoami.x64.o --format markdown --output report.md
```

#### Output Sections

The analysis report includes:

1. **Overview**
   - File path and size
   - Architecture (x64/x86)
   - Entry point information
   - Section count
   - Symbol count

2. **Sections**
   - Section name, size, entropy
   - Section characteristics/flags
   - Hex preview (optional)

3. **Symbols**
   - Symbol name and type
   - Section and address
   - External/internal classification

4. **APIs** (if `--apis` specified)
   - Beacon API usage
   - Win32 API usage with DLL names

5. **Dependencies** (if `--dependencies` specified)
   - Required DLLs
   - Required functions

6. **Security Assessment** (if `--security` specified)
   - Risk level (LOW, MEDIUM, HIGH)
   - Detected capabilities
   - OpSec score

7. **Lint Findings** (if `--lints` specified)
   - Lint rule violations
   - Severity and location
   - Suggestions

### `execute`

Execute a BOF file locally for testing.

#### Syntax

```bash
redbofanalyzer execute <file> [--args <arguments>] [OPTIONS]
```

#### Arguments

- `<file>` - Path to BOF file (.o or .obj)
- `--args <format>` - Arguments in format: `"z:string i:123 s:456"`

#### Options

| Option | Description |
|--------|-------------|
| `--args <format>` | Provide arguments (see Argument Format below) |
| `--sandbox` | Run in sandbox mode (restricted API access) |
| `--trace` | Verbose API call logging |
| `--timeout <seconds>` | Execution timeout (default: 30) |
| `--verbose` | Verbose output |

#### Argument Format

Arguments use type prefixes:

- `z:value` - ANSI string (null-terminated)
- `Z:value` - Wide string (UTF-16, null-terminated)
- `i:value` - 32-bit integer
- `s:value` - 16-bit integer (short)
- `b:hexdata` - Binary data (hex encoded)

Multiple arguments are space-separated.

#### Examples

```bash
# Execute without arguments
redbofanalyzer execute whoami.x64.o

# Execute with string argument
redbofanalyzer execute bof.o --args "z:C:\\Windows\\System32"

# Execute with multiple arguments
redbofanalyzer execute bof.o --args "z:test i:42 s:123"

# Execute in sandbox mode
redbofanalyzer execute bof.o --sandbox

# Execute with API tracing
redbofanalyzer execute bof.o --trace

# Execute with custom timeout
redbofanalyzer execute bof.o --timeout 60
```

#### Output

Execution output includes:

- Execution status (success/failure)
- BOF output (from BeaconPrintf, etc.)
- Execution time
- Error messages (if any)
- API calls (if `--trace` enabled)

### `test`

Batch test multiple BOFs in a directory.

#### Syntax

```bash
redbofanalyzer test <directory> [OPTIONS]
```

#### Arguments

- `<directory>` - Directory containing BOF files

#### Options

| Option | Description |
|--------|-------------|
| `--filter <pattern>` | Filter BOFs by pattern (e.g., `*.o`, `*x64.o`) |
| `--report <format>` | Report format: `text`, `json`, `markdown` (default: `text`) |
| `--output <file>` | Write report to file (default: stdout) |
| `--continue-on-error` | Continue testing even if some BOFs fail |
| `--verbose` | Verbose output |

#### Examples

```bash
# Test all BOFs in directory
redbofanalyzer test ./bofs/

# Test with filtering
redbofanalyzer test ./bofs/ --filter "*.x64.o"

# Generate JSON report
redbofanalyzer test ./bofs/ --report json --output results.json

# Generate Markdown report
redbofanalyzer test ./bofs/ --report markdown --output results.md

# Continue on errors
redbofanalyzer test ./bofs/ --continue-on-error
```

#### Report Format

The test report includes:

- Summary statistics (total, passed, failed)
- Per-file results:
  - File path
  - Status (success/failure/error)
  - Execution time
  - Error messages (if any)
  - Notes

### `validate`

Quickly validate a BOF file without full analysis.

#### Syntax

```bash
redbofanalyzer validate <file>
```

#### Arguments

- `<file>` - Path to BOF file (.o or .obj)

#### What It Checks

- COFF format validity
- Architecture (x64/x86)
- Entry point presence
- Required symbols
- Basic structure integrity

#### Examples

```bash
# Validate a single file
redbofanalyzer validate whoami.x64.o

# Validate multiple files (shell expansion)
redbofanalyzer validate *.o
```

#### Output

Validation output is brief:

- File path
- Validation status (valid/invalid)
- Issues found (if any)

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Invalid arguments
- `3` - File not found
- `4` - Parse error
- `5` - Execution error

## Environment Variables

- `RUST_LOG` - Set logging level (e.g., `debug`, `info`, `warn`, `error`)
- `RUST_BACKTRACE` - Enable backtraces (set to `1`)

## Examples

### Complete Workflow

```bash
# 1. Validate BOF
redbofanalyzer validate mybof.o

# 2. Analyze BOF
redbofanalyzer analyze mybof.o --apis --dependencies --security --output analysis.json

# 3. Execute BOF
redbofanalyzer execute mybof.o --args "z:test" --trace

# 4. Batch test directory
redbofanalyzer test ./bofs/ --report json --output test_results.json
```

### Scripting Examples

#### PowerShell

```powershell
# Analyze all BOFs and export to JSON
Get-ChildItem -Filter "*.o" | ForEach-Object {
    $output = $_.BaseName + ".json"
    redbofanalyzer analyze $_.FullName --format json --output $output
}
```

#### Bash

```bash
# Validate all BOFs
for file in *.o; do
    echo "Validating $file..."
    redbofanalyzer validate "$file"
done
```

## Tips

1. **Use `--format json` for programmatic processing**
2. **Use `--verbose` for debugging**
3. **Use `--sandbox` for untrusted BOFs**
4. **Use `--trace` to see what APIs a BOF calls**
5. **Use `--timeout` to prevent hanging executions**

## See Also

- [USER_GUIDE.md](USER_GUIDE.md) - Comprehensive user guide
- [README.md](../README.md) - Project overview

