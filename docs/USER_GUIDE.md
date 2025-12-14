# RedBofAnalizer User Guide

A comprehensive guide to using RedBofAnalizer for analyzing and executing Beacon Object Files (BOFs).

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [CLI Usage](#cli-usage)
4. [GUI Usage](#gui-usage)
5. [Examples](#examples)
6. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

- **Windows 10/11** (required for BOF execution features)
- **Rust 1.70+** (2021 edition)
- **Cargo** (comes with Rust)

### Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd RedBofAnalizer

# Build in release mode (recommended)
cargo build --release

# The executable will be at:
# target/release/redbofanalyzer.exe
```

### Build Options

```bash
# Debug build (faster compilation, slower execution)
cargo build

# Release build (optimized, recommended for use)
cargo build --release

# Check for compilation errors without building
cargo check
```

## Quick Start

### Analyze a BOF

```bash
# Basic analysis
redbofanalyzer analyze path/to/bof.o

# With detailed options
redbofanalyzer analyze path/to/bof.o --apis --dependencies --security
```

### Execute a BOF

```bash
# Execute without arguments
redbofanalyzer execute path/to/bof.o

# Execute with arguments
redbofanalyzer execute path/to/bof.o --args "z:test_string i:123"
```

### Launch GUI

```bash
# Launch GUI mode
redbofanalyzer --gui

# Or simply (defaults to GUI if no command specified)
redbofanalyzer
```

## CLI Usage

### Command Overview

RedBofAnalizer provides four main commands:

- `analyze` - Analyze a BOF file
- `execute` - Execute a BOF file
- `test` - Batch test multiple BOFs
- `validate` - Quick validation of a BOF

### Analyze Command

Analyze a BOF file to get detailed information about its structure, APIs, and security characteristics.

#### Basic Usage

```bash
redbofanalyzer analyze <file>
```

#### Options

- `--apis` - Show API usage (Beacon and Win32 APIs)
- `--dependencies` - Show dependencies (required DLLs and functions)
- `--security` - Show security assessment only
- `--disasm` - Include disassembly (when implemented)
- `--lints` - Show lint findings
- `--format <format>` - Output format: `text` (default), `json`, `markdown`
- `--output <file>` - Write output to file
- `--verbose` - Verbose output

#### Examples

```bash
# Basic analysis
redbofanalyzer analyze whoami.x64.o

# Analysis with all details
redbofanalyzer analyze whoami.x64.o --apis --dependencies --security

# Export to JSON
redbofanalyzer analyze whoami.x64.o --format json --output report.json

# Export to Markdown
redbofanalyzer analyze whoami.x64.o --format markdown --output report.md
```

### Execute Command

Execute a BOF file locally for testing and troubleshooting.

#### Basic Usage

```bash
redbofanalyzer execute <file> [--args <arguments>]
```

#### Options

- `--args <format>` - Provide arguments in format: `"z:string i:123 s:456"`
- `--sandbox` - Run in sandbox mode (restricted API access)
- `--trace` - Verbose API call logging
- `--timeout <seconds>` - Execution timeout (default: 30)
- `--verbose` - Verbose output

#### Argument Format

Arguments use the following format:
- `z:value` - ANSI string (null-terminated)
- `Z:value` - Wide string (UTF-16, null-terminated)
- `i:value` - 32-bit integer
- `s:value` - 16-bit integer (short)
- `b:hexdata` - Binary data (hex encoded)

#### Examples

```bash
# Execute without arguments
redbofanalyzer execute whoami.x64.o

# Execute with string argument
redbofanalyzer execute bof.o --args "z:C:\\Windows\\System32"

# Execute with multiple arguments
redbofanalyzer execute bof.o --args "z:test i:42 s:123"

# Execute in sandbox mode with tracing
redbofanalyzer execute bof.o --sandbox --trace

# Execute with timeout
redbofanalyzer execute bof.o --timeout 10
```

### Test Command

Batch test multiple BOFs in a directory.

#### Basic Usage

```bash
redbofanalyzer test <directory>
```

#### Options

- `--filter <pattern>` - Filter BOFs by pattern (e.g., `*.o`)
- `--report <format>` - Report format: `text` (default), `json`, `markdown`
- `--output <file>` - Write report to file
- `--continue-on-error` - Continue testing even if some BOFs fail

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
```

### Validate Command

Quickly validate a BOF file without full analysis.

#### Basic Usage

```bash
redbofanalyzer validate <file>
```

#### What It Checks

- COFF format validity
- Architecture (x64/x86)
- Entry point presence
- Required symbols

#### Examples

```bash
# Validate a BOF
redbofanalyzer validate whoami.x64.o

# Validate multiple files
redbofanalyzer validate *.o
```

## GUI Usage

### Launching the GUI

```bash
redbofanalyzer --gui
# or simply
redbofanalyzer
```

### Main Features

#### File Operations

- **Open File**: Use `File > Open` menu or drag-and-drop a BOF file
- **Reload**: Reload the current file with `File > Reload`

#### Tabs Overview

1. **Overview Tab**
   - File information summary
   - Quick statistics (sections, symbols, size)
   - Security assessment card
   - Capability detection

2. **Sections Tab**
   - Table view of all sections
   - Filter by name, size, or characteristics
   - Hex preview (collapsible)
   - Entropy calculation

3. **Symbols Tab**
   - Complete symbol table
   - Filter and search functionality
   - Symbol details (type, section, address)
   - Color-coded by symbol type

4. **Imports Tab**
   - Win32 API list with DLL names
   - Beacon API list
   - Dependency information

5. **Issues Tab (Lints)**
   - Lint findings with severity
   - Detailed messages and suggestions
   - Location information

6. **Disassembly Tab**
   - Instruction-level view
   - Color-coded instructions
   - Function detection

7. **Run Tab (Execution)**
   - Argument input with format help
   - Execute button
   - Execution options (sandbox, trace, timeout)
   - Output console with results

### Using the Execute Tab

1. **Load a BOF**: Open a BOF file first
2. **Enter Arguments** (optional):
   - Use format: `z:string i:123 s:456`
   - See format help in the UI
3. **Set Options**:
   - Enable sandbox mode for restricted execution
   - Enable trace for API call logging
   - Set timeout (seconds)
4. **Execute**: Click the "Execute" button
5. **View Results**: Output appears in the console below

## Examples

### Example 1: Analyze a Simple BOF

```bash
# Analyze whoami BOF
redbofanalyzer analyze ../src/bof_template/examples/whoami/whoami.x64.o

# Output shows:
# - File information
# - Sections (text, data, rdata, etc.)
# - Symbols (functions, imports)
# - API usage (Beacon APIs, Win32 APIs)
# - Security assessment
```

### Example 2: Execute a BOF with Arguments

```bash
# Execute a BOF that takes a string argument
redbofanalyzer execute mybof.o --args "z:C:\\Windows\\System32"

# Execute with multiple arguments
redbofanalyzer execute mybof.o --args "z:test i:42 s:123"
```

### Example 3: Batch Testing

```bash
# Test all BOFs in a directory
redbofanalyzer test ../src/CS-Situational-Awareness-BOF/SA/

# Generate a report
redbofanalyzer test ./bofs/ --report json --output test_results.json
```

### Example 4: Export Analysis Report

```bash
# Export to JSON for programmatic processing
redbofanalyzer analyze bof.o --format json --output analysis.json

# Export to Markdown for documentation
redbofanalyzer analyze bof.o --format markdown --output analysis.md
```

### Example 5: Using GUI for Interactive Analysis

1. Launch GUI: `redbofanalyzer --gui`
2. Open a BOF file via File menu or drag-and-drop
3. Navigate through tabs to explore:
   - Overview for quick summary
   - Sections for detailed section information
   - Symbols for function and import details
   - Imports for API usage
   - Issues for lint findings
   - Disassembly for code analysis
   - Run to execute the BOF

## Troubleshooting

### Common Issues

#### "Failed to parse BOF"

**Cause**: Invalid or corrupted COFF file

**Solutions**:
- Verify the file is a valid COFF object file (.o or .obj)
- Check if the file was compiled correctly
- Try recompiling the BOF source

#### "No entry point found"

**Cause**: BOF doesn't have a `go` function or entry point

**Solutions**:
- Verify the BOF has an entry point function named `go`
- Check if the BOF was compiled with the correct flags
- Some BOFs may use different entry point names

#### "Symbol resolution failed"

**Cause**: Missing Windows API or Beacon API

**Solutions**:
- Verify you're running on Windows (required for API resolution)
- Check if required DLLs are available
- Some BOFs may use APIs not available on your system

#### "BOF execution crashed"

**Cause**: BOF code has bugs or incompatible with execution environment

**Solutions**:
- Run with `--trace` to see API calls before crash
- Try `--sandbox` mode for safer execution
- Check BOF source code for issues
- Some BOFs may require specific environment setup

#### "Timeout exceeded"

**Cause**: BOF execution took too long

**Solutions**:
- Increase timeout: `--timeout 60`
- Check if BOF is waiting for input or network
- Some BOFs may have infinite loops

### Getting Help

- Check the [README.md](../README.md) for project overview
- Review [PLAN.md](../PLAN.md) for development status
- Check test files in `tests/` for usage examples
- Review error messages - they often contain helpful information

### Debug Mode

Enable verbose logging for debugging:

```bash
# Set environment variable
set RUST_LOG=debug

# Run with verbose output
redbofanalyzer analyze bof.o --verbose
```

### Performance Tips

- Use `--release` build for better performance
- For batch testing, use `--report json` for faster processing
- GUI may be slower for very large BOFs - use CLI for batch operations

## Advanced Usage

### Custom Output Formats

The tool supports multiple output formats:

- **Text** (default): Human-readable format
- **JSON**: Machine-readable, suitable for scripting
- **Markdown**: Documentation-friendly format

### Integration with Scripts

You can integrate RedBofAnalizer into scripts:

```bash
# Bash/PowerShell example
for file in *.o; do
    redbofanalyzer analyze "$file" --format json > "${file%.o}.json"
done
```

### CI/CD Integration

Use in CI/CD pipelines:

```bash
# Validate all BOFs
redbofanalyzer test ./bofs/ --report json --output results.json

# Check exit code
if [ $? -eq 0 ]; then
    echo "All BOFs validated successfully"
else
    echo "Some BOFs failed validation"
    exit 1
fi
```

## Best Practices

1. **Always validate before execution**: Use `validate` command first
2. **Use sandbox mode for untrusted BOFs**: `--sandbox` flag
3. **Export reports for documentation**: Use `--format markdown`
4. **Batch test regularly**: Use `test` command for regression testing
5. **Check lint findings**: Review `--lints` output for potential issues

## See Also

- [README.md](../README.md) - Project overview
- [PLAN.md](../PLAN.md) - Development plan and status
- [TESTING.md](../TESTING.md) - Testing information
- [tests/README.md](../tests/README.md) - Test suite documentation

