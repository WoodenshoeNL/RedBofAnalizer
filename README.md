# RedBofAnalizer

A comprehensive Beacon Object File (BOF) analyzer and execution tool written in Rust. This tool provides both command-line and GUI interfaces for analyzing, validating, and executing BOFs locally for testing and troubleshooting.

## Features

### ✅ Implemented Features

#### Core Functionality
- **COFF Parser**: Full parsing of COFF/PE object files
  - Header parsing with machine type detection (x64/x86)
  - Section parsing (.text, .data, .rdata, .bss, .pdata, .reloc)
  - Symbol table parsing (internal and external symbols)
  - Import extraction and entry point detection
  - Basic relocation processing

- **Memory Loader**: Safe memory management for BOF execution
  - Page-aligned memory allocation using VirtualAlloc
  - Section mapping with appropriate memory protections
  - Relocation application for proper address resolution

- **Symbol Resolution**: Complete symbol resolution system
  - Windows API resolution (LoadLibrary/GetProcAddress)
  - Beacon API stub registration
  - Import symbol parsing (`__imp_LIBRARY$Function` format)

- **Beacon API Emulation**: Comprehensive Beacon API implementation
  - Output APIs: `BeaconPrintf`, `BeaconOutput`
  - Data Parsing APIs: `BeaconDataParse`, `BeaconDataInt`, `BeaconDataShort`, `BeaconDataLength`, `BeaconDataExtract`
  - Token APIs: `BeaconUseToken`, `BeaconRevertToken`, `BeaconIsAdmin`
  - Process APIs: `BeaconSpawnTemporaryProcess`, `BeaconInjectProcess`, `BeaconInjectTemporaryProcess`, `BeaconCleanupProcess`
  - Format APIs: `BeaconFormatAlloc`, `BeaconFormatReset`, `BeaconFormatFree`, `BeaconFormatAppend`, `BeaconFormatPrintf`, `BeaconFormatToString`, `BeaconFormatInt`
  - Memory APIs: `BeaconVirtualAlloc`, `BeaconVirtualFree`

- **Execution Engine**: Full BOF execution capabilities
  - BOF loading and execution
  - Argument parsing and packing (z, Z, i, s, b types)
  - Output capture and formatting
  - Sandbox mode for safe execution
  - Execution tracing and API call logging
  - Timeout handling

#### CLI Interface
- **Analyze Command**: Comprehensive BOF analysis
  - File information and overview
  - Section details with entropy calculation
  - Symbol table with filtering
  - API usage detection (Beacon and Win32 APIs)
  - Dependency analysis
  - Security assessment (basic)
  - Multiple output formats (text, JSON, Markdown)

- **Execute Command**: Execute BOFs with full control
  - Argument passing via command line
  - Sandbox mode for restricted execution
  - Verbose tracing of API calls
  - Configurable timeout
  - Output capture and display

- **Test Command**: Batch testing of multiple BOFs
  - Recursive directory scanning
  - File pattern matching (*.o, *.obj)
  - Filter options
  - Batch execution with error handling
  - Comprehensive reporting (text, JSON, Markdown)
  - Continue on errors option

- **Validate Command**: Quick BOF validation
  - Architecture validation
  - Entry point validation
  - Required symbol checks

#### Analysis Features
- **Static Analysis**: Basic analysis engine
  - API detection and categorization
  - Dependency extraction
  - Basic security assessment
  - Risk level calculation

- **Output Formatting**: Multiple output formats
  - Human-readable text format
  - Machine-readable JSON format
  - Markdown format for documentation

### 🟡 Partially Implemented

- **BeaconPrintf**: Basic implementation exists, but full variadic argument support needs enhancement
- **Relocation Processing**: Basic implementation done, but some relocation types (REL32_1-5, ADDR32NB, SECREL) need implementation
- **Security Assessment**: Basic risk level calculation done, but capability detection and OpSec analysis pending
- **Disassembly**: Structure exists but Capstone integration not yet implemented

### ❌ Not Yet Implemented

- **Linting System**: Structure exists but lint rules not implemented
- **GUI Interface**: Stub exists, full egui implementation pending
- **Advanced Analysis**: OpSec analysis, YARA integration, enhanced security features
- **Unit Tests**: Test suite not yet created
- **Documentation**: User guide and API reference pending

## Installation

### Prerequisites

- Rust 1.70+ (2021 edition)
- Windows 10/11 (for execution features)
- Cargo (comes with Rust)

### Build

```bash
# Clone the repository
git clone <repository-url>
cd RedBofAnalizer

# Build in debug mode
cargo build

# Build in release mode
cargo build --release
```

The executable will be located at:
- Debug: `target/debug/redbofanalyzer.exe`
- Release: `target/release/redbofanalyzer.exe`

## Usage

### CLI Mode

#### Analyze a BOF

```bash
# Basic analysis
redbofanalyzer analyze path/to/bof.o

# With options
redbofanalyzer analyze path/to/bof.o --apis --dependencies --security

# Output to file
redbofanalyzer analyze path/to/bof.o --output report.json --format json
```

#### Execute a BOF

```bash
# Execute without arguments
redbofanalyzer execute path/to/bof.o

# Execute with arguments
redbofanalyzer execute path/to/bof.o --args "z:test_string i:123"

# Execute in sandbox mode with tracing
redbofanalyzer execute path/to/bof.o --sandbox --trace --timeout 10
```

#### Test Multiple BOFs

```bash
# Test all BOFs in a directory
redbofanalyzer test path/to/bofs/

# With filtering and reporting
redbofanalyzer test path/to/bofs/ --filter "*.o" --report markdown --output test_results.md
```

#### Validate a BOF

```bash
redbofanalyzer validate path/to/bof.o
```

### GUI Mode

```bash
# Launch GUI (not yet implemented)
redbofanalyzer --gui

# Or simply
redbofanalyzer
```

## Project Status

### Current Progress

**Phase 1 (Foundation)**: ✅ **~95% Complete**
- Project setup: ✅ Complete
- COFF parser: ✅ Complete (relocations need enhancement)
- BOF models: ✅ Complete
- Memory loader: ✅ Complete
- Symbol resolution: ✅ Complete
- Beacon API emulation: ✅ Mostly complete (BeaconPrintf needs variadic args)

**Phase 2 (Analysis)**: 🟡 **~40% Complete**
- Static analysis engine: ✅ Basic implementation
- Linting system: ❌ Not started
- Disassembly support: ❌ Not started

**Phase 3 (Execution Enhancement)**: ✅ **~90% Complete**
- Complete Beacon API: ✅ Mostly complete
- Argument handling: ✅ Complete
- Execution options: ✅ Complete

**Phase 4 (CLI Interface)**: ✅ **100% Complete**
- All commands implemented
- All output formats working

**Phase 5 (GUI Interface)**: ✅ **90% Complete**
- Full egui-based GUI with dark theme
- All main tabs implemented (Overview, Sections, Symbols, Imports, Lints, Disassembly, Execute)
- File loading via menu and drag-drop
- Async analysis with progress indicator

**Phase 6-8 (Advanced Features, Testing, Documentation)**: ❌ **Not Started**

### Overall Progress: ~80% Complete

## Architecture

```
RedBofAnalizer
├── CLI Mode (clap)
├── GUI Mode (egui) - ✅ Implemented
└── Core Library
    ├── Parser (COFF/PE parsing)
    ├── Analyzer (Static analysis + linting)
    ├── Executor (BOF execution engine)
    ├── Models (Data structures)
    └── Utils (Disassembly, entropy, etc.)
```

## Development

### Project Structure

```
RedBofAnalizer/
├── src/
│   ├── main.rs              # Entry point
│   ├── lib.rs               # Library root
│   ├── cli/                 # CLI interface
│   ├── gui/                 # GUI interface (stub)
│   └── core/                # Core library
│       ├── parser/          # COFF parsing
│       ├── analyzer/        # Static analysis
│       ├── executor/         # Execution engine
│       ├── models/           # Data structures
│       └── utils/            # Utilities
├── Cargo.toml
├── PLAN.md                  # Development plan
└── README.md                # This file
```

### Building

```bash
# Check for compilation errors
cargo check

# Build
cargo build

# Run tests (when implemented)
cargo test

# Run with verbose logging
RUST_LOG=debug cargo run -- analyze path/to/bof.o
```

## Next Steps

Based on the current progress, the recommended next steps are:

1. **Implement Linting System (Phase 2.2)**
   - Implement lint rules (BOF001-BOF008)
   - Add severity levels and location tracking
   - Integrate with analysis command

2. **Enhance Relocation Processing (Phase 1.2.4)**
   - Implement remaining relocation types
   - Improve address calculation

3. **Complete BeaconPrintf (Phase 1.6)**
   - Implement full variadic argument support
   - Add C wrapper if needed

4. **Implement Disassembly Support (Phase 2.3)**
   - Integrate Capstone disassembler
   - Add disassembly view to analysis

5. **Start GUI Implementation (Phase 5)**
   - Set up egui framework
   - Implement main window and navigation
   - Create overview and sections tabs

6. **Create Test Suite (Phase 7)**
   - Unit tests for parser, executor, analyzer
   - Integration tests with real BOFs
   - Regression test suite

## Contributing

Contributions are welcome! Please see the development plan in `PLAN.md` for areas that need work.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- Built with Rust and the `object` crate for COFF parsing
- Inspired by the need for better BOF testing and analysis tools
- Designed to complement existing BOF development workflows
