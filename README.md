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

### ✅ Recently Completed

- **Testing Suite**: Comprehensive test coverage
  - Unit tests for argument parsing, Beacon API, symbol resolution
  - Integration tests for BOF execution and analysis
  - Parser, analyzer, and executor tests
  - All tests passing

### ✅ Recently Completed

- **User Documentation**: ✅ Complete
  - Installation guide
  - Comprehensive user guide with examples
  - CLI reference
  - GUI guide

### ❌ Not Yet Implemented

- **Advanced Analysis**: OpSec analysis, YARA integration, enhanced security features
- **Developer Documentation**: Architecture overview, API documentation, contributing guide

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

## Quick Start

### Installation

See [INSTALLATION.md](docs/INSTALLATION.md) for detailed installation instructions.

```bash
# Build from source
cargo build --release

# Executable will be at: target/release/redbofanalyzer.exe
```

### Basic Usage

#### Analyze a BOF

```bash
# Basic analysis
redbofanalyzer analyze path/to/bof.o

# Full analysis with all details
redbofanalyzer analyze path/to/bof.o --apis --dependencies --security --lints
```

#### Execute a BOF

```bash
# Execute without arguments
redbofanalyzer execute path/to/bof.o

# Execute with arguments
redbofanalyzer execute path/to/bof.o --args "z:test_string i:123"
```

#### Launch GUI

```bash
# Launch GUI mode
redbofanalyzer --gui

# Or simply (defaults to GUI)
redbofanalyzer
```

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[USER_GUIDE.md](docs/USER_GUIDE.md)** - Complete user guide with examples
- **[CLI_REFERENCE.md](docs/CLI_REFERENCE.md)** - Detailed CLI command reference
- **[GUI_GUIDE.md](docs/GUI_GUIDE.md)** - GUI usage guide
- **[INSTALLATION.md](docs/INSTALLATION.md)** - Installation instructions
- **[TESTING.md](TESTING.md)** - Testing information
- **[tests/README.md](tests/README.md)** - Test suite documentation

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
- Linting system: ✅ Complete (12 rules: BOF001-BOF012)
  - BOF001: BeaconDataExtract without BeaconDataParse
  - BOF002: Missing entry point
  - BOF003: Invalid entry point signature
  - BOF004: Suspicious API patterns
  - BOF005: Direct syscall detection
  - BOF006: Missing cleanup (handles not closed)
  - BOF007: Unusual section flags
  - BOF008: High entropy sections (packing detection)
  - **BOF009**: Undefined symbols (stack checks, exception handlers, CRT functions) ✨ NEW
  - **BOF010**: Unexpected relocation types ✨ NEW
  - **BOF011**: Loader-unfriendly sections (.bss, .rdata, .pdata) ✨ NEW
  - **BOF012**: Beacon API import whitelist enforcement ✨ NEW
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

**Phase 6 (Advanced Features)**: ❌ **Not Started**
**Phase 7 (Testing & Quality Assurance)**: ✅ **Complete**
- Unit tests for all core components
- Integration tests for BOF execution and analysis
- Parser, analyzer, executor, and CLI tests
- Batch testing framework
- All tests passing ✅

**Phase 8 (Documentation & Polish)**: 🟡 **~50% Complete**
- ✅ User documentation complete
- 🟡 Developer documentation pending
- ❌ Performance optimization pending

### Overall Progress: ~90% Complete

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

**Standard Build (YARA enabled by default):**
```bash
# Check for compilation errors
cargo check

# Build (YARA enabled by default)
cargo build

# Build release version
cargo build --release

# Run tests
cargo test

# Run with verbose logging
RUST_LOG=debug cargo run -- analyze path/to/bof.o
```

**Building without YARA Support (Optional):**

If you want to build without YARA support, use `--no-default-features`:

```bash
# Build without YARA
cargo build --no-default-features

# Build release version without YARA
cargo build --release --no-default-features
```

**Note:** YARA is enabled by default but can be disabled. The application works fully without it - the YARA tab will simply show that YARA bindings are not available. See [BUILD.md](BUILD.md) for detailed instructions.

## Documentation

Complete documentation is available:

- **[User Guide](docs/USER_GUIDE.md)** - Comprehensive guide with examples and troubleshooting
- **[CLI Reference](docs/CLI_REFERENCE.md)** - Complete command-line reference
- **[GUI Guide](docs/GUI_GUIDE.md)** - Graphical interface guide
- **[Installation Guide](docs/INSTALLATION.md)** - Installation and setup instructions

## Next Steps

1. **Test with Real BOFs** ⭐ **Current Priority**
   - Run tests with BOFs from `src/` directories
   - Validate execution with various BOF types
   - Identify and fix any issues discovered

2. **Advanced Features (Phase 6)** - Optional
   - OpSec analysis and scoring
   - YARA integration
   - Enhanced analysis features

3. **Performance Optimization (Phase 8.3)** - Optional
   - Profile and optimize hot paths
   - Memory optimization
   - Startup time improvements

## Contributing

Contributions are welcome! Please see the development plan in `PLAN.md` for areas that need work.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- Built with Rust and the `object` crate for COFF parsing
- Inspired by the need for better BOF testing and analysis tools
- Designed to complement existing BOF development workflows
