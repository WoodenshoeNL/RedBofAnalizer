# RedBofAnalizer

A comprehensive Beacon Object File (BOF) analyzer and execution tool written in Rust. This tool provides both command-line and GUI interfaces for analyzing, validating, and executing BOFs locally for testing and troubleshooting.

## Features

### ✅ Core Functionality

#### COFF Parser
- **Full COFF/PE parsing**: Complete parsing of object files
  - Header parsing with machine type detection (x64/x86)
  - Section parsing (.text, .data, .rdata, .bss, .pdata, .reloc)
  - Symbol table parsing (internal and external symbols)
  - Import extraction and entry point detection
  - Comprehensive relocation processing (AMD64_REL32, ADDR64, and more)

#### Memory Loader
- **Safe memory management** for BOF execution
  - Page-aligned memory allocation using VirtualAlloc
  - Section mapping with appropriate memory protections
  - Relocation application for proper address resolution
  - Exception handling for crash detection

#### Symbol Resolution
- **Complete symbol resolution system**
  - Windows API resolution (LoadLibrary/GetProcAddress)
  - Beacon API stub registration
  - Import symbol parsing (`__imp_LIBRARY$Function` format)
  - Symbol caching for performance

#### Beacon API Emulation
- **Comprehensive Beacon API implementation** (60+ APIs)
  - **Output APIs**: `BeaconPrintf`, `BeaconOutput`, `BeaconDownload`
  - **Data Parsing APIs**: `BeaconDataParse`, `BeaconDataInt`, `BeaconDataShort`, `BeaconDataLength`, `BeaconDataExtract`, `BeaconDataPtr`
  - **Token APIs**: `BeaconUseToken`, `BeaconRevertToken`, `BeaconIsAdmin`
  - **Process APIs**: `BeaconSpawnTemporaryProcess`, `BeaconInjectProcess`, `BeaconInjectTemporaryProcess`, `BeaconCleanupProcess`, `BeaconGetSpawnTo`
  - **Format APIs**: `BeaconFormatAlloc`, `BeaconFormatReset`, `BeaconFormatFree`, `BeaconFormatAppend`, `BeaconFormatPrintf`, `BeaconFormatToString`, `BeaconFormatInt`, `BeaconFormatShort`, `BeaconFormatLength`
  - **Memory APIs**: `BeaconVirtualAlloc`, `BeaconVirtualAllocEx`, `BeaconVirtualFree`, `BeaconVirtualProtect`, `BeaconVirtualProtectEx`
  - **Information APIs**: `BeaconInformation`, `BeaconGetSyscallInformation`
  - **Key/Value Store APIs**: `BeaconAddValue`, `BeaconGetValue`, `BeaconRemoveValue`, and variants
  - **Data Store APIs**: `BeaconDataStoreAlloc`, `BeaconDataStoreReset`, `BeaconDataStoreFree`, and more
  - **User Data APIs**: `BeaconGetCustomUserData`, `BeaconGetUserData`
  - **Thread/Process APIs**: `BeaconGetThreadContext`, `BeaconSetThreadContext`, `BeaconResumeThread`, `BeaconOpenProcess`, `BeaconOpenThread`, `BeaconCloseHandle`, and more
  - **Beacon Gate APIs**: `BeaconDisableBeaconGate`, `BeaconEnableBeaconGate`, and masking variants
  - **Utility APIs**: `toWideChar`

#### Execution Engine
- **Full BOF execution capabilities**
  - BOF loading and execution
  - Argument parsing and packing (z, Z, i, s, b types)
  - Output capture and formatting
  - Sandbox mode for safe execution
  - Execution tracing and API call logging
  - Timeout handling
  - Exception handling and crash reporting

### ✅ CLI Interface

#### Analyze Command
- **Comprehensive BOF analysis**
  - File information and overview
  - Section details with entropy calculation
  - Symbol table with filtering
  - API usage detection (Beacon and Win32 APIs)
  - Dependency analysis
  - Security assessment with OpSec scoring
  - Linting with 12 rules
  - Disassembly support
  - OpSec analysis
  - Compatibility analysis
  - Calling convention analysis
  - Stack usage analysis
  - YARA rule matching
  - Multiple output formats (text, JSON, Markdown)

#### Execute Command
- **Execute BOFs with full control**
  - Argument passing via command line
  - Sandbox mode for restricted execution
  - Verbose tracing of API calls
  - Configurable timeout
  - Output capture and display
  - Beacon information emulation

#### Test Command
- **Batch testing of multiple BOFs**
  - Recursive directory scanning
  - File pattern matching (*.o, *.obj)
  - Filter options
  - Batch execution with error handling
  - Comprehensive reporting (text, JSON, Markdown)
  - Continue on errors option

#### Validate Command
- **Quick BOF validation**
  - Architecture validation
  - Entry point validation
  - Required symbol checks

### ✅ GUI Interface

- **Full egui-based GUI** with dark theme
- **10 comprehensive tabs**:
  - **Overview**: File information, quick stats, security assessment, lint summary
  - **Sections**: Detailed section information with entropy, flags, and hex viewer
  - **Symbols**: Filterable symbol table with search functionality
  - **Imports**: Import analysis with API categorization
  - **Lints**: Filterable lint findings with explanations and suggestions
  - **OpSec**: Enhanced OpSec analysis with scoring, API categorization, and pattern detection
  - **Disassembly**: Instruction-level view with syntax highlighting
  - **Stack Analysis**: Stack usage analysis per function
  - **YARA**: YARA rule matching with custom rule support
  - **Execute**: BOF execution with argument builder and output console
- **File operations**: Drag-and-drop support, recent files
- **Async analysis** with progress indicators
- **Settings persistence**: YARA rules, preferences

### ✅ Analysis Features

#### Static Analysis
- **Comprehensive analysis engine**
  - API detection and categorization
  - Dependency extraction
  - Security assessment with risk levels
  - Capability detection
  - OpSec scoring and analysis

#### Linting System
- **12 lint rules** (BOF001-BOF012):
  - **BOF001**: BeaconDataExtract without BeaconDataParse
  - **BOF002**: Missing entry point
  - **BOF003**: Invalid entry point signature
  - **BOF004**: Suspicious API patterns
  - **BOF005**: Direct syscall detection
  - **BOF006**: Missing cleanup (handles not closed)
  - **BOF007**: Unusual section flags
  - **BOF008**: High entropy sections (packing detection)
  - **BOF009**: Undefined symbols (stack checks, exception handlers, CRT functions)
  - **BOF010**: Unexpected relocation types
  - **BOF011**: Loader-unfriendly sections (.bss, .rdata, .pdata)
  - **BOF012**: Beacon API import whitelist enforcement

#### Advanced Analysis
- **OpSec Analysis**: 
  - API categorization by risk level (Low, Medium, High, Critical)
  - Risky API combination detection
  - Suspicious pattern identification
  - Comprehensive OpSec scoring (0-100)
  - Detection vector analysis
  
- **YARA Integration**:
  - YARA rule engine (optional, enabled by default)
  - Default BOF-specific rule library
  - Custom rule support (files, directories, strings)
  - Rule matching against sections and symbols
  - Detailed match information with metadata

- **Disassembly**:
  - Full disassembly support using iced-x86
  - Instruction-level analysis
  - Architecture detection (x64/x86)
  - Section-based disassembly

- **Stack Analysis**:
  - Stack usage estimation per function
  - Potential stack overflow detection
  - Stack frame size analysis

- **Compatibility Analysis**:
  - Cobalt Strike version compatibility detection
  - Version-specific feature detection
  - Compatibility warnings

- **Calling Convention Analysis**:
  - Calling convention verification
  - Mismatch detection

#### Output Formatting
- **Multiple output formats**
  - Human-readable text format
  - Machine-readable JSON format
  - Markdown format for documentation

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

**Note:** YARA is enabled by default but can be disabled. The application works fully without it - the YARA tab will simply show that YARA bindings are not available. See [BUILD.md](BUILD.md) for detailed instructions.

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
redbofanalyzer analyze path/to/bof.o --apis --dependencies --security --lints --opsec

# With disassembly and YARA rules
redbofanalyzer analyze path/to/bof.o --disasm --yara-rules rules/ --opsec
```

#### Execute a BOF

```bash
# Execute without arguments
redbofanalyzer execute path/to/bof.o

# Execute with arguments
redbofanalyzer execute path/to/bof.o --args "z:test_string i:123"

# Execute in sandbox mode
redbofanalyzer execute path/to/bof.o --sandbox --timeout 10
```

#### Launch GUI

```bash
# Launch GUI mode (default)
redbofanalyzer

# Or explicitly
redbofanalyzer --gui
```

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[USER_GUIDE.md](docs/USER_GUIDE.md)** - Complete user guide with examples
- **[CLI_REFERENCE.md](docs/CLI_REFERENCE.md)** - Detailed CLI command reference
- **[GUI_GUIDE.md](docs/GUI_GUIDE.md)** - GUI usage guide
- **[INSTALLATION.md](docs/INSTALLATION.md)** - Installation instructions
- **[ADVANCED_FEATURES.md](docs/ADVANCED_FEATURES.md)** - Advanced features guide
- **[OPSEC_TAB.md](docs/OPSEC_TAB.md)** - OpSec analysis guide
- **[TESTING.md](TESTING.md)** - Testing information
- **[tests/README.md](tests/README.md)** - Test suite documentation

## Project Status

### Current Progress

**Phase 1 (Foundation)**: ✅ **100% Complete**
- Project setup: ✅ Complete
- COFF parser: ✅ Complete
- BOF models: ✅ Complete
- Memory loader: ✅ Complete
- Symbol resolution: ✅ Complete
- Beacon API emulation: ✅ Complete (60+ APIs)

**Phase 2 (Analysis)**: ✅ **100% Complete**
- Static analysis engine: ✅ Complete
- Linting system: ✅ Complete (12 rules: BOF001-BOF012)
- Disassembly support: ✅ Complete (iced-x86)
- OpSec analysis: ✅ Complete
- YARA integration: ✅ Complete
- Stack analysis: ✅ Complete
- Compatibility analysis: ✅ Complete
- Calling convention analysis: ✅ Complete

**Phase 3 (Execution Enhancement)**: ✅ **100% Complete**
- Complete Beacon API: ✅ Complete
- Argument handling: ✅ Complete
- Execution options: ✅ Complete
- Sandbox mode: ✅ Complete

**Phase 4 (CLI Interface)**: ✅ **100% Complete**
- All commands implemented
- All output formats working

**Phase 5 (GUI Interface)**: ✅ **100% Complete**
- Full egui-based GUI with dark theme
- All 10 tabs implemented
- File loading via menu and drag-drop
- Async analysis with progress indicator

**Phase 6 (Advanced Features)**: ✅ **100% Complete**
- OpSec analysis: ✅ Complete
- YARA integration: ✅ Complete
- Stack analysis: ✅ Complete
- Compatibility analysis: ✅ Complete
- Calling convention analysis: ✅ Complete

**Phase 7 (Testing & Quality Assurance)**: ✅ **Complete**
- Unit tests for all core components
- Integration tests for BOF execution and analysis
- Parser, analyzer, executor, and CLI tests
- Batch testing framework
- All tests passing ✅

**Phase 8 (Documentation & Polish)**: ✅ **~90% Complete**
- ✅ User documentation complete
- ✅ Contributing guidelines (CONTRIBUTING.md)
- ✅ Security policy (SECURITY.md)
- 🟡 Developer documentation pending (low priority)
- 🟡 Performance optimization pending (low priority)

### Overall Progress: ~98% Complete

## Architecture

```
RedBofAnalizer
├── CLI Mode (clap)
├── GUI Mode (egui) - ✅ Implemented
└── Core Library
    ├── Parser (COFF/PE parsing)
    ├── Analyzer (Static analysis + linting + OpSec + YARA)
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
│   ├── gui/                 # GUI interface
│   └── core/                # Core library
│       ├── parser/          # COFF parsing
│       ├── analyzer/        # Static analysis
│       ├── executor/         # Execution engine
│       ├── models/           # Data structures
│       └── utils/            # Utilities
├── tests/                   # Test suite
├── docs/                    # Documentation
├── data/                     # OpSec data files
├── tools/                   # Helper tools
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

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

## Security

For security-related questions or to report vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

GPL-3.0 License - see LICENSE file for details.

## Acknowledgments

- Built with Rust and the `object` crate for COFF parsing
- Inspired by the need for better BOF testing and analysis tools
- Designed to complement existing BOF development workflows
