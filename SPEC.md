# RedBofAnalizer - Detailed Specifications

## 1. Overview

**RedBofAnalizer** is a comprehensive Beacon Object File (BOF) analyzer and execution tool written in Rust. It provides both command-line and GUI interfaces for analyzing, executing, and testing BOF files locally.

### 1.1 Purpose

The tool is designed to help red teamers and BOF developers:
- **Analyze BOFs**: Understand BOF structure, APIs used, and capabilities
- **Test BOFs**: Execute BOFs locally without Cobalt Strike infrastructure
- **Troubleshoot**: Identify and fix issues with BOF execution
- **Validate**: Ensure BOFs are properly formatted and compatible

### 1.2 Target Users

- BOF developers writing and testing new BOFs
- Red teamers troubleshooting BOF execution issues
- Security researchers analyzing BOF capabilities
- QA engineers testing BOF collections

### 1.3 Key Requirements

- **Single Executable**: Same binary for CLI and GUI modes
- **Shared Core**: Analysis, execution, and testing use the same core engine
- **Windows-Only**: Designed for Windows platform (BOF execution target)
- **Real BOF Support**: Must work with actual BOFs from Cobalt Strike ecosystem

## 2. Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   CLI Mode   │  │   GUI Mode   │  │  Batch Mode  │     │
│  │  (clap)      │  │   (egui)     │  │  (automated) │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                 │                 │              │
│         └─────────────────┼─────────────────┘              │
│                           ▼                                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  Core Library                        │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │   │
│  │  │  Parser  │  │ Analyzer │  │    Executor      │  │   │
│  │  │  (COFF)  │  │          │  │  (Beacon API)    │  │   │
│  │  └──────────┘  └──────────┘  └──────────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│                           ▼                                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Platform Layer (Windows)                 │   │
│  │  (VirtualAlloc, LoadLibrary, GetProcAddress, etc.)    │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Core Components

#### 2.2.1 Parser Module
- **COFF Parser**: Parse COFF headers, sections, symbols, relocations
- **File Reader**: Read and validate BOF files
- **Structure Builder**: Build in-memory BOF representation

#### 2.2.2 Analyzer Module
- **Static Analysis**: Analyze BOF without execution
- **API Detection**: Identify Beacon and Win32 API usage
- **Security Assessment**: Evaluate risk and OpSec implications
- **Linting**: Apply lint rules and generate findings

#### 2.2.3 Executor Module
- **Memory Loader**: Load BOF into executable memory
- **Symbol Resolver**: Resolve Windows and Beacon API symbols
- **Beacon API Emulator**: Implement Beacon API functions
- **Execution Engine**: Execute BOF entry point and capture output

## 3. BOF File Format

### 3.1 COFF Structure

BOF files are COFF (Common Object File Format) object files with the following structure:

```
COFF Header (20 bytes)
├── Machine Type (0x8664 for x64, 0x014C for x86)
├── Number of Sections
├── Timestamp
├── Symbol Table Pointer
├── Number of Symbols
├── Optional Header Size (0 for object files)
└── Characteristics

Section Headers (40 bytes each)
├── Section Name (8 bytes or string table offset)
├── Virtual Size
├── Virtual Address (0 for object files)
├── Raw Data Size
├── Raw Data Pointer
├── Relocations Pointer
├── Line Numbers Pointer
├── Number of Relocations
├── Number of Line Numbers
└── Characteristics

Sections
├── .text   - Executable code
├── .data   - Initialized data
├── .rdata  - Read-only data (strings, constants)
├── .bss    - Uninitialized data
├── .pdata  - Exception handling data
└── .reloc  - Relocation information

Symbol Table
├── Name (8 bytes or string table offset)
├── Value (address or section index)
├── Section Number
├── Type
├── Storage Class
└── Number of Auxiliary Entries

String Table
└── Null-terminated strings (for names > 8 bytes)

Relocations
├── Virtual Address
├── Symbol Index
└── Type (AMD64_REL32, ADDR64, etc.)
```

### 3.2 BOF-Specific Requirements

- **Entry Point**: Must export `go` function with signature: `void go(char* args, int len)`
- **Position Independent**: Code must be position-independent (PIC)
- **No Standard Library**: Cannot link against standard C runtime
- **External Symbols**: Uses import symbols for Windows and Beacon APIs

### 3.3 Import Symbol Format

Beacon and Windows APIs are referenced via import symbols:
- Format: `__imp_LIBRARY$Function`
- Examples:
  - `__imp_BeaconPrintf`
  - `__imp_KERNEL32$VirtualAlloc`
  - `__imp_NTDLL$NtOpenProcess`

## 4. Core Functionality Specifications

### 4.1 COFF Parser

#### 4.1.1 Header Parsing
- Parse COFF file header
- Validate machine type (x64 or x86)
- Extract section count and symbol table information
- Validate file format

#### 4.1.2 Section Parsing
- Parse all section headers
- Extract section data
- Identify section types (.text, .data, .rdata, etc.)
- Extract section characteristics (executable, readable, writable)
- Calculate section entropy (for packing detection)

#### 4.1.3 Symbol Table Parsing
- Parse symbol table entries
- Handle string table references
- Categorize symbols (function, data, external, etc.)
- Identify entry point (`go` function)
- Extract import symbols

#### 4.1.4 Relocation Processing
- Parse relocation entries
- Identify relocation types:
  - `IMAGE_REL_AMD64_REL32` (32-bit relative)
  - `IMAGE_REL_AMD64_ADDR64` (64-bit absolute)
  - `IMAGE_REL_AMD64_ADDR32` (32-bit absolute)
- Calculate target addresses
- Prepare for runtime relocation application

### 4.2 Static Analysis

#### 4.2.1 API Detection
- **Beacon APIs**: Detect all Beacon API function calls
  - Output APIs (BeaconPrintf, BeaconOutput)
  - Data parsing APIs (BeaconDataParse, BeaconDataInt, etc.)
  - Token APIs (BeaconUseToken, BeaconRevertToken)
  - Process APIs (BeaconInjectProcess, etc.)
  - Format APIs (BeaconFormatAlloc, etc.)
- **Win32 APIs**: Detect Windows API calls
  - Categorize by DLL (kernel32, ntdll, advapi32, etc.)
  - Identify function names
  - Group by functionality

#### 4.2.2 Signature Detection
- Analyze code to detect argument signature
- Parse argument format strings (z, Z, i, s, b)
- Validate entry point signature
- Report detected signature

#### 4.2.3 Dependency Analysis
- List required DLLs
- List required functions per DLL
- Check for missing dependencies
- Generate dependency graph

#### 4.2.4 Security Assessment
- **Risk Level Calculation**:
  - LOW: Basic operations, safe APIs
  - MEDIUM: Process operations, token access
  - HIGH: Process injection, direct syscalls, evasion techniques
- **Capability Detection**:
  - Process operations (query, inject, spawn)
  - Token manipulation
  - Memory operations
  - Network operations
  - File operations
  - Registry operations
- **OpSec Analysis**:
  - API OpSec implications
  - Risky API combinations
  - Suspicious patterns
  - Direct syscall usage

#### 4.2.5 Linting System
- **Lint Rules**:
  - BOF001: BeaconDataExtract without BeaconDataParse
  - BOF002: Missing entry point
  - BOF003: Invalid entry point signature
  - BOF004: Suspicious API patterns
  - BOF005: Direct syscall detection
  - BOF006: Missing cleanup (potential handle leaks)
  - BOF007: Unusual section flags
  - BOF008: High entropy sections (possible packing)
  - BOF009: Missing error handling patterns
  - BOF010: Unusual relocation patterns
- **Severity Levels**:
  - ERROR: Critical issues that will cause failures
  - WARNING: Potential issues or best practice violations
  - INFO: Informational findings
- **Location Tracking**: Symbol, section, address, line (if available)

### 4.3 Memory Loading

#### 4.3.1 Memory Allocation
- Allocate executable memory using `VirtualAlloc`
- Ensure page-aligned allocations
- Calculate total memory needed (all sections)
- Reserve contiguous memory space

#### 4.3.2 Section Mapping
- Map each section to allocated memory
- Set appropriate memory protections:
  - `.text`: `PAGE_EXECUTE_READ`
  - `.data`, `.bss`: `PAGE_READWRITE`
  - `.rdata`: `PAGE_READONLY`
- Handle section alignment requirements
- Initialize `.bss` section to zero

#### 4.3.3 Relocation Application
- Apply relocations to loaded code
- Fix addresses based on actual load address
- Handle different relocation types correctly
- Update references to symbols

### 4.4 Symbol Resolution

#### 4.4.1 Windows API Resolution
- Parse import symbol format: `__imp_LIBRARY$Function`
- Extract library name and function name
- Load DLL using `LoadLibrary`
- Resolve function address using `GetProcAddress`
- Handle common DLLs:
  - `KERNEL32` → `kernel32.dll`
  - `NTDLL` → `ntdll.dll`
  - `ADVAPI32` → `advapi32.dll`
  - `USER32` → `user32.dll`
  - etc.

#### 4.4.2 Beacon API Resolution
- Create stub functions for all Beacon APIs
- Set up function pointers for BOF to call
- Resolve import symbols to stub addresses
- Handle all Beacon API categories

### 4.5 Beacon API Emulation

#### 4.5.1 Output APIs
```rust
// Format and output text
BeaconPrintf(callback_type: u32, format: *const c_char, ...) -> void

// Output raw data
BeaconOutput(callback_type: u32, data: *const u8, length: usize) -> void
```
- Capture output to console/GUI
- Support callback types: OUTPUT, ERROR, CUSTOM
- Format strings using printf-style formatting

#### 4.5.2 Data Parsing APIs
```rust
// Initialize parser
BeaconDataParse(parser: *mut datap, buffer: *const u8, size: usize) -> void

// Extract int32
BeaconDataInt(parser: *mut datap) -> i32

// Extract int16
BeaconDataShort(parser: *mut datap) -> i16

// Get remaining length
BeaconDataLength(parser: *mut datap) -> usize

// Extract binary data
BeaconDataExtract(parser: *mut datap, size: usize) -> *mut u8
```
- Implement parser state machine
- Handle argument format: z, Z, i, s, b
- Validate parser state

#### 4.5.3 Token APIs
```rust
// Use impersonation token
BeaconUseToken(token: HANDLE) -> void

// Revert to original token
BeaconRevertToken() -> void

// Check admin privileges
BeaconIsAdmin() -> BOOL
```
- Track token state
- Implement token operations
- Handle token reversion

#### 4.5.4 Process APIs
```rust
// Spawn temporary process
BeaconSpawnTemporaryProcess(x86: BOOL, ignoreToken: BOOL, 
                           si: *mut STARTUPINFOA, 
                           pi: *mut PROCESS_INFORMATION) -> void

// Inject into process
BeaconInjectProcess(hProcess: HANDLE, pid: DWORD, 
                   payload: *const u8, payloadLen: usize,
                   offset: usize, arg: *const u8, argLen: usize) -> void

// Inject into temporary process
BeaconInjectTemporaryProcess(pi: *mut PROCESS_INFORMATION,
                            payload: *const u8, payloadLen: usize,
                            offset: usize, arg: *const u8, argLen: usize) -> void

// Cleanup process
BeaconCleanupProcess(pi: *mut PROCESS_INFORMATION) -> void
```
- Implement process spawning (sandboxed if needed)
- Handle process injection (optional, may be disabled in sandbox)
- Track process handles for cleanup

#### 4.5.5 Format APIs
```rust
// Allocate format buffer
BeaconFormatAlloc(format: *mut formatp, maxsz: usize) -> void

// Reset format buffer
BeaconFormatReset(format: *mut formatp) -> void

// Free format buffer
BeaconFormatFree(format: *mut formatp) -> void

// Append data
BeaconFormatAppend(format: *mut formatp, data: *const u8, len: usize) -> void

// Format string
BeaconFormatPrintf(format: *mut formatp, fmt: *const c_char, ...) -> void

// Convert to string
BeaconFormatToString(format: *mut formatp, size: *mut usize) -> *mut u8

// Append integer
BeaconFormatInt(format: *mut formatp, val: i32) -> void
```
- Implement format buffer management
- Support printf-style formatting
- Handle memory allocation/deallocation

#### 4.5.6 Memory APIs
```rust
// Allocate memory
BeaconVirtualAlloc(size: usize) -> *mut u8

// Free memory
BeaconVirtualFree(ptr: *mut u8) -> void
```
- Track allocations for cleanup
- Use Windows VirtualAlloc/VirtualFree

### 4.6 Execution Engine

#### 4.6.1 Execution Flow
1. Load BOF into memory
2. Apply relocations
3. Resolve all symbols
4. Set up Beacon API stubs
5. Prepare arguments (if any)
6. Call entry point (`go` function)
7. Capture output
8. Handle errors/exceptions
9. Cleanup resources

#### 4.6.2 Argument Handling
- Parse argument format string (e.g., "z:string i:123 s:456")
- Pack arguments into Beacon format:
  - `z` - null-terminated string
  - `Z` - null-terminated wide string
  - `i` - 32-bit integer
  - `s` - 16-bit integer
  - `b` - binary data (length + data)
- Pass packed buffer to BOF entry point

#### 4.6.3 Output Capture
- Capture all BeaconPrintf/BeaconOutput calls
- Separate by output type (OUTPUT, ERROR, CUSTOM)
- Timestamp each output (optional)
- Store for display in CLI/GUI

#### 4.6.4 Error Handling
- Catch execution exceptions
- Report clear error messages
- Include context (address, symbol, etc.)
- Continue execution if possible (for batch mode)

## 5. CLI Interface Specifications

### 5.1 Command Structure

```
redbofanalyzer [OPTIONS] <COMMAND>
```

#### 5.1.1 Global Options
- `--gui` - Launch GUI mode
- `--verbose` - Verbose output
- `--quiet` - Quiet mode (errors only)
- `--format <json|markdown|text>` - Output format (default: text)
- `--version` - Show version
- `--help` - Show help

#### 5.1.2 Commands

**analyze** - Analyze BOF file
```
redbofanalyzer analyze <FILE> [OPTIONS]
```
Options:
- `--security` - Security assessment only
- `--disasm` - Include disassembly
- `--apis` - Show API usage
- `--dependencies` - Show dependencies
- `--lints` - Show lint findings
- `--output <FILE>` - Write report to file

**execute** - Execute BOF file
```
redbofanalyzer execute <FILE> [OPTIONS]
```
Options:
- `--args <FORMAT>` - Arguments (e.g., "z:string i:123")
- `--sandbox` - Run in sandbox mode
- `--trace` - Verbose API logging
- `--timeout <SECONDS>` - Execution timeout

**test** - Test all BOFs in directory
```
redbofanalyzer test <DIRECTORY> [OPTIONS]
```
Options:
- `--report <FORMAT>` - Report format (json, markdown, text)
- `--filter <PATTERN>` - Filter BOFs (glob pattern)
- `--output <FILE>` - Write report to file
- `--continue-on-error` - Continue on errors

**validate** - Validate BOF without execution
```
redbofanalyzer validate <FILE>
```

### 5.2 Output Formats

#### 5.2.1 Text Format
- Human-readable tables
- Color-coded output (optional)
- Progress indicators
- Clear section separators

#### 5.2.2 JSON Format
- Structured data
- Machine-readable
- Complete analysis data
- Suitable for automation

#### 5.2.3 Markdown Format
- Formatted tables
- Code blocks for disassembly
- Suitable for documentation

## 6. GUI Interface Specifications

### 6.1 Window Layout

```
┌─────────────────────────────────────────────────────────────┐
│  RedBofAnalizer v0.1.0                    [─] [□] [×]       │
├─────────────────────────────────────────────────────────────┤
│  File   Edit   View   Analysis   Execution   Tools   Help  │
├─────────────────────────────────────────────────────────────┤
│ ┌──────────────┬───────────────────────────────────────────┤
│ │ File Browser │  ┌─ Overview ─┬─ Sections ─┬─ Symbols ─┐  │
│ │              │  │                                          │
│ │ [Directory]  │  │  [Main Content Area]                    │
│ │  - file1.o   │  │                                          │
│ │  - file2.o   │  │                                          │
│ │              │  │                                          │
│ ├──────────────┤  │                                          │
│ │ Quick Info   │  │                                          │
│ │              │  │                                          │
│ └──────────────┴───────────────────────────────────────────┤
├─────────────────────────────────────────────────────────────┤
│  Output Console                                    [Clear]  │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ [INFO] Messages...                                       │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Main Tabs

#### 6.2.1 Overview Tab
- File information summary
- Quick stats (sections, symbols, size, architecture)
- Security assessment card (risk level, capabilities)
- Status indicators
- Lint summary (counts by severity)
- Detected argument signature

#### 6.2.2 Sections Tab
- Table view:
  - Name, Virtual Size, Raw Size, Entropy, Flags, Characteristics
- Section selection
- Raw hex viewer (toggle)
- Section details panel

#### 6.2.3 Symbols Tab
- Filterable symbol table
- Search functionality
- Columns: Name, Type, Section, Address, Size
- Symbol details panel
- Filter by type (function, data, external, etc.)

#### 6.2.4 Issues Tab (Lints)
- Filterable lint list
- Filters: All, Errors, Warnings, Info
- Columns: Level, Code, Message, Location
- Detailed explanation panel
- Fix suggestions

#### 6.2.5 Run Tab (Execution)
- BOF file selector
- Argument builder:
  - Signature display
  - Argument input fields (one per argument)
  - Type indicators
  - Validation feedback
- Execution options:
  - [ ] Capture Beacon output
  - [ ] Log API calls
  - [ ] Sandbox mode
  - [ ] Verbose tracing
- Execute/Stop buttons
- Output console (scrollable)
- Execution status indicator

#### 6.2.6 Tests Tab (Batch)
- Directory selector
- Test configuration
- Results table:
  - File, Status, Time (ms), Notes
- Filtering and sorting
- Export options (JSON, Markdown)
- Run tests button

### 6.3 Additional Views

#### 6.3.1 Hex Viewer
- Raw byte view (hex + ASCII)
- Section highlighting
- Address navigation
- Search functionality
- Copy to clipboard

#### 6.3.2 Disassembly View
- Instruction-level view
- Syntax highlighting
- Address navigation
- API call highlighting
- Cross-references (future)

### 6.4 GUI Features

#### 6.4.1 File Operations
- Open BOF file (Ctrl+O)
- Recent files menu
- Open folder/project
- Save analysis report

#### 6.4.2 Settings
- Theme selection (Dark/Light)
- Default directories
- Execution preferences
- Window state persistence

#### 6.4.3 Keyboard Shortcuts
- `Ctrl+O` - Open file
- `F5` - Execute BOF
- `Ctrl+T` - Switch to Tests tab
- `Ctrl+1-6` - Switch tabs
- `Esc` - Cancel operation

## 7. Data Models

### 7.1 BOF Model

```rust
pub struct BofFile {
    pub path: PathBuf,
    pub header: CoffHeader,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub entry_point: Option<Symbol>,
    pub imports: Vec<Import>,
}

pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub data: Vec<u8>,
    pub characteristics: u32,
    pub entropy: f64,
}

pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub section: Option<usize>,
    pub symbol_type: SymbolType,
    pub storage_class: u8,
    pub is_external: bool,
}

pub struct Import {
    pub library: String,
    pub function: String,
    pub symbol_name: String,
}
```

### 7.2 Analysis Report Model

```rust
pub struct AnalysisReport {
    pub bof: BofFile,
    pub overview: Overview,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub apis: ApiUsage,
    pub security: SecurityAssessment,
    pub lints: Vec<LintFinding>,
    pub dependencies: Dependencies,
}

pub struct SecurityAssessment {
    pub risk_level: RiskLevel,
    pub capabilities: Vec<Capability>,
    pub opsec_score: u8,
    pub opsec_analysis: OpsecAnalysis,
}

pub struct LintFinding {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    pub location: Location,
    pub explanation: String,
    pub suggestion: Option<String>,
}
```

### 7.3 Execution Result Model

```rust
pub struct ExecutionResult {
    pub success: bool,
    pub output: Vec<OutputMessage>,
    pub execution_time: Duration,
    pub error: Option<ExecutionError>,
    pub api_calls: Vec<ApiCall>,
}

pub struct OutputMessage {
    pub timestamp: DateTime<Utc>,
    pub message_type: OutputType,
    pub content: String,
}
```

## 8. Error Handling

### 8.1 Error Types

- **ParseError**: COFF parsing failures
- **LoadError**: Memory loading failures
- **ResolutionError**: Symbol resolution failures
- **ExecutionError**: BOF execution failures
- **ValidationError**: BOF validation failures

### 8.2 Error Reporting

- Clear, descriptive error messages
- Context information (file, address, symbol)
- Suggested fixes when possible
- Error codes for automation

## 9. Performance Requirements

### 9.1 Parsing
- Parse typical BOF (< 100KB) in < 100ms
- Handle large BOFs (< 10MB) in < 1s

### 9.2 Execution
- Load and execute simple BOF in < 50ms
- Support execution timeouts (configurable)

### 9.3 GUI
- Responsive UI (60 FPS target)
- Fast file loading (< 500ms for typical BOF)
- Smooth scrolling and navigation

## 10. Security Considerations

### 10.1 Execution Safety
- Sandbox mode for untrusted BOFs
- Timeout protection
- Memory isolation (optional)
- API call restrictions in sandbox

### 10.2 Input Validation
- Validate all file inputs
- Sanitize user-provided arguments
- Bounds checking on all operations

### 10.3 Error Information
- Don't leak sensitive information in errors
- Safe error messages for production use

## 11. Testing Requirements

### 11.1 Unit Tests
- COFF parser tests
- Symbol resolution tests
- Beacon API tests
- Analysis engine tests

### 11.2 Integration Tests
- Full BOF execution tests
- Test with BOFs from `src/` directory
- Test with BOFs from `RedBof/` directory

### 11.3 GUI Tests
- UI component tests
- User interaction tests
- File operation tests

## 12. Documentation Requirements

### 12.1 User Documentation
- Installation guide
- Quick start guide
- CLI reference
- GUI guide
- Troubleshooting guide

### 12.2 Developer Documentation
- Architecture overview
- API documentation
- Contributing guide
- Code examples

### 12.3 Code Documentation
- Inline comments for complex logic
- Module-level documentation
- Function documentation for public APIs

## 13. Future Enhancements

### 13.1 Advanced Analysis
- Control flow analysis
- Data flow analysis
- Symbolic execution (future)
- Fuzzing support (future)

### 13.2 Integration
- Cobalt Strike plugin (future)
- VS Code extension (future)
- CI/CD integration

### 13.3 Performance
- Parallel BOF execution
- Caching of analysis results
- Incremental analysis

