# RedBofAnalizer GUI Guide

Complete guide to using the RedBofAnalizer graphical user interface.

## Launching the GUI

### Windows

```bash
# Launch GUI mode
redbofanalyzer --gui

# Or simply (defaults to GUI if no command specified)
redbofanalyzer
```

The GUI will open in a new window with a dark theme optimized for analysis work.

## Main Window

### Menu Bar

- **File**
  - `Open` - Open a BOF file (Ctrl+O)
  - `Reload` - Reload the current file
  - `Exit` - Close the application

- **View**
  - Tab navigation
  - Theme settings (future)

- **Help**
  - About dialog (future)

### Tab Navigation

The main window uses a tab-based interface with the following tabs:

1. **Overview** - Quick summary and statistics
2. **Sections** - Detailed section information
3. **Symbols** - Symbol table and imports
4. **Imports** - API usage (Beacon and Win32)
5. **Issues** - Lint findings and warnings
6. **Disassembly** - Code disassembly view
7. **Run** - BOF execution interface

## Tab Details

### Overview Tab

The Overview tab provides a quick summary of the loaded BOF.

#### Information Cards

- **File Information**
  - File path
  - File size
  - Architecture (x64/x86)
  - Entry point status

- **Statistics**
  - Number of sections
  - Number of symbols
  - Number of imports
  - Total size

- **Security Assessment**
  - Risk level (LOW, MEDIUM, HIGH)
  - OpSec score
  - Detected capabilities

#### Status Indicators

- Green: Valid/OK
- Yellow: Warning
- Red: Error/Issue

### Sections Tab

Detailed view of all sections in the BOF.

#### Features

- **Table View**
  - Section name
  - Size (raw and virtual)
  - Entropy (for packing detection)
  - Characteristics/flags
  - Memory protection

- **Filtering**
  - Filter by section name
  - Filter by characteristics
  - Search functionality

- **Hex Preview**
  - Collapsible hex dump
  - Shows raw section data
  - Truncated for large sections

#### Section Characteristics

Sections are marked with badges:
- **CODE** - Executable code
- **DATA** - Initialized data
- **READ** - Read-only data
- **WRITE** - Writable data
- **EXEC** - Executable

### Symbols Tab

Complete symbol table with filtering and search.

#### Features

- **Symbol Table**
  - Symbol name
  - Type (function, data, etc.)
  - Section
  - Address (RVA)
  - External/Internal classification

- **Color Coding**
  - Functions: Blue
  - Data: Green
  - Imports: Orange
  - Exports: Purple

- **Search and Filter**
  - Search by name
  - Filter by type
  - Filter by section

### Imports Tab

Lists all imported APIs (Beacon and Win32).

#### Sections

- **Beacon APIs**
  - All Beacon API functions used
  - Grouped by category (Output, Data, Token, etc.)

- **Win32 APIs**
  - Windows API functions
  - Grouped by DLL (kernel32, ntdll, etc.)
  - Function names

#### Information Display

- API name
- DLL name (for Win32 APIs)
- Usage count (if available)

### Issues Tab (Lints)

Shows lint findings and potential issues.

#### Features

- **Lint List**
  - Severity icons (Error, Warning, Info)
  - Rule ID (BOF001, BOF002, etc.)
  - Description
  - Location (section, symbol, address)

- **Details Panel**
  - Full message
  - Suggestions for fixes
  - Context information

#### Severity Levels

- **Error** (Red) - Critical issues
- **Warning** (Yellow) - Potential problems
- **Info** (Blue) - Informational notes

### Disassembly Tab

Instruction-level view of the BOF code.

#### Features

- **Disassembly View**
  - Address
  - Instruction bytes (hex)
  - Disassembled instruction
  - Comments (if available)

- **Color Coding**
  - Call instructions: Green
  - Jump instructions: Blue
  - Return instructions: Red
  - Other instructions: Default

- **Statistics**
  - Total instructions
  - Function count
  - Call count

### Run Tab (Execution)

Execute the BOF with custom arguments and options.

#### Features

- **Argument Input**
  - Text field for arguments
  - Format help displayed
  - Type validation

- **Execution Options**
  - **Sandbox Mode**: Restrict API access
  - **Trace Mode**: Log all API calls
  - **Timeout**: Execution timeout (seconds)

- **Output Console**
  - Scrollable output area
  - Shows BOF output (BeaconPrintf, etc.)
  - Execution status
  - Error messages
  - Clear button

#### Using the Execute Tab

1. **Load a BOF**: Open a BOF file first (File > Open)

2. **Enter Arguments** (optional):
   ```
   Format: z:string i:123 s:456
   Types:
   - z: ANSI string
   - Z: Wide string
   - i: 32-bit integer
   - s: 16-bit integer
   - b: Binary (hex)
   ```

3. **Set Options**:
   - Check "Sandbox" for restricted execution
   - Check "Trace" for API call logging
   - Set timeout (default: 30 seconds)

4. **Execute**: Click the "Execute" button

5. **View Results**: 
   - Output appears in the console
   - Success/failure status shown
   - Execution time displayed
   - Errors shown if any

#### Example Usage

1. Open `whoami.x64.o`
2. Go to Run tab
3. Leave arguments empty (or enter `z:test` for testing)
4. Click "Execute"
5. View output in console

## Keyboard Shortcuts

- `Ctrl+O` - Open file
- `Ctrl+R` - Reload file
- `Ctrl+Q` - Quit (future)
- `Tab` - Navigate between tabs
- `Esc` - Close dialogs (future)

## Tips and Best Practices

### File Loading

- **Drag and Drop**: Drag BOF files directly onto the window
- **File Menu**: Use File > Open for file picker
- **Reload**: Use File > Reload to refresh analysis

### Analysis Workflow

1. **Start with Overview**: Get quick summary
2. **Check Sections**: Verify section structure
3. **Review Symbols**: Check for expected functions
4. **Examine Imports**: See what APIs are used
5. **Review Issues**: Check for lint findings
6. **View Disassembly**: Analyze code structure
7. **Test Execution**: Run in Run tab

### Execution Tips

- **Start Simple**: Test without arguments first
- **Use Sandbox**: Enable for untrusted BOFs
- **Enable Trace**: See what APIs are called
- **Check Timeout**: Increase for long-running BOFs

### Performance

- Large BOFs may take time to analyze
- Disassembly view may be slow for large code sections
- Use CLI for batch operations

## Troubleshooting

### GUI Won't Launch

- **Check Rust Installation**: Ensure Rust is properly installed
- **Check Build**: Ensure you built with `cargo build --release`
- **Check Dependencies**: GUI requires Windows (for execution features)

### File Won't Load

- **Check File Format**: Must be .o or .obj COFF file
- **Check File Path**: Use absolute paths if relative paths fail
- **Check Permissions**: Ensure file is readable

### Execution Fails

- **Check Arguments**: Verify argument format
- **Check Sandbox**: Disable if BOF needs full API access
- **Check Timeout**: Increase if BOF takes time
- **View Console**: Check error messages in output

### Performance Issues

- **Large Files**: Very large BOFs may be slow
- **Disassembly**: Disable disassembly view for large code sections
- **Use CLI**: CLI is faster for batch operations

## See Also

- [USER_GUIDE.md](USER_GUIDE.md) - Comprehensive user guide
- [CLI_REFERENCE.md](CLI_REFERENCE.md) - CLI command reference
- [README.md](../README.md) - Project overview

