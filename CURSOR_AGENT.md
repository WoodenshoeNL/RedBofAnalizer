# RedBofAnalizer - Cursor AI Agent Guide

> **Note for AI Agents**: This file is specifically for Cursor AI agents. Other AI agents should ignore this file. This document provides context and guidance for developing the RedBofAnalizer project within Cursor.

---

## Project Context

### What is RedBofAnalizer?

**RedBofAnalizer** is a Beacon Object File (BOF) analyzer and execution tool designed to:
- **Analyze BOFs**: Parse, validate, and inspect BOF files
- **Execute BOFs**: Run BOFs locally for testing and troubleshooting
- **Test Suite**: Execute all BOFs in the `src/` directory for comprehensive testing
- **Troubleshoot**: Help identify and fix issues with BOF execution

### Project Structure

```
c:\bofproject\
├── RedBofAnalizer/          ← YOUR DEFAULT WORKING DIRECTORY
│   ├── CURSOR_AGENT.md      ← This file (Cursor-specific)
│   └── [your code here]
├── src/                      ← Test BOFs (reference only)
│   ├── CS-Situational-Awareness-BOF/
│   ├── CS-Remote-OPs-BOF/
│   ├── C2-Tool-Collection/
│   ├── unhook-bof/
│   └── bof_template/
│       └── beacon.h         ← BOF specifications (Cobalt Strike)
├── RedLoader/               ← Reference implementation (inspiration only)
│   └── [Rust-based BOF loader - has flaws, don't copy directly]
├── RedBof/                  ← BOF collection (troubleshooting target)
│   └── [BOFs that RedLoader has trouble executing]
└── RedBofAnalizerG/          ← OFF LIMITS (parallel development)
```

### Key Directories

- **`RedBofAnalizer/`**: **ALWAYS** your default directory for programming
- **`src/`**: Contains various BOF repositories for testing - the final tool should run them all
- **`src/bof_template/beacon.h`**: Cobalt Strike BOF API specifications - **critical reference**
- **`RedLoader/`**: Can be used as inspiration, but has flaws - **do not copy directly**
- **`RedBof/`**: BOF collection that RedLoader struggles with - **troubleshooting target**
- **`RedBofAnalizerG/`**: **OFF LIMITS** - parallel development project

### Project Documentation

The project includes comprehensive planning and specification documents:

- **`PLAN.md`**: Detailed development plan with phases, priorities, and timeline
  - Development phases (Foundation, Analysis, Execution, CLI, GUI, etc.)
  - Project structure and dependencies
  - Success criteria and risk mitigation
  - **Reference this for understanding the development roadmap**

- **`SPEC.md`**: Detailed technical specifications
  - Architecture and component specifications
  - BOF file format details
  - Core functionality specifications (Parser, Analyzer, Executor)
  - CLI and GUI interface specifications
  - Data models and error handling
  - **Reference this for implementation details and requirements**

**When implementing features:**
1. Check `PLAN.md` to understand the phase and priorities
2. Check `SPEC.md` for detailed technical requirements
3. Follow the specifications closely to ensure consistency
4. Update documentation if requirements change

---

## Development Principles

### 1. Default Working Directory

**ALWAYS** work in `RedBofAnalizer/` directory:
- All new files should be created in `RedBofAnalizer/`
- When reading files, use paths relative to `c:\bofproject\` or absolute paths
- When writing code, assume `RedBofAnalizer/` as the project root

### 2. BOF Specifications

**Reference `src/bof_template/beacon.h`** for:
- Beacon API function signatures
- Data structures (datap, formatp, BEACON_INFO, etc.)
- Callback types (CALLBACK_OUTPUT, CALLBACK_ERROR, etc.)
- Memory management structures
- System call APIs

This file defines the **official Cobalt Strike BOF interface** - your implementation must match these specifications.

### 3. Learning from RedLoader

**RedLoader** (`RedLoader/`) can provide:
- Implementation patterns and approaches
- COFF parsing techniques
- Memory management strategies
- Error handling patterns

**However**:
- RedLoader has known flaws - don't copy bugs
- RedLoader is a first attempt - improve upon it
- RedLoader may have architectural issues - design better solutions
- Use it as **inspiration**, not a template

### 4. Testing with Real BOFs

**Test BOFs** are in `src/`:
- `CS-Situational-Awareness-BOF/` - Cobalt Strike situational awareness BOFs
- `CS-Remote-OPs-BOF/` - Remote operations BOFs
- `C2-Tool-Collection/` - Various C2 tool BOFs
- `unhook-bof/` - Unhooking BOFs
- `bof_template/` - Template and specifications
  - **`bof_template/examples/`** - Official Cobalt Strike example BOFs
    - **CRITICAL**: These are official BOF examples from the Cobalt Strike repository
    - **DO NOT MODIFY** these example BOF files - they must remain unchanged
    - The tool must work with these BOFs as-is, even if they have parameter detection issues
    - If a BOF has issues, fix the tool's implementation, not the BOF

**Troubleshooting BOFs** are in `RedBof/`:
- These BOFs cause issues in RedLoader
- Your tool should be able to execute them successfully
- Use them to identify and fix common BOF loading problems

**Goal**: The final tool should be able to **run all BOFs** in `src/` successfully.

---

## Technical Requirements

### BOF File Format

BOFs are **COFF (Common Object File Format)** object files:
- Compiled with `-c` flag (compile only, no linking)
- Position-independent code (PIC)
- External symbol references (Windows APIs, Beacon functions)
- Relocation entries for address fixing
- No standard library dependencies

### Core Functionality Required

1. **COFF Parser**
   - Parse COFF headers and sections
   - Extract symbol table
   - Process relocation entries
   - Handle string table

2. **Memory Management**
   - Allocate executable memory for BOF code
   - Map sections to memory
   - Apply relocations
   - Set proper memory protections

3. **Symbol Resolution**
   - Resolve Windows API functions (kernel32.dll, ntdll.dll, etc.)
   - Resolve Beacon API functions (BeaconPrintf, BeaconDataParse, etc.)
   - Handle import symbols (`__imp_LIBRARY$Function` format)

4. **Beacon API Implementation**
   - Implement all functions from `beacon.h`
   - Data parsing (BeaconDataParse, BeaconDataInt, etc.)
   - Output functions (BeaconPrintf, BeaconOutput)
   - Format functions (BeaconFormatAlloc, BeaconFormatPrintf, etc.)
   - Token functions (BeaconUseToken, BeaconRevertToken)
   - Memory functions (BeaconVirtualAlloc, etc.)

5. **Execution Engine**
   - Load BOF into memory
   - Resolve all symbols
   - Apply relocations
   - Call BOF entry point (`go` function)
   - Handle BOF callbacks
   - Capture output

6. **Testing Framework**
   - Discover BOFs in `src/` directories
   - Execute each BOF
   - Report success/failure
   - Capture and display output
   - Handle errors gracefully

---

## Coding Guidelines

### Language Choice

**Rust**: Memory safety, good for systems programming (like RedLoader)


**Recommendation**: Consider what will work best for BOF execution and Windows API integration.

### Code Organization

```
RedBofAnalizer/
├── CURSOR_AGENT.md          ← This file
├── README.md                 ← Project documentation
├── [language-specific files]
│   ├── src/                  ← Source code
│   ├── tests/                ← Test files
│   ├── examples/             ← Example BOFs
│   └── docs/                 ← Additional documentation
└── [build/config files]
```

### Error Handling

- **Comprehensive**: Handle all error conditions
- **Descriptive**: Error messages should explain what went wrong
- **Contextual**: Include relevant information (file paths, addresses, etc.)
- **Graceful**: Don't crash on BOF errors - report and continue

### Logging and Output

- **Verbose mode**: Detailed execution information
- **Progress indicators**: Show what's happening during execution
- **Error reporting**: Clear error messages with context
- **Output capture**: Capture BOF output (BeaconPrintf, etc.)

### Testing Strategy

1. **Unit Tests**: Test individual components (COFF parser, symbol resolver, etc.)
2. **Integration Tests**: Test full BOF loading and execution
3. **Regression Tests**: Test with BOFs from `src/` and `RedBof/`
4. **Error Tests**: Test with malformed/invalid BOFs

---

## Common BOF Loading Challenges

### 1. Relocation Processing

**Problem**: Incorrect relocation calculations cause crashes
- **Solution**: Carefully implement relocation types (AMD64_REL32, ADDR64, etc.)
- **Reference**: PE/COFF specification, RedLoader implementation (but fix bugs)

### 2. Symbol Resolution

**Problem**: Unresolved symbols cause execution failures
- **Solution**: Properly parse import symbols (`__imp_LIBRARY$Function`)
- **Load libraries**: Use LoadLibrary/GetProcAddress correctly
- **Handle missing symbols**: Report clearly which symbols are missing

### 3. Memory Protection

**Problem**: Code sections need execute permission, data sections need read/write
- **Solution**: Set proper memory protections (PAGE_EXECUTE_READ, PAGE_READWRITE)
- **Alignment**: Ensure page-aligned allocations

### 4. Argument Parsing

**Problem**: BOFs receive arguments in Beacon's packed format
- **Solution**: Implement BeaconDataParse correctly
- **Test**: Use various argument types (int, string, wide string, binary)

### 5. Output Handling

**Problem**: BOF output must be captured and displayed
- **Solution**: Implement BeaconPrintf/BeaconOutput callbacks
- **Format**: Handle different output types (OUTPUT, ERROR, CUSTOM)

---

## Development Workflow

### When Starting Development

1. **Review project documentation**: Read `PLAN.md` and `SPEC.md` to understand the full scope and requirements
2. **Understand the goal**: Build a tool that can analyze and execute BOFs (see `PLAN.md` for detailed phases)
3. **Review beacon.h**: Understand the BOF API requirements
4. **Check specifications**: Refer to `SPEC.md` for detailed technical requirements
5. **Examine RedLoader**: Learn from it, but identify flaws to avoid
6. **Test with real BOFs**: Use BOFs from `src/` and `RedBof/`
7. **Iterate**: Fix issues as you discover them

### When Implementing Features

1. **Check the plan**: Review `PLAN.md` to understand which phase the feature belongs to and its priority
2. **Review specifications**: Check `SPEC.md` for detailed technical requirements and interface specifications
3. **Start small**: Get basic COFF parsing working first (follow phase order in `PLAN.md`)
4. **Add incrementally**: Memory management → Symbol resolution → Execution (as specified in `PLAN.md`)
5. **Follow specs**: Ensure implementation matches `SPEC.md` requirements
6. **Test frequently**: Test with real BOFs after each major feature
7. **Document**: Comment complex code, explain design decisions

### When Troubleshooting

1. **Identify the issue**: What BOF fails? What error occurs?
2. **Compare with RedLoader**: Does RedLoader have the same issue?
3. **Check beacon.h**: Are you implementing the API correctly?
4. **Test incrementally**: Simplify the BOF to isolate the problem
5. **Fix and verify**: Fix the issue and test with multiple BOFs

---

## File Path Conventions

### Absolute Paths

When referencing files outside `RedBofAnalizer/`, use absolute paths:
```
c:\bofproject\src\bof_template\beacon.h
c:\bofproject\src\CS-Situational-Awareness-BOF\...
c:\bofproject\RedLoader\...
c:\bofproject\RedBof\...
```

### Relative Paths

When referencing files within `RedBofAnalizer/`, use relative paths:
```
src\main.rs
tests\test_bofs\hello.o
docs\api.md
```

### Path Handling

- Use platform-appropriate path separators (`\` on Windows)
- Handle both absolute and relative paths
- Normalize paths when comparing

---

## Interaction Guidelines

### When User Asks to Implement a Feature

1. **Acknowledge**: Confirm understanding
2. **Plan**: Outline the implementation approach
3. **Check references**: Review `beacon.h`, RedLoader (for inspiration)
4. **Implement**: Write code in `RedBofAnalizer/`
5. **Test**: Test with BOFs from `src/` or `RedBof/`
6. **Document**: Update documentation if needed

### When User Asks to Fix a Bug

1. **Understand**: Get error messages, logs, reproduction steps
2. **Locate**: Find the problematic code
3. **Analyze**: Determine root cause
4. **Compare**: Check if RedLoader has the same issue
5. **Fix**: Implement the fix
6. **Test**: Verify with multiple BOFs
7. **Prevent**: Add test case if applicable

### When User Asks to Run BOFs

1. **Discover**: Find BOFs in `src/` directories
2. **Load**: Parse and load each BOF
3. **Execute**: Run the BOF entry point
4. **Report**: Show results (success/failure, output)
5. **Handle errors**: Continue with other BOFs if one fails

---

## Important Reminders

### ✅ DO

- ✅ Always work in `RedBofAnalizer/` directory
- ✅ Review `PLAN.md` and `SPEC.md` before starting development
- ✅ Reference `src/bof_template/beacon.h` for API specifications
- ✅ Follow the development phases outlined in `PLAN.md`
- ✅ Implement features according to `SPEC.md` specifications
- ✅ Test with real BOFs from `src/` and `RedBof/`
- ✅ Learn from RedLoader but improve upon it
- ✅ Handle errors gracefully
- ✅ Document complex code
- ✅ Test incrementally

### ❌ DON'T

- ❌ Don't copy RedLoader bugs or flawed patterns
- ❌ Don't modify files in `RedBofAnalizerG/` (off limits)
- ❌ **Don't modify example BOF files in `src/bof_template/examples/`** - These are official Cobalt Strike BOF examples and must remain unchanged. The tool should work with these BOFs as-is.
- ❌ Don't assume RedLoader is correct - verify against `beacon.h`
- ❌ Don't ignore error cases
- ❌ Don't hardcode paths - use proper path handling
- ❌ Don't skip testing with real BOFs

---

## Resources

### In This Repository

- **`PLAN.md`**: Detailed development plan with phases, priorities, and timeline
- **`SPEC.md`**: Comprehensive technical specifications for all components
- **`CURSOR_AGENT.md`**: This file - AI agent guidelines and context
- **`src/bof_template/beacon.h`**: Official Cobalt Strike BOF API
- **`RedLoader/`**: Reference implementation (with known issues)
- **`RedBof/`**: BOFs that need troubleshooting
- **`src/`**: Test BOF collections

### External References

- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [COFF Object File Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-object-file-format-object-and-image)
- [Cobalt Strike BOF Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm)

---

## Success Criteria

The RedBofAnalizer project is successful when:

1. ✅ Can parse COFF/BOF files correctly
2. ✅ Can load BOFs into memory and resolve symbols
3. ✅ Can execute BOFs and capture output
4. ✅ Can run **all** BOFs in `src/` successfully
5. ✅ Can execute BOFs from `RedBof/` that RedLoader struggles with
6. ✅ Provides clear error messages when BOFs fail
7. ✅ Has comprehensive testing framework

---

**Remember**: This is a tool for analyzing and executing BOFs. Focus on correctness, reliability, and the ability to troubleshoot BOF execution issues. Learn from RedLoader, but build something better.

