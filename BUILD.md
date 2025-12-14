# Building RedBofAnalizer

## Quick Reference

**Standard build (YARA enabled by default):**
```bash
cargo build
# or
cargo build --release
```

**To build without YARA:**
```bash
cargo build --no-default-features
# or for release
cargo build --release --no-default-features
```

## Standard Build (With YARA) ⭐ Default

YARA support is **enabled by default**. The `vendored` feature automatically builds YARA from source - no manual setup needed!

**To build with YARA (default):**
```bash
cargo build
# or
cargo build --release
```

The `vendored` feature in `yara-sys` will automatically download and build YARA - you don't need to install anything manually!

## Building Without YARA Support (Optional)

If you want to build without YARA support (e.g., to avoid build dependencies or reduce binary size):

```bash
cargo build --no-default-features
# or for release
cargo build --release --no-default-features
```

This will compile all core features without requiring YARA or libclang. The application will work fully without YARA - the YARA tab will simply show that YARA bindings are not available.

**Alternative:** If you prefer to use system-installed YARA (via vcpkg), see the manual setup options below.

YARA support requires additional dependencies (only if not using vendored feature):

### Windows Requirements

1. **Install YARA C Library (Development Files):**
   
   **Option A: Build from Source (Recommended)**
   
   You need the YARA development files (headers and libraries), not just the executables:
   
   ```powershell
   # Install prerequisites
   # - Visual Studio with C++ build tools
   # - CMake (https://cmake.org/download/)
   # - Git
   
   # Step 1: Clone YARA repository (if you haven't already)
   cd C:\tools
   git clone https://github.com/VirusTotal/yara.git
   # OR if you already have it, make sure you're in the right directory
   cd C:\tools\yara
   
   # Step 2: Verify you have the source code
   # Check if CMakeLists.txt exists
   Test-Path CMakeLists.txt
   # If this returns False, you don't have the source code - re-clone the repository
   
   # Step 3: Create build directory (outside the source tree is fine)
   mkdir build
   cd build
   
   # Step 4: Configure with CMake
   # Make sure you're in the build directory and pointing to the source directory
   cmake .. -A x64
   
   # If you get "CMakeLists.txt not found" error:
   # - Make sure you cloned the full repository (not just downloaded a zip)
   # - Check that you're in C:\tools\yara\build and the source is in C:\tools\yara
   # - Verify: Test-Path ..\CMakeLists.txt should return True
   
   # Step 5: Build
   cmake --build . --config Release
   
   # This will create:
   # - yara.h in the libyara/include directory (or include directory)
   # - yara.lib and yara.dll in the build\Release directory
   ```
   
   **Troubleshooting CMake Errors:**
   
   If you get "CMakeLists.txt not found":
   ```powershell
   # Verify you have the source code
   cd C:\tools\yara
   dir CMakeLists.txt
   
   # If it doesn't exist, you need to clone the repository properly:
   cd C:\tools
   # Remove the old directory if it exists
   Remove-Item -Recurse -Force yara -ErrorAction SilentlyContinue
   # Clone fresh
   git clone https://github.com/VirusTotal/yara.git
   cd yara
   # Verify
   Test-Path CMakeLists.txt  # Should return True
   ```
   
   **Alternative: Use Visual Studio Solution (if CMake fails)**
   
   Some YARA versions include Visual Studio project files:
   ```powershell
   cd C:\tools\yara
   # Look for .sln files
   dir *.sln
   # If found, open in Visual Studio and build
   ```
   
   After building, set environment variables **permanently**:
   
   **Option A: Using PowerShell (Permanent - User Level)**
   ```powershell
   # Set permanently for current user
   [System.Environment]::SetEnvironmentVariable("YARA_LIBRARY_PATH", "C:\path\to\yara\build\Release", "User")
   [System.Environment]::SetEnvironmentVariable("YARA_INCLUDE_PATH", "C:\path\to\yara\libyara\include", "User")
   
   # Refresh current session (or restart PowerShell)
   $env:YARA_LIBRARY_PATH = [System.Environment]::GetEnvironmentVariable("YARA_LIBRARY_PATH", "User")
   $env:YARA_INCLUDE_PATH = [System.Environment]::GetEnvironmentVariable("YARA_INCLUDE_PATH", "User")
   ```
   
   **Option B: Using System Properties (GUI)**
   1. Press `Win + R`, type `sysdm.cpl`, press Enter
   2. Go to "Advanced" tab → Click "Environment Variables"
   3. Under "User variables", click "New"
   4. Add:
      - Variable name: `YARA_LIBRARY_PATH`
      - Variable value: `C:\path\to\yara\build\Release`
   5. Click "New" again and add:
      - Variable name: `YARA_INCLUDE_PATH`
      - Variable value: `C:\path\to\yara\libyara\include`
   6. Click "OK" on all dialogs
   7. **Restart your terminal/PowerShell** for changes to take effect
   
   **Option C: Using Command Prompt (Permanent - User Level)**
   ```cmd
   setx YARA_LIBRARY_PATH "C:\path\to\yara\build\Release"
   setx YARA_INCLUDE_PATH "C:\path\to\yara\libyara\include"
   ```
   Note: `setx` requires restarting the terminal to take effect.
   
   **For Current Session Only (Temporary):**
   ```powershell
   # These only last for the current PowerShell session
   $env:YARA_LIBRARY_PATH = "C:\path\to\yara\build\Release"
   $env:YARA_INCLUDE_PATH = "C:\path\to\yara\libyara\include"
   ```
   
   **Option B: Use Pre-built Development Package**
   
   Some distributions provide development packages. You need:
   - `yara.h` header file
   - `libyara.lib` or `yara.lib` (import library) or `libyara.dll`/`yara.dll` (dynamic library)
   - **Note:** vcpkg installs `libyara.lib` (Unix naming convention)
   
   Place them in a directory and set **permanently**:
   ```powershell
   # Permanent (User level)
   [System.Environment]::SetEnvironmentVariable("YARA_LIBRARY_PATH", "C:\path\to\yara\lib", "User")
   [System.Environment]::SetEnvironmentVariable("YARA_INCLUDE_PATH", "C:\path\to\yara\include", "User")
   
   # Refresh current session
   $env:YARA_LIBRARY_PATH = [System.Environment]::GetEnvironmentVariable("YARA_LIBRARY_PATH", "User")
   $env:YARA_INCLUDE_PATH = [System.Environment]::GetEnvironmentVariable("YARA_INCLUDE_PATH", "User")
   ```
   

2. **Install LLVM/Clang (for libclang):**
   
   ✅ You already have this installed! Just verify and set permanently:
   ```powershell
   # Verify libclang.dll exists
   Test-Path "C:\Program Files\LLVM\bin\libclang.dll"
   
   # Set environment variable permanently (if not already set)
   [System.Environment]::SetEnvironmentVariable("LIBCLANG_PATH", "C:\Program Files\LLVM\bin", "User")
   
   # Refresh current session
   $env:LIBCLANG_PATH = [System.Environment]::GetEnvironmentVariable("LIBCLANG_PATH", "User")
   ```

3. **Verify Installation:**
   
   Before building, verify all paths are set correctly:
   ```powershell
   # Check YARA library path
   $env:YARA_LIBRARY_PATH
   
   # Check YARA include path (if set)
   $env:YARA_INCLUDE_PATH
   
   # Check libclang path
   $env:LIBCLANG_PATH
   
   # Verify files exist
   # Note: vcpkg installs libyara.lib (not yara.lib) - this is normal!
   Test-Path "$env:YARA_LIBRARY_PATH\libyara.lib"  # or libyara.dll
   Test-Path "$env:YARA_INCLUDE_PATH\yara.h"
   Test-Path "$env:LIBCLANG_PATH\libclang.dll"
   ```

4. **Build with YARA feature:**
   ```powershell
   # Make sure environment variables are set in the same PowerShell session
   cargo build --features yara
   
   # Or for release
   cargo build --release --features yara
   ```

**Important Notes:**
- You need **development files** (headers and libraries), not just executables
- `yara64.exe` and `yarac64.exe` are runtime executables, not development files
- The `yara-sys` crate needs `yara.h` to generate Rust bindings
- If you only have executables, you'll need to build YARA from source or find a development package

### Linux Requirements

1. **Install YARA:**
   ```bash
   sudo apt-get install yara libyara-dev  # Debian/Ubuntu
   # or
   sudo yum install yara yara-devel      # RHEL/CentOS
   ```

2. **Install LLVM/Clang:**
   ```bash
   sudo apt-get install llvm clang libclang-dev  # Debian/Ubuntu
   ```

3. **Build with YARA feature:**
   ```bash
   cargo build --features yara
   ```

## Troubleshooting

### Error: "CMakeLists.txt not found" or "The source directory does not appear to contain CMakeLists.txt"

**This is expected!** YARA doesn't use CMake - it uses **autotools** (configure.ac, Makefile.am) on Unix and **Visual Studio project files** on Windows. See the [YARA GitHub repository](https://github.com/VirusTotal/yara) structure.

**Solution:**
```powershell
# YARA doesn't have CMakeLists.txt - it uses different build systems

# Option 1: Use vcpkg (Easiest) ⭐ RECOMMENDED
cd C:\tools
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg install yara:x64-windows
# Then set environment variables as shown in Option A above

# Option 2: Use Visual Studio project files
cd C:\tools\yara-src\windows
# Look for .sln or .vcxproj files
dir *.sln, *.vcxproj
# Open in Visual Studio or build with MSBuild

# Option 3: Use MSYS2/MinGW to build with autotools (advanced)
# This requires installing MSYS2 and using the autotools build system
```

**Note:** The easiest way is to use **vcpkg** (Option A) - it handles all the complexity for you!

### Error: "Unable to find libclang"

This means libclang is not installed or not in PATH.

**Solution:**
- Install LLVM/Clang (see above)
- Set `LIBCLANG_PATH` environment variable to the directory containing `clang.dll` (Windows) or `libclang.so` (Linux)

### Error: "couldn't find yara library" or "yara.h file not found"

This means YARA development files are not installed or not found.

**Common Issues:**
- You only have YARA executables (`yara64.exe`, `yarac64.exe`) but not the development files
- `YARA_LIBRARY_PATH` points to the wrong directory (executables instead of libraries)
- `yara.h` header file is missing

**Solution:**
1. **Verify you have development files:**
   ```powershell
   # You need these files:
   # - yara.h (header file)
   # - libyara.lib or yara.lib (library file) - vcpkg uses libyara.lib
   
   # Check if you have them
   dir "$env:YARA_LIBRARY_PATH\yara.*"
   dir "$env:YARA_INCLUDE_PATH\yara.h"
   ```

2. **If you only have executables:**
   - You need to build YARA from source (see Option A above)
   - Or find a Windows development package that includes headers and libraries

3. **Set correct paths:**
   ```powershell
   # YARA_LIBRARY_PATH should point to where libyara.lib (or yara.lib) or libyara.dll/yara.dll is
   # Note: vcpkg installs libyara.lib, not yara.lib
   $env:YARA_LIBRARY_PATH = "C:\path\to\yara\lib"
   
   # YARA_INCLUDE_PATH should point to where yara.h is
   $env:YARA_INCLUDE_PATH = "C:\path\to\yara\include"
   ```

4. **If using vcpkg:**
   ```powershell
   $env:VCPKG_ROOT = "C:\path\to\vcpkg"
   ```

### Building Without YARA

If you don't need YARA support, build with `--no-default-features`:
```bash
cargo build --no-default-features
# or for release
cargo build --release --no-default-features
```

The application will work fully without YARA - the YARA tab will show a message that YARA bindings are not available.

## Feature Status

- **Core Features**: Always available
- **YARA Support**: Enabled by default (use `--no-default-features` to disable)
- **Stack Analysis**: Always available (requires disassembly)
- **All Other Features**: Always available

