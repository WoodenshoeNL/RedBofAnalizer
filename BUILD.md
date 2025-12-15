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

1. **Install YARA C Library (Development Files) via vcpkg (Recommended)**
   
   You need the YARA **development files** (headers and libraries), not just the `yara64.exe` / `yarac64.exe` executables. The simplest and tested setup on Windows is using **vcpkg**:
   
   ```powershell
   # 1) Install vcpkg (once)
   cd C:\tools
   git clone https://github.com/microsoft/vcpkg.git
   cd .\vcpkg
   .\bootstrap-vcpkg.bat
   
   # 2) Install YARA for 64‑bit Windows
   .\vcpkg.exe install yara:x64-windows
   ```
   
   After installation, vcpkg will place YARA headers and libraries under a path similar to:
   
   - C:\tools\vcpkg\installed\x64-windows\include\yara.h
   - C:\tools\vcpkg\installed\x64-windows\lib\libyara.lib
   
   Set environment variables **once** so `yara-sys` can find them:
   
   ```powershell
   # Adjust the paths if your vcpkg root is different
   [System.Environment]::SetEnvironmentVariable("YARA_LIBRARY_PATH", "C:\tools\vcpkg\installed\x64-windows\lib", "User")
   [System.Environment]::SetEnvironmentVariable("YARA_INCLUDE_PATH", "C:\tools\vcpkg\installed\x64-windows\include", "User")
   
   # Refresh current PowerShell session
   $env:YARA_LIBRARY_PATH = [System.Environment]::GetEnvironmentVariable("YARA_LIBRARY_PATH", "User")
   $env:YARA_INCLUDE_PATH = [System.Environment]::GetEnvironmentVariable("YARA_INCLUDE_PATH", "User")
   ```
   
   Notes:
   - vcpkg installs **`libyara.lib`** (not `yara.lib`) – this is expected
   - `YARA_LIBRARY_PATH` must point to the directory that contains `libyara.lib`
   - `YARA_INCLUDE_PATH` must contain `yara.h`
   

2. **Install LLVM/Clang (for libclang):**
   
   YARA bindings on Windows require **libclang**. If you don’t have LLVM/Clang yet, install it and then set `LIBCLANG_PATH`.
   
   **Option A: Install via official LLVM installer (recommended)**
   
   1. Download the latest Windows installer from the LLVM website (`https://llvm.org/` → *Download* → *Windows*) (e.g. `LLVM-win64.exe`).
   2. Run the installer and keep the default install path `C:\Program Files\LLVM` (or note the custom path you choose).
   3. Ensure the **Clang** / **Clang tools** components are selected during setup.
   
   After installation, verify and configure:
   
   ```powershell
   # Verify libclang.dll exists (adjust path if you chose a different install dir)
   Test-Path "C:\Program Files\LLVM\bin\libclang.dll"
   
   # Set environment variable permanently (User level)
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

4. **Build (YARA enabled by default):**
   ```powershell
   # Make sure environment variables are set in the same PowerShell session
   cargo build
   
   # Or for release
   cargo build --release
   ```
   
   YARA is part of the **default features**, so no extra `--features` flag is required.  
   Use `--no-default-features` only if you explicitly want to **disable** YARA support.

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

**This is expected if you're trying to build YARA from source with CMake.** The official YARA project does **not** ship a `CMakeLists.txt` file by default.

**Recommended solution on Windows:** use **vcpkg** instead of building YARA manually:

```powershell
cd C:\tools
git clone https://github.com/microsoft/vcpkg.git
cd .\vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg.exe install yara:x64-windows
# Then set YARA_LIBRARY_PATH / YARA_INCLUDE_PATH as shown in the Windows Requirements section
```

This gives you a known‑good, tested layout that works with `yara-sys` on Windows.

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

