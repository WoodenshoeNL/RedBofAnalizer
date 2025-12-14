# RedBofAnalizer Installation Guide

Step-by-step installation instructions for RedBofAnalizer.

## Prerequisites

### Required

- **Windows 10/11** (required for BOF execution features)
- **Rust 1.70+** (2021 edition)
- **Cargo** (comes with Rust)

### Optional

- **Git** (for cloning the repository)
- **Visual Studio Build Tools** (if using MSVC toolchain)

## Installing Rust

### Windows

1. **Download Rustup**
   - Visit https://rustup.rs/
   - Download and run `rustup-init.exe`

2. **Run Installer**
   - Follow the installation wizard
   - Choose default options (recommended)
   - This installs Rust, Cargo, and rustup

3. **Verify Installation**
   ```bash
   rustc --version
   cargo --version
   ```

### Alternative: Using Package Managers

#### Chocolatey

```powershell
choco install rust
```

#### Scoop

```powershell
scoop install rust
```

## Building RedBofAnalizer

### Clone Repository

```bash
git clone <repository-url>
cd RedBofAnalizer
```

### Build Options

#### Release Build (Recommended)

```bash
# Build optimized release version
cargo build --release

# Executable location:
# target/release/redbofanalyzer.exe
```

#### Debug Build

```bash
# Build debug version (faster compilation)
cargo build

# Executable location:
# target/debug/redbofanalyzer.exe
```

### Build Time

- **Release build**: ~2-5 minutes (first time)
- **Debug build**: ~1-2 minutes (first time)
- **Subsequent builds**: Faster (incremental compilation)

## Installation Methods

### Method 1: Use from Build Directory

Simply run from the build directory:

```bash
# Release build
target/release/redbofanalyzer.exe analyze bof.o

# Debug build
target/debug/redbofanalyzer.exe analyze bof.o
```

### Method 2: Add to PATH

Add the release directory to your PATH:

```powershell
# PowerShell (current session)
$env:Path += ";C:\path\to\RedBofAnalizer\target\release"

# PowerShell (permanent)
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\path\to\RedBofAnalizer\target\release", "User")
```

Then use from anywhere:

```bash
redbofanalyzer analyze bof.o
```

### Method 3: Copy Executable

Copy the executable to a convenient location:

```bash
# Copy release executable
copy target\release\redbofanalyzer.exe C:\Tools\

# Use from anywhere
C:\Tools\redbofanalyzer.exe analyze bof.o
```

### Method 4: Install with Cargo (Future)

If published to crates.io:

```bash
cargo install redbofanalyzer
```

## Verifying Installation

### Test Installation

```bash
# Check version
redbofanalyzer --version

# Check help
redbofanalyzer --help

# Test with a BOF (if available)
redbofanalyzer validate path/to/bof.o
```

### Run Tests

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --test unit_tests
```

## Troubleshooting

### "rustc: command not found"

**Problem**: Rust is not installed or not in PATH

**Solution**:
1. Install Rust using rustup
2. Restart terminal/PowerShell
3. Verify: `rustc --version`

### "linker not found"

**Problem**: No C linker available

**Solution**:
- Install Visual Studio Build Tools
- Or install MinGW-w64
- Or use `rustup` to install the MSVC toolchain

### Build Fails with "cannot find crate"

**Problem**: Dependencies not downloaded

**Solution**:
```bash
# Update dependencies
cargo update

# Clean and rebuild
cargo clean
cargo build --release
```

### "Permission denied" on Windows

**Problem**: Antivirus or Windows Defender blocking

**Solution**:
- Add exception for the executable
- Or build directory to antivirus exclusions

### GUI Won't Launch

**Problem**: Missing GUI dependencies or Windows version

**Solution**:
- Ensure Windows 10/11
- Check that release build completed successfully
- Try CLI mode first: `redbofanalyzer analyze bof.o`

## Updating

### Update from Source

```bash
# Pull latest changes
git pull

# Rebuild
cargo build --release
```

### Update Rust

```bash
# Update Rust toolchain
rustup update

# Update to latest stable
rustup update stable
```

## Uninstallation

### Remove Executable

Simply delete the executable file:

```bash
# If in PATH
del redbofanalyzer.exe

# If copied to custom location
del C:\Tools\redbofanalyzer.exe
```

### Remove Build Artifacts

```bash
# Clean build artifacts
cargo clean

# Remove entire directory
rmdir /s RedBofAnalizer
```

## System Requirements

### Minimum

- Windows 10 (64-bit)
- 4 GB RAM
- 500 MB disk space
- Rust 1.70+

### Recommended

- Windows 11 (64-bit)
- 8 GB RAM
- 1 GB disk space
- Rust latest stable

## Next Steps

After installation:

1. **Read the User Guide**: [USER_GUIDE.md](USER_GUIDE.md)
2. **Try CLI Commands**: [CLI_REFERENCE.md](CLI_REFERENCE.md)
3. **Explore GUI**: [GUI_GUIDE.md](GUI_GUIDE.md)
4. **Test with BOFs**: Use the `test` command or GUI

## See Also

- [USER_GUIDE.md](USER_GUIDE.md) - Comprehensive user guide
- [README.md](../README.md) - Project overview
- [Rust Installation Guide](https://www.rust-lang.org/tools/install)

