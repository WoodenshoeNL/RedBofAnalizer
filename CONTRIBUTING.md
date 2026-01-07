# Contributing to RedBofAnalizer

Thank you for your interest in contributing to RedBofAnalizer! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Testing](#testing)
- [Documentation](#documentation)
- [Areas for Contribution](#areas-for-contribution)

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful, inclusive, and professional in all interactions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/RedBofAnalizer.git
   cd RedBofAnalizer
   ```
3. **Add the upstream repository**:
   ```bash
   git remote add upstream https://github.com/original-owner/RedBofAnalizer.git
   ```

## Development Setup

### Prerequisites

- **Rust 1.70+** (2021 edition)
- **Windows 10/11** (for execution features)
- **Cargo** (comes with Rust)
- **Git**

### Building the Project

```bash
# Build in debug mode
cargo build

# Build in release mode
cargo build --release

# Run tests
cargo test

# Check for compilation errors
cargo check

# Run clippy for linting
cargo clippy
```

### Optional Dependencies

- **YARA** (optional, enabled by default)
  - Can be built without YARA using `cargo build --no-default-features`
  - See [BUILD.md](BUILD.md) for detailed setup instructions

## Contributing Guidelines

### Before You Start

1. **Check existing issues** - Your idea might already be discussed
2. **Open an issue first** for significant changes to discuss the approach
3. **Keep changes focused** - One feature or fix per pull request
4. **Follow the project structure** - Maintain consistency with existing code

### Types of Contributions

We welcome various types of contributions:

- 🐛 **Bug fixes** - Fix issues and improve reliability
- ✨ **New features** - Add functionality (discuss in issues first)
- 📚 **Documentation** - Improve docs, add examples, fix typos
- 🧪 **Tests** - Add or improve test coverage
- 🎨 **UI/UX improvements** - Enhance the GUI interface
- 🔍 **Analysis enhancements** - Improve BOF analysis capabilities
- ⚡ **Performance** - Optimize code and reduce resource usage

## Submitting Changes

### Workflow

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following the code style guidelines

3. **Write or update tests** for your changes

4. **Update documentation** if needed

5. **Commit your changes** with clear, descriptive messages:
   ```bash
   git commit -m "Add feature: description of what you did"
   ```

6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Open a Pull Request** on GitHub with:
   - Clear title and description
   - Reference to related issues (if any)
   - Description of changes and testing done

### Commit Message Guidelines

- Use clear, descriptive commit messages
- Start with a verb in imperative mood (e.g., "Add", "Fix", "Update")
- Keep the first line under 72 characters
- Add detailed description if needed (separated by blank line)

Examples:
```
Add support for new relocation type REL32_1

Implement parsing and application of IMAGE_REL_AMD64_REL32_1
relocations to improve compatibility with certain BOF compilers.
```

```
Fix memory leak in Beacon API cleanup

Ensure all allocated memory is properly freed when BOF execution
completes, preventing memory leaks in batch testing scenarios.
```

## Code Style

### Rust Style Guide

- Follow **Rust standard formatting** (use `cargo fmt`)
- Follow **Clippy suggestions** (use `cargo clippy`)
- Use **meaningful variable names**
- Add **comments** for complex logic
- Keep functions **focused and small**
- Use **appropriate error types** (`anyhow::Result` or custom errors)

### Formatting

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt --check
```

### Linting

```bash
# Run clippy
cargo clippy

# Run clippy with all warnings
cargo clippy -- -W clippy::all
```

### Code Organization

- **Modules**: Keep related functionality together
- **Visibility**: Use appropriate visibility modifiers (`pub`, `pub(crate)`, etc.)
- **Imports**: Organize imports logically (std, external, internal)
- **Error Handling**: Use `Result` types, avoid panics in library code

### Example Code Structure

```rust
//! Module-level documentation explaining the module's purpose

use std::path::Path;

use anyhow::Result;
use thiserror::Error;

/// Function-level documentation
/// 
/// # Arguments
/// * `path` - Description of argument
/// 
/// # Returns
/// Description of return value
/// 
/// # Errors
/// Description of error conditions
pub fn example_function(path: &Path) -> Result<()> {
    // Implementation
    Ok(())
}
```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture

# Run ignored tests (long-running)
cargo test -- --ignored
```

### Writing Tests

- **Unit tests**: Place in the same file with `#[cfg(test)]`
- **Integration tests**: Place in `tests/` directory
- **Test coverage**: Aim for high coverage of new code
- **Test names**: Use descriptive names explaining what is tested

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_does_something() {
        // Arrange
        let input = create_test_input();
        
        // Act
        let result = function_under_test(input);
        
        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_value);
    }
}
```

## Documentation

### Code Documentation

- **Public APIs**: Must have documentation comments (`///`)
- **Complex logic**: Add inline comments explaining the approach
- **Module docs**: Add module-level documentation (`//!`)

### User Documentation

- **User-facing changes**: Update relevant docs in `docs/`
- **CLI changes**: Update `docs/CLI_REFERENCE.md`
- **GUI changes**: Update `docs/GUI_GUIDE.md`
- **New features**: Add examples to `docs/USER_GUIDE.md`

### Documentation Style

- Use **Markdown** for all documentation
- Include **code examples** where helpful
- Keep documentation **up-to-date** with code changes

## Areas for Contribution

### High Priority Areas

1. **Testing**
   - GUI tests
   - Performance benchmarks
   - Edge case coverage

2. **Documentation**
   - Developer documentation
   - Architecture overview
   - API reference

3. **Performance**
   - Profiling and optimization
   - Memory usage improvements
   - Caching strategies

### Feature Areas

1. **Analysis Enhancements**
   - Additional lint rules
   - Improved OpSec analysis
   - Enhanced compatibility detection

2. **Execution Features**
   - Advanced sandboxing
   - Better error reporting
   - Execution profiling

3. **GUI Improvements**
   - UI/UX enhancements
   - Additional visualization
   - Better error handling

4. **CLI Enhancements**
   - Additional output formats
   - Better error messages
   - Improved batch processing

## Pull Request Process

### Review Checklist

Before submitting a PR, ensure:

- ✅ Code follows style guidelines
- ✅ All tests pass (`cargo test`)
- ✅ Code is formatted (`cargo fmt`)
- ✅ No clippy warnings (`cargo clippy`)
- ✅ Documentation is updated
- ✅ Commit messages are clear
- ✅ Changes are focused and logical

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Other (please describe)

## Testing
Describe how you tested your changes

## Related Issues
Closes #issue_number

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

### Review Process

1. **Automated checks** must pass (CI/CD)
2. **Code review** by maintainers
3. **Feedback** and requested changes
4. **Approval** and merge

## Questions?

- **Open an issue** for questions or discussions
- **Check existing issues** for similar questions
- **Review documentation** in `docs/` directory

## License

By contributing to RedBofAnalizer, you agree that your contributions will be licensed under the GPL-3.0 License.

---

Thank you for contributing to RedBofAnalizer! 🎉

