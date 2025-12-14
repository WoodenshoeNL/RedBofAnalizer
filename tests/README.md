# RedBofAnalizer Test Suite

This directory contains comprehensive tests for the RedBofAnalizer project.

## Test Structure

### Unit Tests
- **`unit_tests.rs`**: Tests for core functionality (argument parsing, Beacon API, symbol resolution)
- **`parser_tests.rs`**: Tests for COFF parser functionality
- **`analyzer_tests.rs`**: Tests for static analysis engine
- **`executor_tests.rs`**: Tests for BOF execution engine

### Integration Tests
- **`integration_tests.rs`**: End-to-end tests with real BOF files
- **`batch_tests.rs`**: Batch testing of multiple BOFs

### CLI Tests
- **`cli_tests.rs`**: Tests for command-line interface

### Common Utilities
- **`common/mod.rs`**: Shared test utilities and helpers

## Running Tests

### Run All Tests
```bash
cargo test
```

### Run Specific Test Suite
```bash
# Unit tests only
cargo test --test unit_tests

# Integration tests only
cargo test --test integration_tests

# Parser tests only
cargo test --test parser_tests
```

### Run Ignored Tests (Long-running)
```bash
# Run batch tests (requires BOF files in src/)
cargo test --test batch_tests -- --ignored

# Run CLI tests (requires built binary)
cargo test --test cli_tests -- --ignored
```

### Run with Output
```bash
# Show test output
cargo test -- --nocapture

# Show output for specific test
cargo test test_name -- --nocapture
```

## Test Requirements

### Required
- Rust 1.70+
- Windows 10/11 (for execution tests)
- Test BOF files in `../src/` directory

### Optional
- Built binary (`target/debug/redbofanalyzer.exe`) for CLI tests

## Test BOF Locations

Tests look for BOF files in:
- `../src/bof_template/examples/` - Official Cobalt Strike examples
- `../src/CS-Situational-Awareness-BOF/SA/` - CS SA BOFs
- `../src/CS-Remote-OPs-BOF/Remote/` - CS Remote Ops BOFs
- `../src/C2-Tool-Collection/BOF/` - Various C2 tool BOFs

## Test Coverage

### Current Coverage
- ✅ COFF parsing
- ✅ Symbol resolution
- ✅ Argument parsing and packing
- ✅ Beacon API emulation
- ✅ BOF execution (basic)
- ✅ Static analysis
- ✅ CLI commands (when binary available)

### Planned Coverage
- [ ] Full BOF execution with all BOFs in `src/`
- [ ] Error handling edge cases
- [ ] Performance benchmarks
- [ ] Memory leak detection
- [ ] GUI tests

## Writing New Tests

### Example Unit Test
```rust
#[test]
fn test_my_feature() {
    use redbofanalyzer::core::my_module;
    
    let result = my_module::do_something();
    assert!(result.is_ok());
}
```

### Example Integration Test
```rust
#[test]
fn test_bof_execution() {
    use redbofanalyzer::core::parser;
    use redbofanalyzer::core::executor;
    use std::time::Duration;
    
    let bof = parser::load_bof(&path).expect("Should parse");
    let result = executor::execute(&bof, &[], false, false, Duration::from_secs(30));
    assert!(result.is_ok());
}
```

## Test Best Practices

1. **Use `#[ignore]` for long-running tests** - Mark batch tests and CLI tests with `#[ignore]`
2. **Handle missing BOFs gracefully** - Tests should skip if BOF files aren't available
3. **Don't assert on execution success** - BOF execution may fail for valid reasons
4. **Use descriptive test names** - Test names should clearly describe what they test
5. **Add comments for complex tests** - Explain what the test is verifying

## Continuous Integration

Tests are designed to:
- Pass even when BOF files are not available (skip gracefully)
- Work in CI environments without GUI
- Provide clear error messages when they fail
- Run quickly for unit tests (< 1 second each)
- Allow long-running tests to be skipped with `#[ignore]`

## Troubleshooting

### Tests Fail with "No test BOFs found"
- Ensure BOF files exist in `../src/` directories
- Check that file extensions are `.o` or `.obj`
- Verify file paths are correct

### CLI Tests Fail
- Build the binary first: `cargo build`
- Ensure binary exists at `target/debug/redbofanalyzer.exe`

### Execution Tests Crash
- Some BOFs may crash during execution - this is expected
- Tests should handle crashes gracefully
- Check execution results rather than asserting success

