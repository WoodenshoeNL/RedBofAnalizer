//! Unit tests for core components
//!
//! Everything here exercises the Beacon API implementations, which are
//! Windows-gated in the library (`#[cfg(windows)]`), so this whole target
//! only builds on Windows. Cross-platform coverage lives in parser_tests,
//! pe_tests, analyzer_tests, cli_tests and integration_tests.
#![cfg(windows)]

mod common;

use redbofanalyzer::core::executor::arguments;
use redbofanalyzer::core::executor::beacon_api;
use redbofanalyzer::core::models::bof::Import;

#[test]
fn test_argument_parsing_string() {
    let packed = arguments::parse_arguments("z:test").expect("Should parse string argument");
    assert!(!packed.is_empty(), "Packed arguments should not be empty");
    
    // Verify we can parse it back
    let mut parser = beacon_api::DataParser {
        original: std::ptr::null(),
        buffer: std::ptr::null(),
        length: 0,
        size: 0,
    };
    unsafe {
        beacon_api::BeaconApi::beacon_data_parse(&mut parser, packed.as_ptr(), packed.len() as i32);
        let len = beacon_api::BeaconApi::beacon_data_length(&mut parser);
        assert!(len > 0, "Should have data to parse");
    }
}

#[test]
fn test_argument_parsing_int() {
    let packed = arguments::parse_arguments("i:42").expect("Should parse int argument");
    assert!(!packed.is_empty(), "Packed arguments should not be empty");
    
    // Verify we can parse it back
    let mut parser = beacon_api::DataParser {
        original: std::ptr::null(),
        buffer: std::ptr::null(),
        length: 0,
        size: 0,
    };
    unsafe {
        beacon_api::BeaconApi::beacon_data_parse(&mut parser, packed.as_ptr(), packed.len() as i32);
        let value = beacon_api::BeaconApi::beacon_data_int(&mut parser);
        assert_eq!(value, 42, "Should parse integer correctly");
    }
}

#[test]
fn test_argument_parsing_short() {
    let packed = arguments::parse_arguments("s:1234").expect("Should parse short argument");
    assert!(!packed.is_empty(), "Packed arguments should not be empty");
    
    // Verify we can parse it back
    let mut parser = beacon_api::DataParser {
        original: std::ptr::null(),
        buffer: std::ptr::null(),
        length: 0,
        size: 0,
    };
    unsafe {
        beacon_api::BeaconApi::beacon_data_parse(&mut parser, packed.as_ptr(), packed.len() as i32);
        let value = beacon_api::BeaconApi::beacon_data_short(&mut parser);
        assert_eq!(value, 1234, "Should parse short correctly");
    }
}

#[test]
fn test_argument_parsing_multiple() {
    let packed = arguments::parse_arguments("i:42 z:test s:123").expect("Should parse multiple arguments");
    assert!(!packed.is_empty(), "Packed arguments should not be empty");
    
    // Verify we can parse them back in order
    let mut parser = beacon_api::DataParser {
        original: std::ptr::null(),
        buffer: std::ptr::null(),
        length: 0,
        size: 0,
    };
    unsafe {
        beacon_api::BeaconApi::beacon_data_parse(&mut parser, packed.as_ptr(), packed.len() as i32);
        
        let int_val = beacon_api::BeaconApi::beacon_data_int(&mut parser);
        assert_eq!(int_val, 42, "Should parse first integer correctly");
        
        let str_len = beacon_api::BeaconApi::beacon_data_length(&mut parser);
        assert!(str_len > 0, "Should have string data");
        
        let mut size: i32 = 0;
        let str_ptr = beacon_api::BeaconApi::beacon_data_extract(&mut parser, &mut size);
        assert!(!str_ptr.is_null(), "Should extract string pointer");
        
        let short_val = beacon_api::BeaconApi::beacon_data_short(&mut parser);
        assert_eq!(short_val, 123, "Should parse short correctly");
    }
}

#[test]
fn test_argument_format_parsing() {
    // Test format string parsing
    let format = "z:test_string i:42 s:123";
    let packed = arguments::parse_arguments(format).expect("Should parse format string");
    
    assert!(!packed.is_empty(), "Should have packed data");
    
    // Verify we can parse it back
    let mut parser = beacon_api::DataParser {
        original: std::ptr::null(),
        buffer: std::ptr::null(),
        length: 0,
        size: 0,
    };
    unsafe {
        beacon_api::BeaconApi::beacon_data_parse(&mut parser, packed.as_ptr(), packed.len() as i32);
        
        // Arguments are packed in the order they appear: z:test_string i:42 s:123
        // So first we extract the string
        let mut size: i32 = 0;
        let str_ptr = beacon_api::BeaconApi::beacon_data_extract(&mut parser, &mut size);
        assert!(!str_ptr.is_null(), "Should extract string");
        assert!(size > 0, "String should have size");
        
        // Then int
        let int_val = beacon_api::BeaconApi::beacon_data_int(&mut parser);
        assert_eq!(int_val, 42, "Should parse int correctly");
        
        // Then short
        let short_val = beacon_api::BeaconApi::beacon_data_short(&mut parser);
        assert_eq!(short_val, 123, "Should parse short correctly");
    }
}

// The executor's symbol/Beacon-API machinery is Windows-gated
// (`#[cfg(windows)]`); these tests exercise it directly and therefore only
// build on Windows. Argument-packing tests below are platform-independent.
#[cfg(windows)]
mod windows_executor_tests {
use super::*;

#[test]
fn test_symbol_resolution_windows_api() {
    use redbofanalyzer::core::executor::symbols::SymbolResolver;
    
    let mut resolver = SymbolResolver::new();
    
    // Test resolving a common Windows API
    let import = Import {
        library: "KERNEL32".to_string(),
        function: "GetCurrentProcessId".to_string(),
        symbol_name: "__imp_KERNEL32$GetCurrentProcessId".to_string(),
    };
    
    let result = resolver.resolve(&import);
    assert!(result.is_ok(), "Should resolve Windows API: {:?}", result);
    
    let addr = result.unwrap();
    assert_ne!(addr, 0, "Resolved address should not be zero");
}

#[test]
fn test_symbol_resolution_beacon_api() {
    use redbofanalyzer::core::executor::symbols::SymbolResolver;
    use redbofanalyzer::core::executor::beacon_api::BeaconApi;
    
    let mut resolver = SymbolResolver::new();
    
    // Register a Beacon API
    resolver.set_beacon_api("BeaconPrintf", BeaconApi::beacon_printf as usize);
    
    // Test resolving Beacon API
    // Beacon APIs should have library="Beacon" to be resolved correctly
    let import = Import {
        library: "Beacon".to_string(),
        function: "BeaconPrintf".to_string(),
        symbol_name: "BeaconPrintf".to_string(),
    };
    
    let result = resolver.resolve(&import);
    assert!(result.is_ok(), "Should resolve Beacon API: {:?}", result);
    
    let addr = result.unwrap();
    assert_ne!(addr, 0, "Resolved address should not be zero");
    assert_eq!(addr, BeaconApi::beacon_printf as usize, "Should match registered address");
}

#[test]
fn test_beacon_printf_basic() {
    use redbofanalyzer::core::executor::beacon_api;
    
    // Clear output
    beacon_api::clear_global_output();
    
    // Call BeaconPrintf (takes up to 6 variadic args)
    unsafe {
        let fmt = b"Test message: %d\n\0".as_ptr() as *const i8;
        beacon_api::BeaconApi::beacon_printf(0x00, fmt, 42, 0, 0, 0, 0, 0);
    }
    
    // Check output
    let output = beacon_api::global_output().get_entries();
    assert!(!output.is_empty(), "Should have output");
    
    let content = String::from_utf8_lossy(&output[0].data);
    assert!(content.contains("42"), "Output should contain formatted value");
}

#[test]
fn test_beacon_data_parse() {
    use redbofanalyzer::core::executor::beacon_api;
    
    let data = b"\x04\x00\x00\x00test";
    let mut parser = beacon_api::DataParser {
        original: std::ptr::null(),
        buffer: std::ptr::null(),
        length: 0,
        size: 0,
    };
    
    unsafe {
        beacon_api::BeaconApi::beacon_data_parse(&mut parser, data.as_ptr(), data.len() as i32);
        
        // After parsing, the parser is initialized with the full buffer
        // The data is: [4-byte length: 4] [4-byte data: "test"] = 8 bytes total
        // beacon_data_length returns the remaining length, which is the full buffer size initially
        let len = beacon_api::BeaconApi::beacon_data_length(&mut parser);
        assert_eq!(len, 8, "Should have correct total length (8 bytes: 4-byte length + 4-byte data)");
    }
}

#[test]
fn test_beacon_data_int() {
    use redbofanalyzer::core::executor::beacon_api;
    
    let data = b"\x2a\x00\x00\x00";
    let mut parser = beacon_api::DataParser {
        original: std::ptr::null(),
        buffer: std::ptr::null(),
        length: 0,
        size: 0,
    };
    
    unsafe {
        beacon_api::BeaconApi::beacon_data_parse(&mut parser, data.as_ptr(), data.len() as i32);
        
        let value = beacon_api::BeaconApi::beacon_data_int(&mut parser);
        assert_eq!(value, 42, "Should parse integer correctly");
    }
}

#[test]
fn test_beacon_data_extract() {
    use redbofanalyzer::core::executor::beacon_api;
    
    let data = b"\x04\x00\x00\x00test";
    let mut parser = beacon_api::DataParser {
        original: std::ptr::null(),
        buffer: std::ptr::null(),
        length: 0,
        size: 0,
    };
    
    unsafe {
        beacon_api::BeaconApi::beacon_data_parse(&mut parser, data.as_ptr(), data.len() as i32);
        
        let mut size: i32 = 0;
        let ptr = beacon_api::BeaconApi::beacon_data_extract(&mut parser, &mut size);
        
        assert!(!ptr.is_null(), "Should return non-null pointer");
        assert_eq!(size, 4, "Should set size correctly");
        
        // Verify data
        let extracted = std::slice::from_raw_parts(ptr, size as usize);
        assert_eq!(extracted, b"test", "Should extract correct data");
    }
}


} // windows_executor_tests
