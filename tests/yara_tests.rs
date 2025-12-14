//! YARA integration tests

#[cfg(feature = "yara")]
mod yara_tests {
    use redbofanalyzer::core::analyzer::yara;
    use redbofanalyzer::core::models::bof::{BofFile, Section, CoffHeader, MachineType};
    use std::path::PathBuf;

    #[test]
    fn test_yara_engine_available() {
        // Test that YARA engine can be initialized
        let result = yara::analyze_with_yara(
            &create_test_bof(),
            &[],
        );
        
        assert!(result.is_ok(), "YARA analysis should succeed");
        let analysis = result.unwrap();
        
        // Engine should be available if YARA feature is enabled
        assert!(analysis.engine_available, "YARA engine should be available");
    }

    #[test]
    fn test_yara_default_rules() {
        // Test that default rules can be created
        let rules = yara::create_default_bof_rules();
        assert!(!rules.is_empty(), "Default rules should not be empty");
        assert!(rules.contains("BOF_BeaconAPI"), "Should contain BOF_BeaconAPI rule");
    }

    #[test]
    fn test_yara_scan_beacon_api() {
        // Create a test BOF with Beacon API strings
        let mut bof = create_test_bof();
        
        // Add a section with Beacon API strings
        let beacon_section = Section {
            name: ".text".to_string(),
            data: b"BeaconPrintf\0BeaconDataParse\0BeaconOutput\0".to_vec(),
            virtual_size: 0,
            raw_size: 0,
            characteristics: 0x60000020, // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
            entropy: 0.0,
        };
        bof.sections.push(beacon_section);
        
        let result = yara::analyze_with_yara(&bof, &[]);
        assert!(result.is_ok(), "YARA analysis should succeed");
        
        let analysis = result.unwrap();
        if analysis.engine_available {
            // If engine is available, we should potentially find matches
            // (depending on whether the rules match)
            println!("YARA engine available, found {} matches", analysis.stats.total_matches);
            println!("Rules loaded: {}", analysis.stats.rules_loaded);
        }
    }

    #[test]
    fn test_yara_save_default_rules() {
        use std::fs;
        use tempfile::TempDir;
        
        let temp_dir = TempDir::new().unwrap();
        let rules_path = temp_dir.path().join("test_rules.yar");
        
        let result = yara::save_default_rules_to_file(&rules_path);
        assert!(result.is_ok(), "Should save default rules to file");
        
        // Verify file was created and has content
        assert!(rules_path.exists(), "Rules file should exist");
        let content = fs::read_to_string(&rules_path).unwrap();
        assert!(!content.is_empty(), "Rules file should not be empty");
        assert!(content.contains("BOF_BeaconAPI"), "Should contain BOF_BeaconAPI rule");
    }

    fn create_test_bof() -> BofFile {
        // Create a minimal test BOF
        BofFile {
            path: PathBuf::from("test.o"),
            header: CoffHeader {
                machine: MachineType::X64,
                number_of_sections: 0,
                timestamp: 0,
                number_of_symbols: 0,
                characteristics: 0,
            },
            sections: vec![],
            symbols: vec![],
            relocations: vec![],
            imports: vec![],
            entry_point: None,
        }
    }
}

#[cfg(not(feature = "yara"))]
mod yara_tests {
    #[test]
    fn test_yara_feature_disabled() {
        // When YARA feature is disabled, analysis should still work but return empty results
        use redbofanalyzer::core::analyzer::yara;
        use redbofanalyzer::core::models::bof::{BofFile, Section};
        use std::path::PathBuf;

        let bof = BofFile {
            path: PathBuf::from("test.o"),
            machine: 0x8664,
            sections: vec![],
            symbols: vec![],
            imports: vec![],
            entry_point: None,
        };

        let result = yara::analyze_with_yara(&bof, &[]);
        assert!(result.is_ok(), "YARA analysis should succeed even without feature");
        
        let analysis = result.unwrap();
        assert!(!analysis.engine_available, "Engine should not be available when feature is disabled");
    }
}
