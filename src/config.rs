use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Configuration for scan limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// NTFS MFT scan limit for system drives (C:)
    pub ntfs_mft_system_drive_limit: u64,

    /// NTFS MFT scan limit for spare drives
    pub ntfs_mft_spare_drive_limit: u64,

    /// USN Journal records to scan
    pub ntfs_usn_journal_limit: u64,

    /// File carving cluster limit
    pub file_carving_cluster_limit: u64,

    /// Maximum carved files
    pub file_carving_max_files: u64,

    /// exFAT directory entries to scan
    pub exfat_directory_entries_limit: u64,

    /// Number of parallel threads for file carving (0 = auto-detect)
    pub parallel_scan_threads: usize,

    /// Size search tolerance/range (format: "5MB", "10MB", etc.)
    pub size_search_tolerance: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        // Auto-detect CPU cores, use 75% of available cores for parallel scanning
        // This leaves some cores for OS and GUI responsiveness
        let cpu_count = num_cpus::get();
        let default_threads = ((cpu_count as f32 * 0.75).ceil() as usize).max(2).min(16);

        Self {
            ntfs_mft_system_drive_limit: 300_000,
            ntfs_mft_spare_drive_limit: 10_000_000,
            ntfs_usn_journal_limit: 1_000_000,
            file_carving_cluster_limit: 500_000_000,
            file_carving_max_files: 100_000,
            exfat_directory_entries_limit: 1_000_000,
            parallel_scan_threads: default_threads,
            size_search_tolerance: "10MB".to_string(),
        }
    }
}

impl ScanConfig {
    /// Get the path to the configuration file (same directory as executable)
    fn get_config_path() -> Option<PathBuf> {
        std::env::current_exe().ok().and_then(|exe_path| {
            exe_path.parent().map(|dir| {
                let mut config_name = exe_path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                config_name.push_str(".json");
                dir.join(config_name)
            })
        })
    }

    /// Load configuration from JSON file, or create default if not found
    pub fn load() -> Self {
        let config_path = match Self::get_config_path() {
            Some(path) => path,
            None => {
                eprintln!("Warning: Could not determine config path, using defaults");
                return Self::default();
            }
        };

        // Try to read existing config
        match fs::read_to_string(&config_path) {
            Ok(contents) => {
                // Try to parse JSON
                match serde_json::from_str::<ScanConfig>(&contents) {
                    Ok(config) => {
                        println!("Loaded configuration from: {}", config_path.display());
                        config
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to parse config file '{}': {}",
                            config_path.display(),
                            e
                        );
                        eprintln!("Using default configuration values");
                        Self::default()
                    }
                }
            }
            Err(_) => {
                // Config file doesn't exist, create it with defaults
                let default_config = Self::default();
                if let Err(e) = default_config.save_to(&config_path) {
                    eprintln!("Warning: Failed to create config file: {}", e);
                } else {
                    println!("Created default configuration file: {}", config_path.display());
                }
                default_config
            }
        }
    }

    /// Save configuration to the specified path
    fn save_to(&self, path: &PathBuf) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;

        fs::write(path, json)
            .map_err(|e| format!("Failed to write config file: {}", e))?;

        Ok(())
    }

    /// Save current configuration back to file
    pub fn save(&self) -> Result<(), String> {
        let config_path = Self::get_config_path()
            .ok_or_else(|| "Could not determine config path".to_string())?;
        self.save_to(&config_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ScanConfig::default();
        assert_eq!(config.ntfs_mft_system_drive_limit, 300_000);
        assert_eq!(config.ntfs_mft_spare_drive_limit, 10_000_000);
        assert_eq!(config.file_carving_cluster_limit, 500_000_000);
    }

    #[test]
    fn test_serialize_deserialize() {
        let config = ScanConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ScanConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.ntfs_mft_system_drive_limit, deserialized.ntfs_mft_system_drive_limit);
        assert_eq!(config.file_carving_cluster_limit, deserialized.file_carving_cluster_limit);
    }
}
