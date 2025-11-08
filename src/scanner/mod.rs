pub mod ntfs;
pub mod exfat;
pub mod disk_access;
pub mod file_carving;
pub mod usn_journal;

use chrono::{DateTime, Utc};
use std::path::PathBuf;

/// Represents a contiguous range of clusters
#[derive(Debug, Clone)]
pub struct ClusterRange {
    pub start: u64,  // Starting cluster number
    pub count: u64,  // Number of clusters in this range
}

#[derive(Debug, Clone)]
pub struct DeletedFile {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub size_formatted: String, // Cached formatted size string for UI performance
    pub deleted_time: Option<DateTime<Utc>>,
    pub file_record: u64, // MFT record number for NTFS, directory entry cluster for exFAT
    pub clusters: Vec<u64>, // Data clusters (for exFAT - uses individual clusters)
    pub cluster_ranges: Vec<ClusterRange>, // Data cluster ranges (for NTFS - memory efficient)
    pub is_recoverable: bool,
    pub filesystem_type: String, // "NTFS" or "exFAT"
}

impl DeletedFile {
    /// Format size in bytes to human-readable string
    pub fn format_size(size: u64) -> String {
        if size > 1_000_000_000 {
            format!("{:.2} GB", size as f64 / 1_000_000_000.0)
        } else if size > 1_000_000 {
            format!("{:.2} MB", size as f64 / 1_000_000.0)
        } else if size > 1_000 {
            format!("{:.2} KB", size as f64 / 1_000.0)
        } else {
            format!("{} bytes", size)
        }
    }
}

pub trait FileSystemScanner {
    fn scan(
        &mut self,
        drive_letter: char,
        folder_path: Option<&str>,
        filename_filter: Option<&str>,
    ) -> anyhow::Result<Vec<DeletedFile>>;

    fn scan_realtime(
        &mut self,
        drive_letter: char,
        folder_path: Option<&str>,
        filename_filter: Option<&str>,
        files_output: &std::sync::Arc<std::sync::Mutex<Vec<DeletedFile>>>,
        should_stop: &std::sync::Arc<std::sync::Mutex<bool>>,
        scan_status: &std::sync::Arc<std::sync::Mutex<String>>,
    ) -> anyhow::Result<bool>;

    fn get_filesystem_type(&self) -> &str;
}
