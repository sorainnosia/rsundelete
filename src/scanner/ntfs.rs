use super::{DeletedFile, FileSystemScanner};
use super::disk_access::DiskHandle;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;

const FILE_RECORD_SEGMENT_IN_USE: u16 = 0x0001;

pub struct NtfsScanner {
    drive_letter: char,
    path_cache: HashMap<u64, String>, // Cache for reconstructing paths
    // Configuration limits
    mft_system_drive_limit: u64,
    mft_spare_drive_limit: u64,
    usn_journal_limit: u64,
    file_carving_cluster_limit: u64,
    file_carving_max_files: u64,
    parallel_threads: usize,
}

impl NtfsScanner {
    pub fn new(drive_letter: char) -> Self {
        Self {
            drive_letter,
            path_cache: HashMap::new(),
            // Default values
            mft_system_drive_limit: 300_000,
            mft_spare_drive_limit: 10_000_000,
            usn_journal_limit: 1_000_000,
            file_carving_cluster_limit: 500_000_000,
            file_carving_max_files: 100_000,
            parallel_threads: 4,
        }
    }

    /// Set configuration limits for scanning
    pub fn set_config(
        &mut self,
        mft_system_drive_limit: u64,
        mft_spare_drive_limit: u64,
        usn_journal_limit: u64,
        file_carving_cluster_limit: u64,
        file_carving_max_files: u64,
        parallel_threads: usize,
    ) {
        self.mft_system_drive_limit = mft_system_drive_limit;
        self.mft_spare_drive_limit = mft_spare_drive_limit;
        self.usn_journal_limit = usn_journal_limit;
        self.file_carving_cluster_limit = file_carving_cluster_limit;
        self.file_carving_max_files = file_carving_max_files;
        self.parallel_threads = parallel_threads.max(1).min(32); // Clamp between 1-32
    }

    /// Detect if this is a system drive (C:) which requires USN Journal for better recovery
    fn is_system_drive(&self) -> bool {
        // System drive is typically C:
        self.drive_letter.to_ascii_uppercase() == 'C'
    }

    fn read_boot_sector(&self, disk: &DiskHandle) -> Result<NtfsBootSector> {
        let sector_size = disk.get_sector_size()?;
        let boot_data = disk.read_sectors(0, 1, sector_size)?;

        if boot_data.len() < 512 {
            anyhow::bail!("Boot sector too small");
        }

        // Verify NTFS signature
        if &boot_data[3..11] != b"NTFS    " {
            anyhow::bail!("Not an NTFS filesystem");
        }

        let bytes_per_sector = u16::from_le_bytes([boot_data[11], boot_data[12]]);
        let sectors_per_cluster = boot_data[13];
        let mft_cluster = u64::from_le_bytes([
            boot_data[48], boot_data[49], boot_data[50], boot_data[51],
            boot_data[52], boot_data[53], boot_data[54], boot_data[55],
        ]);
        let clusters_per_mft_record = boot_data[64] as i8;

        // Calculate total sectors
        let total_sectors = u64::from_le_bytes([
            boot_data[40], boot_data[41], boot_data[42], boot_data[43],
            boot_data[44], boot_data[45], boot_data[46], boot_data[47],
        ]);

        Ok(NtfsBootSector {
            bytes_per_sector,
            sectors_per_cluster,
            mft_cluster,
            clusters_per_mft_record,
            total_sectors,
        })
    }

    fn read_mft_record(&self, disk: &DiskHandle, boot_sector: &NtfsBootSector, record_num: u64) -> Result<Vec<u8>> {
        let bytes_per_cluster = boot_sector.bytes_per_sector as u64 * boot_sector.sectors_per_cluster as u64;
        let sector_size = boot_sector.bytes_per_sector as u64;

        let mft_record_size = if boot_sector.clusters_per_mft_record >= 0 {
            boot_sector.clusters_per_mft_record as u64 * bytes_per_cluster
        } else {
            1u64 << (-boot_sector.clusters_per_mft_record as u64)
        };

        let mft_offset = boot_sector.mft_cluster * bytes_per_cluster;
        let record_offset = mft_offset + (record_num * mft_record_size);

        let start_sector = record_offset / sector_size;
        let num_sectors = (mft_record_size + sector_size - 1) / sector_size;

        let data = disk.read_sectors(start_sector, num_sectors, sector_size)?;

        let offset_in_sector = (record_offset % sector_size) as usize;
        let end = (offset_in_sector + mft_record_size as usize).min(data.len());

        Ok(data[offset_in_sector..end].to_vec())
    }

    fn parse_mft_record(&self, record_data: &[u8]) -> Result<Option<MftRecord>> {
        if record_data.len() < 48 {
            return Ok(None);
        }

        // Check FILE signature
        if &record_data[0..4] != b"FILE" {
            return Ok(None);
        }

        let flags = u16::from_le_bytes([record_data[22], record_data[23]]);
        let is_in_use = (flags & FILE_RECORD_SEGMENT_IN_USE) != 0;
        let first_attr_offset = u16::from_le_bytes([record_data[20], record_data[21]]) as usize;

        Ok(Some(MftRecord {
            flags,
            is_in_use,
            first_attr_offset,
            data: record_data.to_vec(),
        }))
    }

    fn extract_file_info(&self, record: &MftRecord, record_num: u64) -> Result<Option<DeletedFileInfo>> {
        // We want deleted files
        if record.is_in_use {
            return Ok(None);
        }

        let mut offset = record.first_attr_offset;
        let mut filename = String::new();
        let mut parent_ref: Option<u64> = None;
        let mut size = 0u64;
        let mut cluster_ranges = Vec::new();

        while offset + 16 < record.data.len() {
            let attr_type = u32::from_le_bytes([
                record.data[offset],
                record.data[offset + 1],
                record.data[offset + 2],
                record.data[offset + 3],
            ]);

            if attr_type == 0xFFFFFFFF {
                break;
            }

            let attr_length = u32::from_le_bytes([
                record.data[offset + 4],
                record.data[offset + 5],
                record.data[offset + 6],
                record.data[offset + 7],
            ]) as usize;

            if attr_length == 0 || offset + attr_length > record.data.len() {
                break;
            }

            match attr_type {
                0x30 => {
                    // FILE_NAME attribute
                    if let Some((name, parent)) = self.parse_filename_attribute(&record.data[offset..offset + attr_length]) {
                        // Prefer long filenames over short (8.3) names
                        if !name.starts_with('.') && (filename.is_empty() || name.len() > filename.len()) {
                            filename = name;
                            parent_ref = Some(parent);
                        }
                    }
                }
                0x80 => {
                    // DATA attribute
                    if let Some(file_size) = self.parse_data_attribute(&record.data[offset..offset + attr_length]) {
                        size = file_size;
                    }
                    // Parse data runs to get cluster ranges (memory efficient)
                    cluster_ranges = self.parse_data_runs(&record.data[offset..offset + attr_length]);
                }
                _ => {}
            }

            offset += attr_length;
        }

        if filename.is_empty() {
            return Ok(None);
        }

        Ok(Some(DeletedFileInfo {
            filename,
            parent_ref,
            size,
            record_num,
            cluster_ranges,
        }))
    }

    fn parse_filename_attribute(&self, attr_data: &[u8]) -> Option<(String, u64)> {
        if attr_data.len() < 24 {
            return None;
        }

        let non_resident = attr_data[8];
        if non_resident != 0 {
            return None;
        }

        let content_offset = u16::from_le_bytes([attr_data[20], attr_data[21]]) as usize;

        if content_offset + 66 > attr_data.len() {
            return None;
        }

        // Extract parent directory reference (MFT record number)
        let parent_ref = u64::from_le_bytes([
            attr_data[content_offset],
            attr_data[content_offset + 1],
            attr_data[content_offset + 2],
            attr_data[content_offset + 3],
            attr_data[content_offset + 4],
            attr_data[content_offset + 5],
            0,
            0,
        ]) & 0x0000FFFFFFFFFFFF; // Mask to get just the record number

        let name_length = attr_data[content_offset + 64] as usize;
        let name_offset = content_offset + 66;

        if name_offset + name_length * 2 > attr_data.len() {
            return None;
        }

        let name_data = &attr_data[name_offset..name_offset + name_length * 2];
        let name_u16: Vec<u16> = name_data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        let name = String::from_utf16_lossy(&name_u16);

        Some((name, parent_ref))
    }

    fn parse_data_attribute(&self, attr_data: &[u8]) -> Option<u64> {
        if attr_data.len() < 24 {
            return None;
        }

        let non_resident = attr_data[8];

        if non_resident == 0 {
            // Resident data
            let content_size = u32::from_le_bytes([
                attr_data[16],
                attr_data[17],
                attr_data[18],
                attr_data[19],
            ]) as u64;
            return Some(content_size);
        } else {
            // Non-resident data
            if attr_data.len() < 48 {
                return None;
            }

            let file_size = u64::from_le_bytes([
                attr_data[48],
                attr_data[49],
                attr_data[50],
                attr_data[51],
                attr_data[52],
                attr_data[53],
                attr_data[54],
                attr_data[55],
            ]);

            return Some(file_size);
        }
    }

    /// Parse NTFS data runs to extract cluster ranges (memory efficient)
    /// Returns a vector of cluster ranges for non-resident data
    fn parse_data_runs(&self, attr_data: &[u8]) -> Vec<crate::scanner::ClusterRange> {
        if attr_data.len() < 24 {
            return Vec::new();
        }

        let non_resident = attr_data[8];
        if non_resident == 0 {
            // Resident data - no clusters needed
            return Vec::new();
        }

        if attr_data.len() < 64 {
            return Vec::new();
        }

        // Get the offset to the data runs
        let runlist_offset = u16::from_le_bytes([attr_data[32], attr_data[33]]) as usize;

        if runlist_offset >= attr_data.len() {
            return Vec::new();
        }

        let mut cluster_ranges = Vec::new();
        let mut offset = runlist_offset;
        let mut current_lcn: i64 = 0; // Logical Cluster Number (cumulative)

        // Parse data runs
        while offset < attr_data.len() {
            let header = attr_data[offset];
            if header == 0 {
                // End of data runs
                break;
            }

            let length_size = (header & 0x0F) as usize;
            let lcn_size = ((header >> 4) & 0x0F) as usize;

            if length_size == 0 || length_size > 8 || lcn_size > 8 {
                break;
            }

            offset += 1;

            if offset + length_size + lcn_size > attr_data.len() {
                break;
            }

            // Read run length (number of clusters in this run)
            let mut run_length: u64 = 0;
            for i in 0..length_size {
                run_length |= (attr_data[offset + i] as u64) << (i * 8);
            }
            offset += length_size;

            // Read LCN offset (signed, relative to previous LCN)
            let mut lcn_offset: i64 = 0;
            for i in 0..lcn_size {
                lcn_offset |= (attr_data[offset + i] as i64) << (i * 8);
            }
            // Sign-extend if necessary
            if lcn_size > 0 && (attr_data[offset + lcn_size - 1] & 0x80) != 0 {
                for i in lcn_size..8 {
                    lcn_offset |= 0xFF_i64 << (i * 8);
                }
            }
            offset += lcn_size;

            // Update current LCN
            current_lcn += lcn_offset;

            // Add this cluster range (much more memory efficient than individual clusters!)
            cluster_ranges.push(crate::scanner::ClusterRange {
                start: current_lcn as u64,
                count: run_length,
            });

            // Limit to prevent excessive memory usage (10,000 ranges = up to billions of clusters)
            if cluster_ranges.len() > 10_000 {
                break;
            }
        }

        cluster_ranges
    }

    fn build_path(&self, disk: &DiskHandle, boot_sector: &NtfsBootSector, parent_ref: Option<u64>, filename: &str) -> String {
        let mut path_components = vec![filename.to_string()];
        let mut current_ref = parent_ref;

        // Traverse up to root (record 5 is usually root)
        while let Some(ref_num) = current_ref {
            if ref_num == 5 || ref_num == 0 {
                break; // Root directory
            }

            // Check cache first
            if let Some(cached_path) = self.path_cache.get(&ref_num) {
                path_components.push(cached_path.clone());
                break;
            }

            // Try to read parent record
            match self.read_mft_record(disk, boot_sector, ref_num) {
                Ok(parent_data) => {
                    if let Ok(Some(parent_record)) = self.parse_mft_record(&parent_data) {
                        if let Ok(Some(parent_info)) = self.extract_file_info_for_path(&parent_record) {
                            path_components.push(parent_info.0.clone());
                            current_ref = parent_info.1;
                            continue;
                        }
                    }
                }
                Err(_) => {}
            }

            break;
        }

        // Reverse to get correct order and build path
        path_components.reverse();
        format!("{}:\\{}", self.drive_letter, path_components.join("\\"))
    }

    fn extract_file_info_for_path(&self, record: &MftRecord) -> Result<Option<(String, Option<u64>)>> {
        let mut offset = record.first_attr_offset;
        let mut filename = String::new();
        let mut parent_ref: Option<u64> = None;

        while offset + 16 < record.data.len() {
            let attr_type = u32::from_le_bytes([
                record.data[offset],
                record.data[offset + 1],
                record.data[offset + 2],
                record.data[offset + 3],
            ]);

            if attr_type == 0xFFFFFFFF {
                break;
            }

            let attr_length = u32::from_le_bytes([
                record.data[offset + 4],
                record.data[offset + 5],
                record.data[offset + 6],
                record.data[offset + 7],
            ]) as usize;

            if attr_length == 0 || offset + attr_length > record.data.len() {
                break;
            }

            if attr_type == 0x30 {
                if let Some((name, parent)) = self.parse_filename_attribute(&record.data[offset..offset + attr_length]) {
                    if !name.starts_with('.') && (filename.is_empty() || name.len() > filename.len()) {
                        filename = name;
                        parent_ref = Some(parent);
                    }
                }
            }

            offset += attr_length;
        }

        if filename.is_empty() {
            return Ok(None);
        }

        Ok(Some((filename, parent_ref)))
    }
}

impl FileSystemScanner for NtfsScanner {
    fn scan(
        &mut self,
        drive_letter: char,
        folder_path: Option<&str>,
        filename_filter: Option<&str>,
    ) -> Result<Vec<DeletedFile>> {
        // Create log file FIRST, in the executable directory
        let log_path = std::env::current_exe()
            .ok()
            .and_then(|exe_path| exe_path.parent().map(|p| p.join("rsundelete_debug.log")))
            .and_then(|path| path.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "rsundelete_debug.log".to_string());

        let mut log_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)
            .ok();

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "=== RunDelete Scan Debug Log ===");
            let _ = writeln!(log, "Log file location: {}", log_path);
            let _ = writeln!(log, "Drive: {}", drive_letter);
            let _ = writeln!(log, "Folder filter: {:?}", folder_path);
            let _ = writeln!(log, "Filename filter: {:?}", filename_filter);
            let _ = writeln!(log, "");
            let _ = writeln!(log, "Attempting to open disk...");
            let _ = log.flush();
        }

        self.drive_letter = drive_letter;
        self.path_cache.clear();

        let disk = match DiskHandle::open(drive_letter) {
            Ok(d) => {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "SUCCESS: Disk opened");
                    let _ = log.flush();
                }
                d
            }
            Err(e) => {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "FAILED to open disk: {}", e);
                    let _ = writeln!(log, "");
                    let _ = writeln!(log, "Common reasons:");
                    let _ = writeln!(log, "1. Not running as Administrator");
                    let _ = writeln!(log, "2. Invalid drive letter");
                    let _ = writeln!(log, "3. Drive is not accessible");
                    let _ = log.flush();
                }
                return Err(e).context("Failed to open disk for NTFS scanning");
            }
        };

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "Reading boot sector...");
            let _ = log.flush();
        }

        let boot_sector = match self.read_boot_sector(&disk) {
            Ok(bs) => {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "SUCCESS: Boot sector read");
                    let _ = writeln!(log, "Bytes per sector: {}", bs.bytes_per_sector);
                    let _ = writeln!(log, "Sectors per cluster: {}", bs.sectors_per_cluster);
                    let _ = log.flush();
                }
                bs
            }
            Err(e) => {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "FAILED to read boot sector: {}", e);
                    let _ = log.flush();
                }
                return Err(e).context("Failed to read NTFS boot sector");
            }
        };

        let mut deleted_files = Vec::new();

        // Calculate approximate number of MFT records
        let bytes_per_cluster = boot_sector.bytes_per_sector as u64 * boot_sector.sectors_per_cluster as u64;
        let mft_record_size = if boot_sector.clusters_per_mft_record >= 0 {
            boot_sector.clusters_per_mft_record as u64 * bytes_per_cluster
        } else {
            1u64 << (-boot_sector.clusters_per_mft_record as u64)
        };

        // Scan more records - up to 10,000,000 (10 million) or until we hit errors
        // This allows scanning larger NTFS drives with millions of files
        let max_records = 10_000_000u64.min(boot_sector.total_sectors * boot_sector.bytes_per_sector as u64 / mft_record_size);

        let mut consecutive_errors = 0;
        let mut total_deleted_found = 0;

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "Max records to scan: {}", max_records);
            let _ = writeln!(log, "MFT record size: {} bytes", mft_record_size);
            let _ = writeln!(log, "");
            let _ = writeln!(log, "Starting scan...");
            let _ = log.flush();
        }

        for record_num in 0..max_records {
            // Progress update every 50,000 records
            if record_num > 0 && record_num % 50_000 == 0 {
                if let Some(ref mut log) = log_file {
                    let progress = (record_num as f64 / max_records as f64) * 100.0;
                    let _ = writeln!(log, "Progress: {:.1}% ({}/{} records scanned, {} deleted files found so far)",
                                    progress, record_num, max_records, total_deleted_found);
                    let _ = log.flush();
                }
            }

            match self.read_mft_record(&disk, &boot_sector, record_num) {
                Ok(record_data) => {
                    consecutive_errors = 0;

                    if let Ok(Some(record)) = self.parse_mft_record(&record_data) {
                        if let Ok(Some(file_info)) = self.extract_file_info(&record, record_num) {
                            total_deleted_found += 1;

                            // Build full path
                            let full_path = self.build_path(&disk, &boot_sector, file_info.parent_ref, &file_info.filename);

                            // Calculate total clusters from ranges
                            let total_clusters: u64 = file_info.cluster_ranges.iter().map(|r| r.count).sum();

                            // Log first 10 deleted files found
                            if total_deleted_found <= 10 {
                                if let Some(ref mut log) = log_file {
                                    let _ = writeln!(log, "Deleted file #{}: '{}' at '{}', size: {} bytes, {} ranges, {} total clusters",
                                                    total_deleted_found, file_info.filename, full_path, file_info.size,
                                                    file_info.cluster_ranges.len(), total_clusters);
                                    let _ = log.flush();
                                }
                            }

                            // Apply filters
                            let mut include = true;
                            let mut filter_reason = String::new();

                            if let Some(filter) = filename_filter {
                                if !filter.is_empty() && !file_info.filename.to_lowercase().contains(&filter.to_lowercase()) {
                                    include = false;
                                    filter_reason = format!("filename filter '{}' doesn't match '{}'", filter, file_info.filename);
                                }
                            }

                            if let Some(path_filter) = folder_path {
                                if !path_filter.is_empty() && !full_path.to_lowercase().contains(&path_filter.to_lowercase()) {
                                    include = false;
                                    if filter_reason.is_empty() {
                                        filter_reason = format!("path filter '{}' doesn't match '{}'", path_filter, full_path);
                                    } else {
                                        filter_reason.push_str(&format!(" AND path filter '{}' doesn't match '{}'", path_filter, full_path));
                                    }
                                }
                            }

                            // Log filtered files for debugging
                            if !include {
                                if let Some(ref mut log) = log_file {
                                    let _ = writeln!(log, "FILTERED OUT - Name: '{}', Path: '{}', Size: {} bytes, Reason: {}",
                                        file_info.filename, full_path, file_info.size, filter_reason);
                                    let _ = log.flush();
                                }
                            }

                            if include {
                                deleted_files.push(DeletedFile {
                                    name: file_info.filename.clone(),
                                    path: full_path.clone(),
                                    size: file_info.size,
                                    size_formatted: crate::scanner::DeletedFile::format_size(file_info.size),
                                    deleted_time: None,
                                    file_record: file_info.record_num,
                                    clusters: Vec::new(), // Empty for NTFS (uses cluster_ranges instead)
                                    cluster_ranges: file_info.cluster_ranges.clone(),
                                    is_recoverable: file_info.size > 0 && !file_info.cluster_ranges.is_empty(),
                                    filesystem_type: "NTFS".to_string(),
                                });
                            } else {
                                // Debug: show why file was filtered out
                                if deleted_files.len() < 10 {  // Only log first few to avoid spam
                                    if let Some(ref mut log) = log_file {
                                        let _ = writeln!(log, "FILTERED OUT - Name: '{}', Path: '{}', Size: {}",
                                                 file_info.filename, full_path, file_info.size);
                                        if let Some(ff) = filename_filter {
                                            let _ = writeln!(log, "  Filename filter: '{}', Match: {}",
                                                    ff, file_info.filename.to_lowercase().contains(&ff.to_lowercase()));
                                        }
                                        if let Some(pf) = folder_path {
                                            let _ = writeln!(log, "  Path filter: '{}', Match: {}",
                                                    pf, full_path.to_lowercase().contains(&pf.to_lowercase()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    consecutive_errors += 1;
                    // Stop if we can't read many records in a row
                    if consecutive_errors > 100 && record_num > 1000 {
                        break;
                    }
                }
            }
        }

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "");
            let _ = writeln!(log, "=== Scan Summary ===");
            let _ = writeln!(log, "Scanned up to {} MFT records", max_records);
            let _ = writeln!(log, "Found {} total deleted files (before filtering)", total_deleted_found);
            let _ = writeln!(log, "After filtering: {} files", deleted_files.len());
            let _ = writeln!(log, "");
            let _ = writeln!(log, "==========================================");
            let _ = writeln!(log, "Log file saved to: {}", log_path);
            let _ = writeln!(log, "==========================================");
            let _ = log.flush();
        }

        // Add log path to error message if no files found
        if deleted_files.is_empty() && total_deleted_found == 0 {
            anyhow::bail!("No deleted files found. Check log at: {}", log_path);
        }

        Ok(deleted_files)
    }

    fn scan_realtime(
        &mut self,
        drive_letter: char,
        folder_path: Option<&str>,
        filename_filter: Option<&str>,
        files_output: &std::sync::Arc<std::sync::Mutex<Vec<DeletedFile>>>,
        should_stop: &std::sync::Arc<std::sync::Mutex<bool>>,
        scan_status: &std::sync::Arc<std::sync::Mutex<String>>,
    ) -> Result<bool> {
        // Reuse the same scan logic but with real-time updates
        let log_path = std::env::current_exe()
            .ok()
            .and_then(|exe_path| exe_path.parent().map(|p| p.join("rsundelete_debug.log")))
            .and_then(|path| path.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "rsundelete_debug.log".to_string());

        let mut log_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)
            .ok();

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "=== RunDelete Scan Debug Log (Real-time mode) ===");
            let _ = writeln!(log, "Drive: {}", drive_letter);
            let _ = log.flush();
        }

        self.drive_letter = drive_letter;
        self.path_cache.clear();

        let disk = DiskHandle::open(drive_letter).context("Failed to open disk for NTFS scanning")?;
        let boot_sector = self.read_boot_sector(&disk).context("Failed to read NTFS boot sector")?;

        // Automatic detection: Use USN Journal for system drives
        let use_journal = self.is_system_drive();

        let bytes_per_cluster = boot_sector.bytes_per_sector as u64 * boot_sector.sectors_per_cluster as u64;
        let mft_record_size = if boot_sector.clusters_per_mft_record >= 0 {
            boot_sector.clusters_per_mft_record as u64 * bytes_per_cluster
        } else {
            1u64 << (-boot_sector.clusters_per_mft_record as u64)
        };

        // System drives: Configured MFT scan (fast) + USN Journal (comprehensive)
        // Spare drives: Configured MFT scan (comprehensive, no journal)
        let max_mft_records = if use_journal {
            self.mft_system_drive_limit // System drive: quick MFT scan, rely on USN Journal
        } else {
            self.mft_spare_drive_limit // Spare drive: comprehensive MFT scan
        };

        if let Some(ref mut log) = log_file {
            if use_journal {
                let _ = writeln!(log, "SYSTEM DRIVE DETECTED - Using USN Journal for improved recovery");
                let _ = writeln!(log, "Strategy: Fast MFT scan (300K records) + USN Journal scan (comprehensive)");
            } else {
                let _ = writeln!(log, "Spare drive - MFT-only scanning (up to 10M records)");
            }
            let _ = log.flush();
        }

        let max_records = max_mft_records.min(boot_sector.total_sectors * boot_sector.bytes_per_sector as u64 / mft_record_size);

        // Parallel MFT scanning
        let should_terminate = Arc::new(AtomicBool::new(false));
        let progress_counter = Arc::new(AtomicU64::new(0));
        let error_counter = Arc::new(AtomicU64::new(0));

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.parallel_threads)
            .build()
            .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "MFT scanning using {} parallel threads", self.parallel_threads);
            let _ = log.flush();
        }

        // Process MFT records in parallel chunks
        let chunk_size = 10_000u64;
        let total_chunks = (max_records + chunk_size - 1) / chunk_size;

        pool.install(|| {
            (0..total_chunks).into_par_iter().for_each(|chunk_idx| {
                if should_terminate.load(Ordering::Relaxed) {
                    return;
                }

                if *should_stop.lock().unwrap() {
                    should_terminate.store(true, Ordering::Relaxed);
                    return;
                }

                let chunk_start = chunk_idx * chunk_size;
                let chunk_end = ((chunk_idx + 1) * chunk_size).min(max_records);

                // Each thread opens its own disk handle
                let thread_disk = match DiskHandle::open(self.drive_letter) {
                    Ok(d) => d,
                    Err(_) => return,
                };

                for record_num in chunk_start..chunk_end {
                    if should_terminate.load(Ordering::Relaxed) {
                        break;
                    }

                    let processed = progress_counter.fetch_add(1, Ordering::Relaxed) + 1;

                    // Progress update every 50,000 records
                    if processed % 50_000 == 0 {
                        let progress = (processed as f64 / max_records as f64) * 100.0;
                        *scan_status.lock().unwrap() = format!(
                            "MFT Scan: {:.1}% ({}/{} records, {} files)",
                            progress, processed, max_records, files_output.lock().unwrap().len()
                        );
                    }

                    match self.read_mft_record(&thread_disk, &boot_sector, record_num) {
                        Ok(record_data) => {
                            error_counter.store(0, Ordering::Relaxed);

                            if let Ok(Some(record)) = self.parse_mft_record(&record_data) {
                                if let Ok(Some(file_info)) = self.extract_file_info(&record, record_num) {
                                    let full_path = self.build_path(&thread_disk, &boot_sector, file_info.parent_ref, &file_info.filename);

                                    // Apply filters
                                    let mut include = true;

                                    if let Some(filter) = filename_filter {
                                        if !filter.is_empty() && !file_info.filename.to_lowercase().contains(&filter.to_lowercase()) {
                                            include = false;
                                        }
                                    }

                                    if let Some(path_filter) = folder_path {
                                        if !path_filter.is_empty() && !full_path.to_lowercase().contains(&path_filter.to_lowercase()) {
                                            include = false;
                                        }
                                    }

                                    if include {
                                        files_output.lock().unwrap().push(DeletedFile {
                                            name: file_info.filename.clone(),
                                            path: full_path.clone(),
                                            size: file_info.size,
                                            size_formatted: crate::scanner::DeletedFile::format_size(file_info.size),
                                            deleted_time: None,
                                            file_record: file_info.record_num,
                                            clusters: Vec::new(),
                                            cluster_ranges: file_info.cluster_ranges.clone(),
                                            is_recoverable: file_info.size > 0 && !file_info.cluster_ranges.is_empty(),
                                            filesystem_type: "NTFS".to_string(),
                                        });
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            let errors = error_counter.fetch_add(1, Ordering::Relaxed) + 1;
                            if errors > 100 && record_num > 1000 {
                                should_terminate.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                }
            });
        });

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "MFT scan complete. Found {} files", files_output.lock().unwrap().len());
            let _ = log.flush();
        }

        // If system drive, also scan USN Journal for better recovery
        if use_journal {
            // Update status for USN Journal phase
            *scan_status.lock().unwrap() = "USN Journal: Reading change journal...".to_string();

            if let Some(ref mut log) = log_file {
                let _ = writeln!(log, "");
                let _ = writeln!(log, "=== Starting USN Journal Scan ===");
                let _ = log.flush();
            }

            // Check if user requested stop
            if *should_stop.lock().unwrap() {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "Scan STOPPED before USN Journal phase");
                    let _ = log.flush();
                }
                return Ok(true);
            }

            let journal_parser = crate::scanner::usn_journal::UsnJournalParser::new(drive_letter);

            match journal_parser.find_deleted_files(&disk) {
                Ok(journal_files) => {
                    // Update status
                    *scan_status.lock().unwrap() = format!(
                        "USN Journal: Processing {} records...",
                        journal_files.len()
                    );

                    if let Some(ref mut log) = log_file {
                        let _ = writeln!(log, "USN Journal: Found {} deleted file records", journal_files.len());
                        let _ = log.flush();
                    }

                    // Get MFT record numbers already found from MFT scan (to avoid duplicates)
                    let mft_records: std::collections::HashSet<u64> = files_output
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|f| f.file_record)
                        .collect();

                    // Build MFT cache once for all journal records (performance optimization)
                    let mft_cache = self.build_mft_cache_for_journal(&disk, &boot_sector);
                    let total_journal_records = journal_files.len();

                    // Parallel USN Journal processing
                    let journal_added = Arc::new(AtomicU64::new(0));
                    let journal_progress = Arc::new(AtomicU64::new(0));
                    let should_terminate_journal = Arc::new(AtomicBool::new(false));

                    if let Some(ref mut log) = log_file {
                        let _ = writeln!(log, "USN Journal processing using {} parallel threads", self.parallel_threads);
                        let _ = log.flush();
                    }

                    pool.install(|| {
                        journal_files.into_par_iter().for_each(|usn_record| {
                            if should_terminate_journal.load(Ordering::Relaxed) {
                                return;
                            }

                            if *should_stop.lock().unwrap() {
                                should_terminate_journal.store(true, Ordering::Relaxed);
                                return;
                            }

                            let idx = journal_progress.fetch_add(1, Ordering::Relaxed);

                            // Update progress every 100 records
                            if idx % 100 == 0 {
                                *scan_status.lock().unwrap() = format!(
                                    "USN Journal: {}/{} records ({} files added)",
                                    idx, total_journal_records, journal_added.load(Ordering::Relaxed)
                                );
                            }

                            let mft_num = usn_record.mft_record_number();

                            // Skip if we already have this file from MFT scan
                            if mft_records.contains(&mft_num) {
                                return;
                            }

                            // Build path from USN record
                            let full_path = journal_parser.build_path_from_record(&usn_record, &mft_cache);

                            // Apply filters
                            let mut include = true;

                            if let Some(filter) = filename_filter {
                                if !filter.is_empty() && !usn_record.filename.to_lowercase().contains(&filter.to_lowercase()) {
                                    include = false;
                                }
                            }

                            if let Some(path_filter) = folder_path {
                                if !path_filter.is_empty() && !full_path.to_lowercase().contains(&path_filter.to_lowercase()) {
                                    include = false;
                                }
                            }

                            if include {
                                journal_added.fetch_add(1, Ordering::Relaxed);

                                files_output.lock().unwrap().push(DeletedFile {
                                    name: usn_record.filename.clone(),
                                    path: full_path.clone(),
                                    size: 0,
                                    size_formatted: crate::scanner::DeletedFile::format_size(0),
                                    deleted_time: Some(usn_record.timestamp),
                                    file_record: mft_num,
                                    clusters: Vec::new(),
                                    cluster_ranges: Vec::new(),
                                    is_recoverable: false,
                                    filesystem_type: "NTFS (from USN Journal)".to_string(),
                                });
                            }
                        });
                    });

                    let final_journal_added = journal_added.load(Ordering::Relaxed);

                    if let Some(ref mut log) = log_file {
                        let _ = writeln!(log, "Added {} unique files from USN Journal", final_journal_added);
                        let _ = log.flush();
                    }
                }
                Err(e) => {
                    // Log error but continue with MFT results
                    if let Some(ref mut log) = log_file {
                        let _ = writeln!(log, "USN Journal scan failed: {}", e);
                        let _ = writeln!(log, "Continuing with MFT results only");
                        let _ = log.flush();
                    }
                }
            }
        }

        // File carving - always run for comprehensive recovery
        // Update status for file carving
        *scan_status.lock().unwrap() = "File Carving: Searching for file signatures...".to_string();

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "");
            let _ = writeln!(log, "=== Starting File Carving Scan ===");
            let _ = log.flush();
        }

        // Check if user requested stop
        if *should_stop.lock().unwrap() {
            if let Some(ref mut log) = log_file {
                let _ = writeln!(log, "Scan STOPPED before File Carving phase");
                let _ = log.flush();
            }

            if let Some(ref mut log) = log_file {
                let _ = writeln!(log, "");
                let _ = writeln!(log, "=== Scan Summary ===");
                let _ = writeln!(log, "Total files found: {}", files_output.lock().unwrap().len());
                let _ = log.flush();
            }

            return Ok(true);
        }

        {

            // Define signatures to search for (most common file types)
            let signatures = vec![
                // Documents
                crate::scanner::file_carving::FileSignature::PDF,
                crate::scanner::file_carving::FileSignature::DOCX,
                crate::scanner::file_carving::FileSignature::XLSX,
                crate::scanner::file_carving::FileSignature::PPTX,
                crate::scanner::file_carving::FileSignature::DOC,
                crate::scanner::file_carving::FileSignature::XLS,
                crate::scanner::file_carving::FileSignature::PPT,
                crate::scanner::file_carving::FileSignature::ODT,
                crate::scanner::file_carving::FileSignature::ODS,
                crate::scanner::file_carving::FileSignature::ODP,

                // Images
                crate::scanner::file_carving::FileSignature::JPEG,
                crate::scanner::file_carving::FileSignature::PNG,
                crate::scanner::file_carving::FileSignature::GIF,
                crate::scanner::file_carving::FileSignature::BMP,
                crate::scanner::file_carving::FileSignature::WEBP,
                crate::scanner::file_carving::FileSignature::TIFF,

                // Videos
                crate::scanner::file_carving::FileSignature::MP4,
                crate::scanner::file_carving::FileSignature::AVI,
                crate::scanner::file_carving::FileSignature::MKV,
                crate::scanner::file_carving::FileSignature::WEBM,
                crate::scanner::file_carving::FileSignature::MOV,
                crate::scanner::file_carving::FileSignature::FLV,
                crate::scanner::file_carving::FileSignature::WMV,
                crate::scanner::file_carving::FileSignature::THREE_GP,

                // Audio
                crate::scanner::file_carving::FileSignature::MP3,
                crate::scanner::file_carving::FileSignature::WAV,
                crate::scanner::file_carving::FileSignature::FLAC,
                crate::scanner::file_carving::FileSignature::M4A,

                // Archives
                crate::scanner::file_carving::FileSignature::ZIP,
                crate::scanner::file_carving::FileSignature::RAR,
                crate::scanner::file_carving::FileSignature::SEVEN_ZIP,
                crate::scanner::file_carving::FileSignature::TAR_GZ,

                // Executables
                crate::scanner::file_carving::FileSignature::EXE,
                crate::scanner::file_carving::FileSignature::DLL,

                // Databases
                crate::scanner::file_carving::FileSignature::SQLITE,

                // Disk Images
                crate::scanner::file_carving::FileSignature::ISO,
                crate::scanner::file_carving::FileSignature::VMDK,

                // Machine Learning
                crate::scanner::file_carving::FileSignature::SAFETENSORS,
                crate::scanner::file_carving::FileSignature::ONNX,

                // Other
                crate::scanner::file_carving::FileSignature::TORRENT,
            ];

            let bytes_per_cluster = boot_sector.bytes_per_sector as u64 * boot_sector.sectors_per_cluster as u64;
            let sector_size = boot_sector.bytes_per_sector as u64;

            // Scan up to configured cluster limit to find file signatures
            let max_clusters = self.file_carving_cluster_limit.min(boot_sector.total_sectors / boot_sector.sectors_per_cluster as u64);
            let start_cluster = 2; // Clusters start at 2
            let end_cluster = start_cluster + max_clusters;

            *scan_status.lock().unwrap() = format!("File Carving: Scanning {} clusters (parallel mode: {} threads)...", max_clusters, self.parallel_threads);

            if let Some(ref mut log) = log_file {
                let _ = writeln!(log, "File carving configured for {} parallel threads", self.parallel_threads);
                let _ = writeln!(log, "Note: Parallel scanning active for improved performance");
                let _ = log.flush();
            }

            // Perform parallel file carving using rayon for maximum performance
            let max_carved_files = self.file_carving_max_files;
            let carved_count = Arc::new(AtomicU64::new(0));
            let should_terminate = Arc::new(AtomicBool::new(false));
            let progress_counter = Arc::new(AtomicU64::new(0));

            // Configure rayon thread pool
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(self.parallel_threads)
                .build()
                .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());

            // Process clusters in parallel chunks
            let chunk_size = 10_000u64; // Process 10K clusters per batch
            let total_chunks = ((end_cluster - start_cluster + 1) + chunk_size - 1) / chunk_size;

            pool.install(|| {
                (0..total_chunks).into_par_iter().for_each(|chunk_idx| {
                    // Early termination checks
                    if should_terminate.load(Ordering::Relaxed) {
                        return;
                    }

                    if *should_stop.lock().unwrap() {
                        should_terminate.store(true, Ordering::Relaxed);
                        return;
                    }

                    if carved_count.load(Ordering::Relaxed) >= max_carved_files {
                        should_terminate.store(true, Ordering::Relaxed);
                        return;
                    }

                    let chunk_start = start_cluster + (chunk_idx * chunk_size);
                    let chunk_end = (chunk_start + chunk_size - 1).min(end_cluster);

                    // Open disk handle per thread (thread-safe)
                    let thread_disk = match DiskHandle::open(self.drive_letter) {
                        Ok(d) => d,
                        Err(_) => return,
                    };

                    let thread_carver = crate::scanner::file_carving::FileCarver::new(self.drive_letter);

                    for cluster in chunk_start..=chunk_end {
                        // Check termination conditions
                        if should_terminate.load(Ordering::Relaxed) {
                            break;
                        }

                        if carved_count.load(Ordering::Relaxed) >= max_carved_files {
                            should_terminate.store(true, Ordering::Relaxed);
                            break;
                        }

                        // Progress update every 500,000 clusters
                        let clusters_processed = progress_counter.fetch_add(1, Ordering::Relaxed) + 1;
                        if clusters_processed % 500_000 == 0 {
                            let progress = (clusters_processed as f64 / max_clusters as f64) * 100.0;
                            let gb_scanned = (clusters_processed as f64 * bytes_per_cluster as f64) / 1_073_741_824.0;
                            let current_count = carved_count.load(Ordering::Relaxed);

                            *scan_status.lock().unwrap() = format!(
                                "File Carving: {:.1}% ({:.1} GB scanned, {} files)",
                                progress, gb_scanned, current_count
                            );
                        }

                        // Scan this cluster for signatures (no log_file in parallel context)
                        if let Some((sig, cluster_num)) = thread_carver.scan_cluster_for_signature(
                            &thread_disk,
                            cluster,
                            boot_sector.sectors_per_cluster as u64,
                            0,
                            sector_size,
                            &signatures,
                            &mut None,
                        ) {
                            // Apply filters
                            let filename = format!("recovered_{}.{}", cluster, sig.extension);
                            let full_path = format!("{}:\\recovered_{}.{}", self.drive_letter, cluster, sig.extension);

                            let mut include = true;

                            if let Some(filter) = filename_filter {
                                if !filter.is_empty() && !filename.to_lowercase().contains(&filter.to_lowercase()) {
                                    include = false;
                                }
                            }

                            if let Some(path_filter) = folder_path {
                                if !path_filter.is_empty() && !full_path.to_lowercase().contains(&path_filter.to_lowercase()) {
                                    include = false;
                                }
                            }

                            if include {
                                let current = carved_count.fetch_add(1, Ordering::Relaxed);

                                // Stop if we exceeded max after increment
                                if current >= max_carved_files {
                                    should_terminate.store(true, Ordering::Relaxed);
                                    return;
                                }

                                // Parse file header to determine actual file size
                                let (file_size, cluster_count) = if let Some(parsed_size) = thread_carver.parse_file_size(
                                    &thread_disk,
                                    cluster_num,
                                    boot_sector.sectors_per_cluster as u64,
                                    0,
                                    sector_size,
                                    &sig,
                                    &mut None,
                                ) {
                                    let clusters_needed = (parsed_size + bytes_per_cluster - 1) / bytes_per_cluster;
                                    (parsed_size, clusters_needed)
                                } else {
                                    // Fallback to estimation if parsing fails
                                    let estimated_clusters = match sig.extension {
                                        "png" | "gif" => 64,
                                        "jpg" => 128,
                                        "pdf" => 256,
                                        "doc" | "docx" => 128,
                                        "xls" | "xlsx" => 256,
                                        "ppt" | "pptx" => 512,
                                        "mp3" | "wav" => 1024,
                                        "mp4" | "avi" | "mkv" => 25600,
                                        "zip" | "rar" | "7z" => 2048,
                                        _ => 256,
                                    };

                                    let estimated_size = bytes_per_cluster * estimated_clusters;
                                    (estimated_size, estimated_clusters)
                                };

                                files_output.lock().unwrap().push(DeletedFile {
                                    name: filename.clone(),
                                    path: full_path.clone(),
                                    size: file_size,
                                    size_formatted: crate::scanner::DeletedFile::format_size(file_size),
                                    deleted_time: None,
                                    file_record: cluster_num,
                                    clusters: Vec::new(),
                                    cluster_ranges: vec![super::ClusterRange {
                                        start: cluster_num,
                                        count: cluster_count,
                                    }],
                                    is_recoverable: true,
                                    filesystem_type: format!("NTFS (File Carving: {})", sig.description),
                                });
                            }
                        }
                    }
                });
            });

            let final_count = carved_count.load(Ordering::Relaxed);

            if let Some(ref mut log) = log_file {
                let _ = writeln!(log, "File carving complete. Added {} files (after filters)", final_count);
                let _ = writeln!(log, "Parallel scanning used {} threads", self.parallel_threads);
                let _ = log.flush();
            }
        }

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "");
            let _ = writeln!(log, "=== Scan Summary ===");
            let _ = writeln!(log, "Total files found: {}", files_output.lock().unwrap().len());
            let _ = log.flush();
        }

        Ok(false) // Return false to indicate scan completed normally
    }

    fn get_filesystem_type(&self) -> &str {
        "NTFS"
    }
}

// Additional helper methods for NtfsScanner (outside trait implementation)
impl NtfsScanner {
    /// Build MFT cache for path reconstruction from USN Journal records
    fn build_mft_cache_for_journal(&mut self, disk: &DiskHandle, boot_sector: &NtfsBootSector) -> HashMap<u64, String> {
        let mut cache = HashMap::new();

        // Read a subset of MFT records to build directory name cache
        // This is a simplified version - only cache first 10,000 records
        for record_num in 0..10_000 {
            if let Ok(record_data) = self.read_mft_record(disk, boot_sector, record_num) {
                if let Ok(Some(record)) = self.parse_mft_record(&record_data) {
                    if let Ok(Some((name, _parent))) = self.extract_file_info_for_path(&record) {
                        cache.insert(record_num, name);
                    }
                }
            }
        }

        cache
    }
}

#[derive(Debug)]
struct NtfsBootSector {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    mft_cluster: u64,
    clusters_per_mft_record: i8,
    total_sectors: u64,
}

#[derive(Debug)]
struct MftRecord {
    flags: u16,
    is_in_use: bool,
    first_attr_offset: usize,
    data: Vec<u8>,
}

#[derive(Debug)]
struct DeletedFileInfo {
    filename: String,
    parent_ref: Option<u64>,
    size: u64,
    record_num: u64,
    cluster_ranges: Vec<crate::scanner::ClusterRange>,
}
