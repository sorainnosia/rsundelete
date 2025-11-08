use super::{DeletedFile, FileSystemScanner};
use super::disk_access::DiskHandle;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc, TimeZone};
use std::fs::OpenOptions;
use std::io::Write;
use rayon::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

const EXFAT_ENTRY_SIZE: usize = 32;
const EXFAT_FILE_ENTRY: u8 = 0x85;
const EXFAT_STREAM_ENTRY: u8 = 0xC0;
const EXFAT_FILENAME_ENTRY: u8 = 0xC1;

pub struct ExfatScanner {
    drive_letter: char,
    directory_entries_limit: u64,
    parallel_threads: usize,
}

impl ExfatScanner {
    pub fn new(drive_letter: char) -> Self {
        Self {
            drive_letter,
            directory_entries_limit: 1_000_000, // Default
            parallel_threads: 8, // Default
        }
    }

    /// Set configuration limits
    pub fn set_config(&mut self, directory_entries_limit: u64, parallel_threads: usize) {
        self.directory_entries_limit = directory_entries_limit;
        self.parallel_threads = parallel_threads.max(1).min(32);
    }

    fn read_boot_sector(&self, disk: &DiskHandle) -> Result<ExfatBootSector> {
        let sector_size = disk.get_sector_size()?;
        let boot_data = disk.read_sectors(0, 1, sector_size)?;

        if boot_data.len() < 512 {
            anyhow::bail!("Boot sector too small");
        }

        // Verify exFAT signature
        if &boot_data[3..11] != b"EXFAT   " {
            anyhow::bail!("Not an exFAT filesystem");
        }

        let bytes_per_sector_shift = boot_data[108];
        let sectors_per_cluster_shift = boot_data[109];

        let cluster_heap_offset = u32::from_le_bytes([
            boot_data[88],
            boot_data[89],
            boot_data[90],
            boot_data[91],
        ]);

        let cluster_count = u32::from_le_bytes([
            boot_data[92],
            boot_data[93],
            boot_data[94],
            boot_data[95],
        ]);

        let root_dir_cluster = u32::from_le_bytes([
            boot_data[96],
            boot_data[97],
            boot_data[98],
            boot_data[99],
        ]);

        let fat_offset = u32::from_le_bytes([
            boot_data[80],
            boot_data[81],
            boot_data[82],
            boot_data[83],
        ]);

        let fat_length = u32::from_le_bytes([
            boot_data[84],
            boot_data[85],
            boot_data[86],
            boot_data[87],
        ]);

        Ok(ExfatBootSector {
            bytes_per_sector: 1u32 << bytes_per_sector_shift,
            sectors_per_cluster: 1u32 << sectors_per_cluster_shift,
            cluster_heap_offset,
            cluster_count,
            root_dir_cluster,
            fat_offset,
            fat_length,
        })
    }

    fn cluster_to_sector(&self, boot: &ExfatBootSector, cluster: u32) -> u64 {
        if cluster < 2 {
            return 0;
        }
        let offset = (cluster - 2) as u64;
        boot.cluster_heap_offset as u64 + (offset * boot.sectors_per_cluster as u64)
    }

    fn read_cluster(&self, disk: &DiskHandle, boot: &ExfatBootSector, cluster: u32) -> Result<Vec<u8>> {
        let sector = self.cluster_to_sector(boot, cluster);
        let sector_size = boot.bytes_per_sector as u64;
        disk.read_sectors(sector, boot.sectors_per_cluster as u64, sector_size)
    }

    /// Read a FAT entry for a given cluster number
    /// Returns the next cluster in the chain, or None if end-of-chain or error
    fn read_fat_entry(&self, disk: &DiskHandle, boot: &ExfatBootSector, cluster: u32) -> Option<u32> {
        // Each FAT entry is 4 bytes (32-bit)
        let fat_entry_offset = cluster as u64 * 4;
        let sector_size = boot.bytes_per_sector as u64;

        // Calculate which sector contains this FAT entry
        let sector_in_fat = fat_entry_offset / sector_size;
        let offset_in_sector = (fat_entry_offset % sector_size) as usize;

        // Read the sector containing the FAT entry
        let fat_sector = boot.fat_offset as u64 + sector_in_fat;

        match disk.read_sectors(fat_sector, 1, sector_size) {
            Ok(data) => {
                if offset_in_sector + 4 <= data.len() {
                    let entry = u32::from_le_bytes([
                        data[offset_in_sector],
                        data[offset_in_sector + 1],
                        data[offset_in_sector + 2],
                        data[offset_in_sector + 3],
                    ]);

                    // exFAT FAT entry values:
                    // 0x00000000 = Free cluster
                    // 0x00000001 = Reserved
                    // 0x00000002-0xFFFFFFF6 = Next cluster in chain
                    // 0xFFFFFFF7 = Bad cluster
                    // 0xFFFFFFF8-0xFFFFFFFF = End of chain

                    if entry >= 0xFFFFFFF8 {
                        // End of chain
                        None
                    } else if entry >= 2 && entry <= 0xFFFFFFF6 {
                        // Valid next cluster
                        Some(entry)
                    } else {
                        // Invalid or bad cluster
                        None
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Follow the FAT chain starting from a given cluster
    /// Returns a vector of all clusters in the chain
    fn follow_fat_chain(&self, disk: &DiskHandle, boot: &ExfatBootSector, start_cluster: u32, max_clusters: usize) -> Vec<u64> {
        let mut clusters = Vec::new();
        let mut current_cluster = start_cluster;

        // Add the first cluster
        clusters.push(current_cluster as u64);

        // Follow the chain
        while clusters.len() < max_clusters {
            match self.read_fat_entry(disk, boot, current_cluster) {
                Some(next_cluster) => {
                    clusters.push(next_cluster as u64);
                    current_cluster = next_cluster;
                }
                None => {
                    // End of chain or error
                    break;
                }
            }
        }

        clusters
    }

    fn parse_directory_entries(&self, data: &[u8]) -> Vec<DirectoryEntry> {
        let mut entries = Vec::new();
        let mut offset = 0;

        while offset + EXFAT_ENTRY_SIZE <= data.len() {
            let entry_type = data[offset];

            // Skip free entries (0x00) and end marker (0xFF for unused)
            if entry_type == 0x00 {
                offset += EXFAT_ENTRY_SIZE;
                continue;
            }

            entries.push(DirectoryEntry {
                entry_type,
                data: data[offset..offset + EXFAT_ENTRY_SIZE].to_vec(),
            });

            offset += EXFAT_ENTRY_SIZE;
        }

        entries
    }

    fn extract_deleted_files(&self, entries: &[DirectoryEntry]) -> Vec<DeletedFileEntry> {
        let mut deleted_files = Vec::new();
        let mut i = 0;

        while i < entries.len() {
            let entry_type = entries[i].entry_type;

            // Check if this is a deleted file entry (bit 7 clear for deleted)
            if (entry_type & 0x80) == 0 && (entry_type & 0x7F) == 0x05 {
                // This is a deleted file entry
                if let Some(file_info) = self.parse_file_entry(&entries[i..], false) {
                    deleted_files.push(file_info);
                }
            }

            i += 1;
        }

        deleted_files
    }

    fn extract_active_directories(&self, entries: &[DirectoryEntry]) -> Vec<DeletedFileEntry> {
        let mut directories = Vec::new();
        let mut i = 0;

        while i < entries.len() {
            let entry_type = entries[i].entry_type;

            // Check if this is an active directory entry (bit 7 set for in-use)
            if (entry_type & 0x80) != 0 && (entry_type & 0x7F) == 0x05 {
                // Check if it's a directory (bit 4 set in file attributes)
                if let Some(dir_info) = self.parse_file_entry(&entries[i..], true) {
                    directories.push(dir_info);
                }
            }

            i += 1;
        }

        directories
    }

    fn parse_file_entry(&self, entries: &[DirectoryEntry], only_directories: bool) -> Option<DeletedFileEntry> {
        if entries.is_empty() {
            return None;
        }

        let file_entry = &entries[0].data;
        let secondary_count = file_entry[1] as usize;
        let file_attributes = u16::from_le_bytes([file_entry[4], file_entry[5]]);
        let is_directory = (file_attributes & 0x0010) != 0;

        // If we only want directories, skip files
        if only_directories && !is_directory {
            return None;
        }
        // If we want files, skip directories
        if !only_directories && is_directory {
            return None;
        }

        if entries.len() < 1 + secondary_count {
            return None;
        }

        let mut stream_entry_data: Option<&Vec<u8>> = None;
        let mut filename_parts = Vec::new();

        for i in 1..=secondary_count {
            if i >= entries.len() {
                break;
            }

            let entry_type = entries[i].entry_type & 0x7F;

            match entry_type {
                0x40 => {
                    // Stream extension entry
                    stream_entry_data = Some(&entries[i].data);
                }
                0x41 => {
                    // File name entry
                    filename_parts.push(&entries[i].data);
                }
                _ => {}
            }
        }

        let stream_data = stream_entry_data?;

        let file_size = u64::from_le_bytes([
            stream_data[8],
            stream_data[9],
            stream_data[10],
            stream_data[11],
            stream_data[12],
            stream_data[13],
            stream_data[14],
            stream_data[15],
        ]);

        let first_cluster = u32::from_le_bytes([
            stream_data[20],
            stream_data[21],
            stream_data[22],
            stream_data[23],
        ]);

        // Extract filename
        let mut filename = String::new();
        for name_entry in filename_parts {
            for chunk_idx in 0..15 {
                let offset = 2 + chunk_idx * 2;
                if offset + 1 < name_entry.len() {
                    let char_code = u16::from_le_bytes([name_entry[offset], name_entry[offset + 1]]);
                    if char_code != 0 {
                        filename.push(char::from_u32(char_code as u32).unwrap_or('?'));
                    }
                }
            }
        }

        if filename.is_empty() {
            return None;
        }

        Some(DeletedFileEntry {
            filename,
            size: file_size,
            first_cluster,
        })
    }

    fn scan_directory_recursive(
        &self,
        disk: &DiskHandle,
        boot: &ExfatBootSector,
        cluster: u32,
        path: &str,
        filename_filter: Option<&str>,
        folder_filter: Option<&str>,
        log_file: &mut Option<std::fs::File>,
        total_deleted: &mut usize,
        depth: u32,
    ) -> Result<Vec<DeletedFile>> {
        // Prevent infinite recursion
        if depth > 20 {
            return Ok(Vec::new());
        }

        let mut deleted_files = Vec::new();

        // Read directory cluster
        let data = match self.read_cluster(disk, boot, cluster) {
            Ok(d) => d,
            Err(e) => {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "Failed to read cluster {} for {}: {}", cluster, path, e);
                    let _ = log.flush();
                }
                return Ok(Vec::new());
            }
        };

        let entries = self.parse_directory_entries(&data);

        // Extract deleted files in this directory
        let deleted = self.extract_deleted_files(&entries);

        if let Some(ref mut log) = log_file {
            if !deleted.is_empty() {
                let _ = writeln!(log, "Found {} deleted file(s) in: {}", deleted.len(), path);
                let _ = log.flush();
            }
        }

        for file in deleted {
            *total_deleted += 1;
            let full_path = format!("{}\\{}", path.trim_end_matches('\\'), file.filename);

            // Log first 10 deleted files
            if *total_deleted <= 10 {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "Deleted file #{}: '{}' at '{}', size: {} bytes, first_cluster: {}",
                                    *total_deleted, file.filename, full_path, file.size, file.first_cluster);
                    let _ = log.flush();
                }
            }

            let mut include = true;

            if let Some(filter) = filename_filter {
                if !filter.is_empty() && !file.filename.to_lowercase().contains(&filter.to_lowercase()) {
                    include = false;
                }
            }

            if let Some(path_filter) = folder_filter {
                if !path_filter.is_empty() && !full_path.to_lowercase().contains(&path_filter.to_lowercase()) {
                    include = false;
                }
            }

            if include {
                // Calculate how many clusters we need for this file
                let cluster_size = boot.sectors_per_cluster as u64 * boot.bytes_per_sector as u64;
                let max_clusters = if cluster_size > 0 {
                    ((file.size + cluster_size - 1) / cluster_size) as usize
                } else {
                    1
                };

                // Follow FAT chain to get all clusters for this file
                let clusters = if file.first_cluster >= 2 {
                    self.follow_fat_chain(disk, boot, file.first_cluster, max_clusters)
                } else {
                    vec![file.first_cluster as u64]
                };

                if let Some(ref mut log) = log_file {
                    if *total_deleted <= 10 {
                        let _ = writeln!(log, "  → FAT chain followed: {} clusters found for {} bytes",
                                        clusters.len(), file.size);
                        let _ = log.flush();
                    }
                }

                deleted_files.push(DeletedFile {
                    name: file.filename.clone(),
                    path: full_path.clone(),
                    size: file.size,
                    size_formatted: crate::scanner::DeletedFile::format_size(file.size),
                    deleted_time: None,
                    file_record: file.first_cluster as u64,
                    clusters,
                    cluster_ranges: Vec::new(), // Empty for exFAT (uses clusters field instead)
                    is_recoverable: file.first_cluster >= 2,
                    filesystem_type: "exFAT".to_string(),
                });
            } else {
                // Log filtered out files
                if deleted_files.len() < 10 {
                    if let Some(ref mut log) = log_file {
                        let _ = writeln!(log, "FILTERED OUT - Name: '{}', Path: '{}', Size: {}",
                                        file.filename, full_path, file.size);
                        if let Some(ff) = filename_filter {
                            let _ = writeln!(log, "  Filename filter: '{}', Match: {}",
                                            ff, file.filename.to_lowercase().contains(&ff.to_lowercase()));
                        }
                        if let Some(pf) = folder_filter {
                            let _ = writeln!(log, "  Path filter: '{}', Match: {}",
                                            pf, full_path.to_lowercase().contains(&pf.to_lowercase()));
                        }
                        let _ = log.flush();
                    }
                }
            }
        }

        // Recursively scan subdirectories
        let directories = self.extract_active_directories(&entries);

        if let Some(ref mut log) = log_file {
            if !directories.is_empty() {
                let _ = writeln!(log, "Scanning {} subdirectory(ies) in: {}", directories.len(), path);
                let _ = log.flush();
            }
        }

        for dir in directories {
            if dir.first_cluster >= 2 {
                let subdir_path = format!("{}\\{}", path.trim_end_matches('\\'), dir.filename);

                if let Ok(mut subdir_files) = self.scan_directory_recursive(
                    disk,
                    boot,
                    dir.first_cluster,
                    &subdir_path,
                    filename_filter,
                    folder_filter,
                    log_file,
                    total_deleted,
                    depth + 1,
                ) {
                    deleted_files.append(&mut subdir_files);
                }
            }
        }

        Ok(deleted_files)
    }
}

impl FileSystemScanner for ExfatScanner {
    fn scan(
        &mut self,
        drive_letter: char,
        folder_path: Option<&str>,
        filename_filter: Option<&str>,
    ) -> Result<Vec<DeletedFile>> {
        // Create log file in the executable directory
        let log_path = std::env::current_exe()
            .ok()
            .and_then(|exe_path| exe_path.parent().map(|p| p.join("rsundelete_debug.log")))
            .and_then(|path| path.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "rsundelete_debug.log".to_string());

        let mut log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "");
            let _ = writeln!(log, "=== exFAT Scanner Started ===");
            let _ = writeln!(log, "Drive: {}", drive_letter);
            let _ = writeln!(log, "Folder filter: {:?}", folder_path);
            let _ = writeln!(log, "Filename filter: {:?}", filename_filter);
            let _ = writeln!(log, "");
            let _ = log.flush();
        }

        self.drive_letter = drive_letter;

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
                    let _ = log.flush();
                }
                return Err(e).context("Failed to open disk for exFAT scanning");
            }
        };

        let boot_sector = match self.read_boot_sector(&disk) {
            Ok(bs) => {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "SUCCESS: Boot sector read");
                    let _ = writeln!(log, "Bytes per sector: {}", bs.bytes_per_sector);
                    let _ = writeln!(log, "Sectors per cluster: {}", bs.sectors_per_cluster);
                    let _ = writeln!(log, "Root directory cluster: {}", bs.root_dir_cluster);
                    let _ = writeln!(log, "");
                    let _ = writeln!(log, "Starting recursive directory scan...");
                    let _ = log.flush();
                }
                bs
            }
            Err(e) => {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "FAILED to read boot sector: {}", e);
                    let _ = log.flush();
                }
                return Err(e).context("Failed to read exFAT boot sector");
            }
        };

        let root_path = format!("{}:", drive_letter);
        let mut total_deleted = 0;

        // Recursively scan all directories
        let deleted_files = self.scan_directory_recursive(
            &disk,
            &boot_sector,
            boot_sector.root_dir_cluster,
            &root_path,
            filename_filter,
            folder_path,
            &mut log_file,
            &mut total_deleted,
            0,
        )?;

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "");
            let _ = writeln!(log, "=== Scan Summary ===");
            let _ = writeln!(log, "Found {} total deleted files (before filtering)", total_deleted);
            let _ = writeln!(log, "After filtering: {} files", deleted_files.len());
            let _ = writeln!(log, "");
            let _ = writeln!(log, "==========================================");
            let _ = writeln!(log, "Log file saved to: {}", log_path);
            let _ = writeln!(log, "==========================================");
            let _ = log.flush();
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
        _scan_status: &std::sync::Arc<std::sync::Mutex<String>>,
    ) -> Result<bool> {
        // Create log file in the executable directory
        let log_path = std::env::current_exe()
            .ok()
            .and_then(|exe_path| exe_path.parent().map(|p| p.join("rsundelete_debug.log")))
            .and_then(|path| path.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "rsundelete_debug.log".to_string());

        let mut log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "");
            let _ = writeln!(log, "=== exFAT Scan (Real-time mode) ===");
            let _ = writeln!(log, "Drive: {}", drive_letter);
            let _ = writeln!(log, "Parallel threads configured: {} (directory traversal is sequential)", self.parallel_threads);
            let _ = writeln!(log, "Note: exFAT uses sequential directory traversal due to its recursive structure");
            let _ = log.flush();
        }

        let disk = DiskHandle::open(drive_letter).context("Failed to open disk for exFAT scanning")?;
        let boot_sector = self.read_boot_sector(&disk).context("Failed to read exFAT boot sector")?;

        let root_path = format!("{}:", drive_letter);
        let mut total_deleted = 0;

        // Call recursive scan with stop checking
        let was_stopped = self.scan_directory_recursive_with_stop(
            &disk,
            &boot_sector,
            boot_sector.root_dir_cluster,
            &root_path,
            filename_filter,
            folder_path,
            &mut log_file,
            &mut total_deleted,
            0,
            files_output,
            should_stop,
        )?;

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "");
            if was_stopped {
                let _ = writeln!(log, "Scan STOPPED by user. Found {} files before stopping", files_output.lock().unwrap().len());
            } else {
                let _ = writeln!(log, "Scan complete. Found {} files", files_output.lock().unwrap().len());
            }
            let _ = log.flush();
        }

        Ok(was_stopped)
    }

    fn get_filesystem_type(&self) -> &str {
        "exFAT"
    }
}

impl ExfatScanner {
    fn scan_directory_recursive_with_stop(
        &self,
        disk: &DiskHandle,
        boot: &ExfatBootSector,
        cluster: u32,
        path: &str,
        filename_filter: Option<&str>,
        folder_filter: Option<&str>,
        log_file: &mut Option<std::fs::File>,
        total_deleted: &mut usize,
        depth: u32,
        files_output: &std::sync::Arc<std::sync::Mutex<Vec<DeletedFile>>>,
        should_stop: &std::sync::Arc<std::sync::Mutex<bool>>,
    ) -> Result<bool> {
        // Check if we should stop
        if *should_stop.lock().unwrap() {
            if let Some(ref mut log) = log_file {
                let _ = writeln!(log, "Scan STOPPED by user in directory: {}", path);
                let _ = log.flush();
            }
            return Ok(true); // Return true to indicate scan was stopped
        }

        // Prevent infinite recursion
        if depth > 20 {
            return Ok(false);
        }

        // Read directory cluster
        let data = match self.read_cluster(disk, boot, cluster) {
            Ok(d) => d,
            Err(e) => {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "Failed to read cluster {} for {}: {}", cluster, path, e);
                    let _ = log.flush();
                }
                return Ok(false);
            }
        };

        let entries = self.parse_directory_entries(&data);

        // Extract deleted files in this directory
        let deleted = self.extract_deleted_files(&entries);

        for file in deleted {
            // Check stop flag before processing each file
            if *should_stop.lock().unwrap() {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "Scan STOPPED by user while processing files in: {}", path);
                    let _ = log.flush();
                }
                return Ok(true);
            }

            *total_deleted += 1;
            let full_path = format!("{}\\{}", path.trim_end_matches('\\'), file.filename);

            let mut include = true;

            if let Some(filter) = filename_filter {
                if !filter.is_empty() && !file.filename.to_lowercase().contains(&filter.to_lowercase()) {
                    include = false;
                }
            }

            if let Some(path_filter) = folder_filter {
                if !path_filter.is_empty() && !full_path.to_lowercase().contains(&path_filter.to_lowercase()) {
                    include = false;
                }
            }

            if include {
                // Calculate how many clusters we need for this file
                let cluster_size = boot.sectors_per_cluster as u64 * boot.bytes_per_sector as u64;
                let max_clusters = if cluster_size > 0 {
                    ((file.size + cluster_size - 1) / cluster_size) as usize
                } else {
                    1
                };

                // Follow FAT chain to get all clusters for this file
                let clusters = if file.first_cluster >= 2 {
                    self.follow_fat_chain(disk, boot, file.first_cluster, max_clusters)
                } else {
                    vec![file.first_cluster as u64]
                };

                // Push to output immediately for real-time updates!
                files_output.lock().unwrap().push(DeletedFile {
                    name: file.filename.clone(),
                    path: full_path.clone(),
                    size: file.size,
                    size_formatted: crate::scanner::DeletedFile::format_size(file.size),
                    deleted_time: None,
                    file_record: file.first_cluster as u64,
                    clusters,
                    cluster_ranges: Vec::new(), // Empty for exFAT (uses clusters field instead)
                    is_recoverable: file.first_cluster >= 2,
                    filesystem_type: "exFAT".to_string(),
                });

                // Log first 10 deleted files
                if files_output.lock().unwrap().len() <= 10 {
                    if let Some(ref mut log) = log_file {
                        let _ = writeln!(log, "File #{}: '{}' at '{}', size: {} bytes",
                                        files_output.lock().unwrap().len(), file.filename, full_path, file.size);
                        let _ = log.flush();
                    }
                }
            }
        }

        // Recursively scan subdirectories
        let directories = self.extract_active_directories(&entries);

        for dir in directories {
            // Check stop flag before processing each subdirectory
            if *should_stop.lock().unwrap() {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "Scan STOPPED by user before scanning subdirectory: {}", dir.filename);
                    let _ = log.flush();
                }
                return Ok(true);
            }

            if dir.first_cluster >= 2 {
                let subdir_path = format!("{}\\{}", path.trim_end_matches('\\'), dir.filename);

                let was_stopped = self.scan_directory_recursive_with_stop(
                    disk,
                    boot,
                    dir.first_cluster,
                    &subdir_path,
                    filename_filter,
                    folder_filter,
                    log_file,
                    total_deleted,
                    depth + 1,
                    files_output,
                    should_stop,
                )?;

                if was_stopped {
                    return Ok(true);
                }
            }
        }

        Ok(false) // Completed normally (not stopped)
    }
}

#[derive(Debug)]
struct ExfatBootSector {
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    cluster_heap_offset: u32,
    cluster_count: u32,
    root_dir_cluster: u32,
    fat_offset: u32,
    fat_length: u32,
}

#[derive(Debug)]
struct DirectoryEntry {
    entry_type: u8,
    data: Vec<u8>,
}

#[derive(Debug)]
struct DeletedFileEntry {
    filename: String,
    size: u64,
    first_cluster: u32,
}
