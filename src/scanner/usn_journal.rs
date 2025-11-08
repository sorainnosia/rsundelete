use super::disk_access::DiskHandle;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// USN Journal parser for NTFS
/// Reads $Extend\$UsnJrnl:$J to find deleted file records
/// This is particularly useful for system drives where MFT entries are quickly reused

// USN Reason flags - indicate what operation occurred
const USN_REASON_DATA_OVERWRITE: u32 = 0x00000001;
const USN_REASON_DATA_EXTEND: u32 = 0x00000002;
const USN_REASON_DATA_TRUNCATION: u32 = 0x00000004;
const USN_REASON_NAMED_DATA_OVERWRITE: u32 = 0x00000010;
const USN_REASON_NAMED_DATA_EXTEND: u32 = 0x00000020;
const USN_REASON_NAMED_DATA_TRUNCATION: u32 = 0x00000040;
const USN_REASON_FILE_CREATE: u32 = 0x00000100;
const USN_REASON_FILE_DELETE: u32 = 0x00000200;
const USN_REASON_RENAME_OLD_NAME: u32 = 0x00001000;
const USN_REASON_RENAME_NEW_NAME: u32 = 0x00002000;
const USN_REASON_CLOSE: u32 = 0x80000000;

// File attributes
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;

#[derive(Debug, Clone)]
pub struct UsnRecord {
    pub record_length: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_reference_number: u64,
    pub parent_file_reference_number: u64,
    pub usn: i64,
    pub timestamp: DateTime<Utc>,
    pub reason: u32,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub filename: String,
}

impl UsnRecord {
    /// Check if this record represents a file deletion
    pub fn is_deletion(&self) -> bool {
        (self.reason & USN_REASON_FILE_DELETE) != 0
    }

    /// Check if this record represents a file creation
    pub fn is_creation(&self) -> bool {
        (self.reason & USN_REASON_FILE_CREATE) != 0
    }

    /// Check if this is a directory
    pub fn is_directory(&self) -> bool {
        (self.file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
    }

    /// Check if this is a regular file
    pub fn is_file(&self) -> bool {
        !self.is_directory()
    }

    /// Get MFT record number (lower 48 bits of file reference)
    pub fn mft_record_number(&self) -> u64 {
        self.file_reference_number & 0x0000_FFFF_FFFF_FFFF
    }

    /// Get parent MFT record number
    pub fn parent_mft_record_number(&self) -> u64 {
        self.parent_file_reference_number & 0x0000_FFFF_FFFF_FFFF
    }
}

pub struct UsnJournalParser {
    drive_letter: char,
}

#[derive(Debug)]
struct NtfsBootSector {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    mft_cluster: u64,
    clusters_per_mft_record: i8,
}

impl UsnJournalParser {
    pub fn new(drive_letter: char) -> Self {
        Self { drive_letter }
    }

    /// Read and parse the USN Journal $J stream
    /// Returns a map of MFT record number -> list of USN records for that file
    pub fn parse_journal(&self, disk: &DiskHandle) -> Result<HashMap<u64, Vec<UsnRecord>>> {
        // Read NTFS boot sector to get MFT location
        let boot_sector = self.read_boot_sector(disk)?;

        // Known MFT record numbers for NTFS metadata files
        const USNJRNL_RECORD: u64 = 38; // $Extend\$UsnJrnl is usually at record 38

        // Read the $UsnJrnl MFT record
        let usnjrnl_data = self.read_mft_record(disk, &boot_sector, USNJRNL_RECORD)?;

        // Find the $J alternate data stream in the MFT record
        let j_stream_clusters = self.parse_j_stream_location(&usnjrnl_data)?;

        if j_stream_clusters.is_empty() {
            eprintln!("USN Journal $J stream not found or empty");
            return Ok(HashMap::new());
        }

        // Read the $J stream data
        let j_data = self.read_clusters(disk, &boot_sector, &j_stream_clusters)?;

        // Parse all USN records from the $J stream
        let records = Self::parse_records_from_buffer(&j_data);

        // Group records by MFT record number
        let mut records_by_mft: HashMap<u64, Vec<UsnRecord>> = HashMap::new();
        for record in records {
            let mft_num = record.mft_record_number();
            records_by_mft.entry(mft_num).or_insert_with(Vec::new).push(record);
        }

        Ok(records_by_mft)
    }

    /// Read NTFS boot sector
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

        Ok(NtfsBootSector {
            bytes_per_sector,
            sectors_per_cluster,
            mft_cluster,
            clusters_per_mft_record,
        })
    }

    /// Read an MFT record
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

    /// Parse the $J alternate data stream location from $UsnJrnl MFT record
    fn parse_j_stream_location(&self, mft_data: &[u8]) -> Result<Vec<super::ClusterRange>> {
        if mft_data.len() < 48 {
            anyhow::bail!("MFT record too small");
        }

        // Check FILE signature
        if &mft_data[0..4] != b"FILE" {
            anyhow::bail!("Invalid MFT record (missing FILE signature)");
        }

        let first_attr_offset = u16::from_le_bytes([mft_data[20], mft_data[21]]) as usize;
        let mut offset = first_attr_offset;

        // Look for $DATA attribute with name "$J"
        while offset + 16 < mft_data.len() {
            let attr_type = u32::from_le_bytes([
                mft_data[offset],
                mft_data[offset + 1],
                mft_data[offset + 2],
                mft_data[offset + 3],
            ]);

            if attr_type == 0xFFFFFFFF {
                break; // End of attributes
            }

            let attr_length = u32::from_le_bytes([
                mft_data[offset + 4],
                mft_data[offset + 5],
                mft_data[offset + 6],
                mft_data[offset + 7],
            ]) as usize;

            if attr_length == 0 || offset + attr_length > mft_data.len() {
                break;
            }

            // 0x80 = $DATA attribute
            if attr_type == 0x80 {
                // Check if this is the $J stream (has a name)
                let name_length = mft_data[offset + 9] as usize;
                let name_offset = u16::from_le_bytes([mft_data[offset + 10], mft_data[offset + 11]]) as usize;

                if name_length > 0 && offset + name_offset + name_length * 2 <= mft_data.len() {
                    // Read attribute name (UTF-16 LE)
                    let name_bytes = &mft_data[offset + name_offset..offset + name_offset + name_length * 2];
                    let name_u16: Vec<u16> = name_bytes
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();
                    let name = String::from_utf16(&name_u16).unwrap_or_default();

                    // Found the $J stream!
                    if name == "$J" {
                        return Ok(self.parse_data_runs(&mft_data[offset..offset + attr_length]));
                    }
                }
            }

            offset += attr_length;
        }

        Ok(Vec::new())
    }

    /// Parse NTFS data runs (similar to ntfs.rs implementation)
    fn parse_data_runs(&self, attr_data: &[u8]) -> Vec<super::ClusterRange> {
        if attr_data.len() < 24 {
            return Vec::new();
        }

        let non_resident = attr_data[8];
        if non_resident == 0 {
            return Vec::new(); // Resident data
        }

        if attr_data.len() < 64 {
            return Vec::new();
        }

        let runlist_offset = u16::from_le_bytes([attr_data[32], attr_data[33]]) as usize;

        if runlist_offset >= attr_data.len() {
            return Vec::new();
        }

        let mut cluster_ranges = Vec::new();
        let mut offset = runlist_offset;
        let mut current_lcn: i64 = 0;

        while offset < attr_data.len() {
            let header = attr_data[offset];
            if header == 0 {
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

            let mut run_length: u64 = 0;
            for i in 0..length_size {
                run_length |= (attr_data[offset + i] as u64) << (i * 8);
            }
            offset += length_size;

            let mut lcn_offset: i64 = 0;
            for i in 0..lcn_size {
                lcn_offset |= (attr_data[offset + i] as i64) << (i * 8);
            }
            if lcn_size > 0 && (attr_data[offset + lcn_size - 1] & 0x80) != 0 {
                for i in lcn_size..8 {
                    lcn_offset |= 0xFF_i64 << (i * 8);
                }
            }
            offset += lcn_size;

            current_lcn += lcn_offset;

            cluster_ranges.push(super::ClusterRange {
                start: current_lcn as u64,
                count: run_length,
            });

            if cluster_ranges.len() > 1_000 {
                break; // Limit for journal
            }
        }

        cluster_ranges
    }

    /// Read data from cluster ranges
    fn read_clusters(&self, disk: &DiskHandle, boot_sector: &NtfsBootSector, clusters: &[super::ClusterRange]) -> Result<Vec<u8>> {
        let sector_size = boot_sector.bytes_per_sector as u64;
        let sectors_per_cluster = boot_sector.sectors_per_cluster as u64;
        let mut data = Vec::new();

        // Limit total size to prevent excessive memory usage (max 128 MB for journal)
        const MAX_JOURNAL_SIZE: u64 = 128 * 1024 * 1024;
        let mut total_read: u64 = 0;

        for range in clusters {
            for i in 0..range.count {
                if total_read >= MAX_JOURNAL_SIZE {
                    break;
                }

                let cluster = range.start + i;
                let sector = cluster * sectors_per_cluster;

                match disk.read_sectors(sector, sectors_per_cluster, sector_size) {
                    Ok(cluster_data) => {
                        data.extend_from_slice(&cluster_data);
                        total_read += cluster_data.len() as u64;
                    }
                    Err(_) => {
                        // Skip unreadable clusters
                        continue;
                    }
                }
            }

            if total_read >= MAX_JOURNAL_SIZE {
                break;
            }
        }

        Ok(data)
    }

    /// Parse a single USN_RECORD_V2 from bytes
    fn parse_usn_record_v2(data: &[u8]) -> Result<Option<UsnRecord>> {
        if data.len() < 60 {
            return Ok(None); // Minimum size for USN_RECORD_V2
        }

        let record_length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        if record_length == 0 || record_length as usize > data.len() {
            return Ok(None);
        }

        let major_version = u16::from_le_bytes([data[4], data[5]]);
        let minor_version = u16::from_le_bytes([data[6], data[7]]);

        // Only support V2 for now (major version 2)
        if major_version != 2 {
            return Ok(None);
        }

        // Parse structure fields according to USN_RECORD_V2 layout
        let file_reference_number = u64::from_le_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);

        let parent_file_reference_number = u64::from_le_bytes([
            data[16], data[17], data[18], data[19],
            data[20], data[21], data[22], data[23],
        ]);

        let usn = i64::from_le_bytes([
            data[24], data[25], data[26], data[27],
            data[28], data[29], data[30], data[31],
        ]);

        // Timestamp is Windows FILETIME (100-nanosecond intervals since Jan 1, 1601)
        let timestamp_raw = i64::from_le_bytes([
            data[32], data[33], data[34], data[35],
            data[36], data[37], data[38], data[39],
        ]);

        // Convert Windows FILETIME to Unix timestamp
        // FILETIME epoch: January 1, 1601
        // Unix epoch: January 1, 1970
        // Difference: 11644473600 seconds
        const FILETIME_TO_UNIX_OFFSET: i64 = 11_644_473_600;
        let timestamp_seconds = (timestamp_raw / 10_000_000) - FILETIME_TO_UNIX_OFFSET;
        let timestamp_nanos = ((timestamp_raw % 10_000_000) * 100) as u32;

        let timestamp = DateTime::from_timestamp(timestamp_seconds, timestamp_nanos)
            .unwrap_or_else(|| Utc::now());

        let reason = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
        let source_info = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        let security_id = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
        let file_attributes = u32::from_le_bytes([data[52], data[53], data[54], data[55]]);

        let filename_length = u16::from_le_bytes([data[56], data[57]]) as usize;
        let filename_offset = u16::from_le_bytes([data[58], data[59]]) as usize;

        // Read filename (UTF-16 LE encoded)
        let filename = if filename_offset + filename_length <= data.len() {
            let filename_bytes = &data[filename_offset..filename_offset + filename_length];

            // Convert UTF-16 LE to String
            let u16_chars: Vec<u16> = filename_bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();

            String::from_utf16(&u16_chars).unwrap_or_else(|_| String::from("???"))
        } else {
            String::from("???")
        };

        Ok(Some(UsnRecord {
            record_length,
            major_version,
            minor_version,
            file_reference_number,
            parent_file_reference_number,
            usn,
            timestamp,
            reason,
            source_info,
            security_id,
            file_attributes,
            filename,
        }))
    }

    /// Parse all USN records from a buffer
    pub fn parse_records_from_buffer(buffer: &[u8]) -> Vec<UsnRecord> {
        let mut records = Vec::new();
        let mut offset = 0;

        while offset + 60 < buffer.len() {
            match Self::parse_usn_record_v2(&buffer[offset..]) {
                Ok(Some(record)) => {
                    let record_length = record.record_length as usize;
                    records.push(record);

                    // Move to next record (aligned to 8-byte boundary)
                    offset += ((record_length + 7) / 8) * 8;
                }
                Ok(None) => {
                    // Invalid record, try next potential record
                    offset += 8; // Try next 8-byte aligned position
                }
                Err(_) => {
                    offset += 8;
                }
            }

            // Safety: don't scan forever
            if records.len() > 10_000_000 {
                break;
            }
        }

        records
    }

    /// Find deleted file records from USN Journal
    /// Returns records where reason includes FILE_DELETE
    pub fn find_deleted_files(&self, disk: &DiskHandle) -> Result<Vec<UsnRecord>> {
        let all_records = self.parse_journal(disk)?;

        let mut deleted_files = Vec::new();

        for (_mft_num, records) in all_records {
            for record in records {
                if record.is_deletion() && record.is_file() {
                    deleted_files.push(record);
                }
            }
        }

        Ok(deleted_files)
    }

    /// Get file path from USN record by traversing parent references
    /// This requires the MFT to still have parent directory entries
    pub fn build_path_from_record(
        &self,
        record: &UsnRecord,
        mft_cache: &HashMap<u64, String>, // MFT number -> directory name cache
    ) -> String {
        let mut path_components = vec![record.filename.clone()];
        let current_parent = record.parent_mft_record_number();

        // Traverse up to root (MFT record 5)
        const ROOT_DIRECTORY: u64 = 5;
        let _visited: std::collections::HashSet<u64> = std::collections::HashSet::new();

        if current_parent != ROOT_DIRECTORY && current_parent != 0 {
            if let Some(parent_name) = mft_cache.get(&current_parent) {
                path_components.push(parent_name.clone());
                // Would need to get parent's parent from MFT
                // For now, stop here
            }
        }

        // Reverse to get path from root to file
        path_components.reverse();

        format!("{}:\\{}", self.drive_letter, path_components.join("\\"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usn_record_v2_parsing() {
        // Create a minimal USN_RECORD_V2 structure for testing
        let mut data = vec![0u8; 100];

        // Record length: 100 bytes
        data[0..4].copy_from_slice(&100u32.to_le_bytes());

        // Major version: 2
        data[4..6].copy_from_slice(&2u16.to_le_bytes());

        // Minor version: 0
        data[6..8].copy_from_slice(&0u16.to_le_bytes());

        // File reference: MFT entry 1000
        data[8..16].copy_from_slice(&1000u64.to_le_bytes());

        // Parent reference: MFT entry 5 (root)
        data[16..24].copy_from_slice(&5u64.to_le_bytes());

        // Reason: FILE_DELETE
        data[40..44].copy_from_slice(&USN_REASON_FILE_DELETE.to_le_bytes());

        // Filename length: 10 bytes (5 UTF-16 chars)
        data[56..58].copy_from_slice(&10u16.to_le_bytes());

        // Filename offset: 60
        data[58..60].copy_from_slice(&60u16.to_le_bytes());

        // Filename: "test.txt" in UTF-16 LE
        let filename_utf16: Vec<u16> = "test".encode_utf16().collect();
        for (i, &c) in filename_utf16.iter().enumerate() {
            data[60 + i * 2..60 + i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }

        let record = UsnJournalParser::parse_usn_record_v2(&data).unwrap();

        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.major_version, 2);
        assert!(record.is_deletion());
        assert_eq!(record.mft_record_number(), 1000);
        assert_eq!(record.parent_mft_record_number(), 5);
    }
}