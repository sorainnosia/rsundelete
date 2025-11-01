use super::{DeletedFile, FileSystemScanner};
use super::disk_access::DiskHandle;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

const MFT_RECORD_SIZE: usize = 1024;
const FILE_RECORD_SEGMENT_IN_USE: u16 = 0x0001;

pub struct NtfsScanner {
    drive_letter: char,
}

impl NtfsScanner {
    pub fn new(drive_letter: char) -> Self {
        Self { drive_letter }
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

        Ok(NtfsBootSector {
            bytes_per_sector: u16::from_le_bytes([boot_data[11], boot_data[12]]),
            sectors_per_cluster: boot_data[13],
            mft_cluster: u64::from_le_bytes([
                boot_data[48], boot_data[49], boot_data[50], boot_data[51],
                boot_data[52], boot_data[53], boot_data[54], boot_data[55],
            ]),
            clusters_per_mft_record: boot_data[64] as i8,
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

        // Extract just the MFT record portion
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

        // We want deleted files, so skip files that are in use
        if is_in_use {
            return Ok(None);
        }

        let first_attr_offset = u16::from_le_bytes([record_data[20], record_data[21]]) as usize;

        Ok(Some(MftRecord {
            flags,
            first_attr_offset,
            data: record_data.to_vec(),
        }))
    }

    fn extract_file_info(&self, record: &MftRecord, record_num: u64) -> Result<Option<DeletedFile>> {
        let mut offset = record.first_attr_offset;
        let mut filename = String::new();
        let mut size = 0u64;
        let mut clusters = Vec::new();

        while offset + 16 < record.data.len() {
            let attr_type = u32::from_le_bytes([
                record.data[offset],
                record.data[offset + 1],
                record.data[offset + 2],
                record.data[offset + 3],
            ]);

            // End marker
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
                    if let Some(name) = self.parse_filename_attribute(&record.data[offset..offset + attr_length]) {
                        if !name.starts_with('.') && name.len() > filename.len() {
                            filename = name;
                        }
                    }
                }
                0x80 => {
                    // DATA attribute
                    if let Some((file_size, data_clusters)) = self.parse_data_attribute(&record.data[offset..offset + attr_length]) {
                        size = file_size;
                        clusters = data_clusters;
                    }
                }
                _ => {}
            }

            offset += attr_length;
        }

        if filename.is_empty() {
            return Ok(None);
        }

        let is_recoverable = !clusters.is_empty();
        Ok(Some(DeletedFile {
            name: filename,
            path: format!("{}:\\", self.drive_letter),
            size,
            deleted_time: None,
            file_record: record_num,
            clusters,
            is_recoverable,
        }))
    }

    fn parse_filename_attribute(&self, attr_data: &[u8]) -> Option<String> {
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

        Some(String::from_utf16_lossy(&name_u16))
    }

    fn parse_data_attribute(&self, attr_data: &[u8]) -> Option<(u64, Vec<u64>)> {
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
            return Some((content_size, Vec::new()));
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

            // For simplicity, we'll return empty clusters for non-resident data
            // In a full implementation, you'd parse the run list here
            return Some((file_size, Vec::new()));
        }
    }
}

impl FileSystemScanner for NtfsScanner {
    fn scan(
        &mut self,
        drive_letter: char,
        folder_path: Option<&str>,
        filename_filter: Option<&str>,
    ) -> Result<Vec<DeletedFile>> {
        self.drive_letter = drive_letter;
        let disk = DiskHandle::open(drive_letter)
            .context("Failed to open disk for NTFS scanning")?;

        let boot_sector = self.read_boot_sector(&disk)
            .context("Failed to read NTFS boot sector")?;

        let mut deleted_files = Vec::new();

        // Scan first 10000 MFT records (adjust as needed)
        for record_num in 0..10000 {
            match self.read_mft_record(&disk, &boot_sector, record_num) {
                Ok(record_data) => {
                    if let Ok(Some(record)) = self.parse_mft_record(&record_data) {
                        if let Ok(Some(file_info)) = self.extract_file_info(&record, record_num) {
                            // Apply filters
                            let mut include = true;

                            if let Some(filter) = filename_filter {
                                if !filter.is_empty() && !file_info.name.to_lowercase().contains(&filter.to_lowercase()) {
                                    include = false;
                                }
                            }

                            if let Some(path_filter) = folder_path {
                                if !path_filter.is_empty() && !file_info.path.to_lowercase().contains(&path_filter.to_lowercase()) {
                                    include = false;
                                }
                            }

                            if include {
                                deleted_files.push(file_info);
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(deleted_files)
    }

    fn get_filesystem_type(&self) -> &str {
        "NTFS"
    }
}

#[derive(Debug)]
struct NtfsBootSector {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    mft_cluster: u64,
    clusters_per_mft_record: i8,
}

#[derive(Debug)]
struct MftRecord {
    flags: u16,
    first_attr_offset: usize,
    data: Vec<u8>,
}
