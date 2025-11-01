use crate::scanner::{DeletedFile, disk_access::DiskHandle, file_carving::{FileCarver, FileSignature}};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct FileRecovery {
    source_drive: char,
}

impl FileRecovery {
    pub fn new(source_drive: char) -> Self {
        Self { source_drive }
    }

    pub fn recover_file(
        &self,
        deleted_file: &DeletedFile,
        destination_path: &Path,
        progress_callback: std::sync::Arc<std::sync::Mutex<String>>,
    ) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write as IoWrite;

        // Create recovery log
        let log_path = std::env::var("USERPROFILE")
            .map(|base| format!("{}\\Desktop\\recovery_debug.log", base))
            .unwrap_or_else(|_| "C:\\recovery_debug.log".to_string());

        let mut log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "\n=== Recovery Attempt ===");
            let _ = writeln!(log, "File: {}", deleted_file.name);
            let _ = writeln!(log, "Path: {}", deleted_file.path);
            let _ = writeln!(log, "Size: {} bytes", deleted_file.size);
            let _ = writeln!(log, "Filesystem: {}", deleted_file.filesystem_type);
            let _ = writeln!(log, "First cluster: {}", deleted_file.clusters.get(0).unwrap_or(&0));
            let _ = log.flush();
        }

        // Validate that destination is on a different drive
        let dest_drive = self.get_drive_letter(destination_path)?;
        if dest_drive.to_uppercase().chars().next() == Some(self.source_drive.to_uppercase().next().unwrap()) {
            anyhow::bail!("Destination must be on a different drive than the source");
        }

        // Open the source disk
        let disk = DiskHandle::open(self.source_drive)
            .context("Failed to open source disk for recovery")?;

        // Check if we have cluster information (either clusters or cluster_ranges)
        if deleted_file.clusters.is_empty() && deleted_file.cluster_ranges.is_empty() {
            anyhow::bail!("Cannot recover this file - cluster information not available");
        }

        // Create output file
        let mut output_file = File::create(destination_path)
            .context("Failed to create destination file")?;

        // Read filesystem-specific boot sector to get cluster size
        let (sectors_per_cluster, cluster_heap_offset) = if deleted_file.filesystem_type == "exFAT" {
            self.read_exfat_boot_info(&disk)?
        } else {
            // NTFS
            self.read_ntfs_boot_info(&disk)?
        };

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "Sectors per cluster: {}", sectors_per_cluster);
            let _ = writeln!(log, "Cluster heap offset: {}", cluster_heap_offset);
            let _ = log.flush();
        }

        let sector_size = disk.get_sector_size()?;
        let mut total_written = 0u64;
        let mut corrected_clusters = deleted_file.clusters.clone();

        // For exFAT, try to detect and fix corrupted cluster numbers using file carving
        if deleted_file.filesystem_type == "exFAT" && !corrected_clusters.is_empty() {
            let first_cluster = corrected_clusters[0];

            // Read first cluster to check if it has valid file signature
            if first_cluster >= 2 {
                let sector = cluster_heap_offset + ((first_cluster - 2) * sectors_per_cluster);

                if let Ok(data) = disk.read_sectors(sector, sectors_per_cluster, sector_size) {
                    // Determine expected signature based on file extension
                    let filename_lower = deleted_file.name.to_lowercase();
                    let expected_sig = if filename_lower.ends_with(".mkv") {
                        Some(&FileSignature::MKV)
                    } else if filename_lower.ends_with(".webm") {
                        Some(&FileSignature::WEBM)
                    } else if filename_lower.ends_with(".mp4") {
                        Some(&FileSignature::MP4)
                    } else if filename_lower.ends_with(".avi") {
                        Some(&FileSignature::AVI)
                    } else if filename_lower.ends_with(".flv") {
                        Some(&FileSignature::FLV)
                    } else if filename_lower.ends_with(".3gp") {
                        Some(&FileSignature::THREE_GP)
                    } else if filename_lower.ends_with(".mov") {
                        Some(&FileSignature::MOV)
                    } else if filename_lower.ends_with(".wmv") {
                        Some(&FileSignature::WMV)
                    } else if filename_lower.ends_with(".zip") {
                        Some(&FileSignature::ZIP)
                    } else if filename_lower.ends_with(".rar") {
                        Some(&FileSignature::RAR)
                    } else if filename_lower.ends_with(".7z") {
                        Some(&FileSignature::SEVEN_ZIP)
                    } else if filename_lower.ends_with(".tar.gz") || filename_lower.ends_with(".tgz") {
                        Some(&FileSignature::TAR_GZ)
                    } else if filename_lower.ends_with(".pdf") {
                        Some(&FileSignature::PDF)
                    } else if filename_lower.ends_with(".docx") {
                        Some(&FileSignature::DOCX)
                    } else if filename_lower.ends_with(".xlsx") {
                        Some(&FileSignature::XLSX)
                    } else if filename_lower.ends_with(".pptx") {
                        Some(&FileSignature::PPTX)
                    } else if filename_lower.ends_with(".doc") {
                        Some(&FileSignature::DOC)
                    } else if filename_lower.ends_with(".xls") {
                        Some(&FileSignature::XLS)
                    } else if filename_lower.ends_with(".ppt") {
                        Some(&FileSignature::PPT)
                    } else if filename_lower.ends_with(".odt") {
                        Some(&FileSignature::ODT)
                    } else if filename_lower.ends_with(".ods") {
                        Some(&FileSignature::ODS)
                    } else if filename_lower.ends_with(".odp") {
                        Some(&FileSignature::ODP)
                    } else if filename_lower.ends_with(".png") {
                        Some(&FileSignature::PNG)
                    } else if filename_lower.ends_with(".jpg") || filename_lower.ends_with(".jpeg") {
                        Some(&FileSignature::JPEG)
                    } else if filename_lower.ends_with(".bmp") {
                        Some(&FileSignature::BMP)
                    } else if filename_lower.ends_with(".gif") {
                        Some(&FileSignature::GIF)
                    } else if filename_lower.ends_with(".webp") {
                        Some(&FileSignature::WEBP)
                    } else if filename_lower.ends_with(".tiff") || filename_lower.ends_with(".tif") {
                        Some(&FileSignature::TIFF)
                    } else if filename_lower.ends_with(".mp3") {
                        Some(&FileSignature::MP3)
                    } else if filename_lower.ends_with(".wav") {
                        Some(&FileSignature::WAV)
                    } else if filename_lower.ends_with(".flac") {
                        Some(&FileSignature::FLAC)
                    } else if filename_lower.ends_with(".m4a") {
                        Some(&FileSignature::M4A)
                    } else if filename_lower.ends_with(".safetensors") {
                        Some(&FileSignature::SAFETENSORS)
                    } else if filename_lower.ends_with(".onnx") {
                        Some(&FileSignature::ONNX)
                    } else if filename_lower.ends_with(".exe") {
                        Some(&FileSignature::EXE)
                    } else if filename_lower.ends_with(".dll") {
                        Some(&FileSignature::DLL)
                    } else if filename_lower.ends_with(".sqlite") || filename_lower.ends_with(".db") {
                        Some(&FileSignature::SQLITE)
                    } else if filename_lower.ends_with(".iso") {
                        Some(&FileSignature::ISO)
                    } else if filename_lower.ends_with(".vmdk") {
                        Some(&FileSignature::VMDK)
                    } else if filename_lower.ends_with(".torrent") {
                        Some(&FileSignature::TORRENT)
                    } else {
                        None
                    };

                    if let Some(sig) = expected_sig {
                        // Check if first bytes match expected signature
                        let signature_matches = if data.len() >= sig.signature.len() {
                            &data[0..sig.signature.len()] == sig.signature
                        } else {
                            false
                        };

                        if !signature_matches {
                            if let Some(ref mut log) = log_file {
                                let preview: Vec<String> = data.iter().take(16)
                                    .map(|b| format!("{:02X}", b))
                                    .collect();
                                let _ = writeln!(log, "\n⚠️  CLUSTER CORRUPTION DETECTED!");
                                let _ = writeln!(log, "Expected {} signature: {:02X?}", sig.description, sig.signature);
                                let _ = writeln!(log, "Actually read: {}", preview.join(" "));
                                let _ = writeln!(log, "\nAttempting FILE CARVING to find correct cluster...");
                                let _ = log.flush();
                            }

                            // Try file carving to find the correct cluster
                            let carver = FileCarver::new(self.source_drive);

                            // First try searching within ±100,000 clusters (~12.8GB radius for 128KB clusters)
                            *progress_callback.lock().unwrap() = "⚠️ Cluster corruption detected! Starting quick nearby search (~25GB)...".to_string();

                            if let Some(ref mut log) = log_file {
                                let _ = writeln!(log, "\nStep 1: Trying quick nearby search (±100,000 clusters)...");
                                let _ = log.flush();
                            }

                            if let Some(correct_cluster) = carver.search_nearby_clusters(
                                &disk,
                                first_cluster,
                                sectors_per_cluster,
                                cluster_heap_offset,
                                sector_size,
                                sig,
                                100000,
                                &mut log_file,
                                Some(progress_callback.clone()),
                            ) {
                                if let Some(ref mut log) = log_file {
                                    let _ = writeln!(log, "\n✅ FILE CARVING SUCCESS!");
                                    let _ = writeln!(log, "Found correct cluster: {} (was: {})", correct_cluster, first_cluster);
                                    let _ = writeln!(log, "Offset: {} clusters", (correct_cluster as i64 - first_cluster as i64).abs());
                                    let _ = log.flush();
                                }
                                corrected_clusters[0] = correct_cluster;
                            } else {
                                // Quick search failed, try full disk carving
                                *progress_callback.lock().unwrap() = "⚠️ Quick search failed. Starting FULL DISK CARVING (may take 30-60 min for 2TB)...".to_string();

                                if let Some(ref mut log) = log_file {
                                    let _ = writeln!(log, "\n⚠️  Quick search failed.");
                                    let _ = writeln!(log, "Step 2: Starting FULL DISK CARVING...");
                                    let _ = writeln!(log, "This will scan the ENTIRE drive for the file signature.");
                                    let _ = writeln!(log, "This may take 30-60 minutes for a 2TB drive.");
                                    let _ = log.flush();
                                }

                                if let Some(correct_cluster) = carver.search_full_disk(
                                    &disk,
                                    sectors_per_cluster,
                                    cluster_heap_offset,
                                    sector_size,
                                    sig,
                                    &mut log_file,
                                    Some(progress_callback.clone()),
                                ) {
                                    if let Some(ref mut log) = log_file {
                                        let _ = writeln!(log, "\n✅ FULL DISK CARVING SUCCESS!");
                                        let _ = writeln!(log, "Found correct cluster: {} (was: {})", correct_cluster, first_cluster);
                                        let _ = writeln!(log, "Offset: {} clusters", (correct_cluster as i64 - first_cluster as i64).abs());
                                        let _ = log.flush();
                                    }
                                    corrected_clusters[0] = correct_cluster;
                                } else {
                                    if let Some(ref mut log) = log_file {
                                        let _ = writeln!(log, "\n❌ FULL DISK CARVING FAILED");
                                        let _ = writeln!(log, "Could not find {} signature anywhere on the disk", sig.description);
                                        let _ = writeln!(log, "The file data has likely been completely overwritten");
                                        let _ = log.flush();
                                    }
                                }
                            }
                        } else {
                            if let Some(ref mut log) = log_file {
                                let _ = writeln!(log, "\n✅ Cluster signature verified: {} detected", sig.description);
                                let _ = log.flush();
                            }
                        }
                    }
                }
            }
        }

        // Process clusters based on filesystem type
        if deleted_file.filesystem_type == "NTFS" && !deleted_file.cluster_ranges.is_empty() {
            // NTFS: Process cluster ranges directly (memory efficient)
            if let Some(ref mut log) = log_file {
                let _ = writeln!(log, "\n=== NTFS Recovery Details ===");
                let _ = writeln!(log, "Total cluster ranges: {}", deleted_file.cluster_ranges.len());
                let _ = writeln!(log, "Sectors per cluster: {}", sectors_per_cluster);
                let _ = writeln!(log, "Sector size: {}", sector_size);
                let _ = log.flush();
            }

            for (range_idx, range) in deleted_file.cluster_ranges.iter().enumerate() {
                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "\nRange #{}: LCN {} - {} ({} clusters)",
                        range_idx, range.start, range.start + range.count - 1, range.count);
                    let _ = log.flush();
                }

                for i in 0..range.count {
                    if total_written >= deleted_file.size {
                        break;
                    }

                    let cluster = range.start + i;
                    let sector = cluster * sectors_per_cluster;

                    // Log first cluster of each range with detailed info
                    if i == 0 {
                        if let Some(ref mut log) = log_file {
                            let _ = writeln!(log, "  Cluster {} (LCN) -> Sector {} ({} sectors)",
                                cluster, sector, sectors_per_cluster);
                            let _ = writeln!(log, "  Byte offset: {}", sector * sector_size);
                            let _ = log.flush();
                        }
                    }

                    match disk.read_sectors(sector, sectors_per_cluster, sector_size) {
                        Ok(data) => {
                            // Log first cluster's data
                            if i == 0 {
                                if let Some(ref mut log) = log_file {
                                    let _ = writeln!(log, "  Read {} bytes from sector {}", data.len(), sector);
                                    let preview: Vec<String> = data.iter().take(16)
                                        .map(|b| format!("{:02X}", b))
                                        .collect();
                                    let _ = writeln!(log, "  First 16 bytes: {}", preview.join(" "));
                                    let _ = log.flush();
                                }
                            }

                            let bytes_to_write = (deleted_file.size - total_written).min(data.len() as u64) as usize;
                            output_file.write_all(&data[..bytes_to_write])
                                .context("Failed to write recovered data")?;
                            total_written += bytes_to_write as u64;

                            if i == 0 {
                                if let Some(ref mut log) = log_file {
                                    let _ = writeln!(log, "  Wrote {} bytes, total so far: {} / {}",
                                        bytes_to_write, total_written, deleted_file.size);
                                    let _ = log.flush();
                                }
                            }
                        }
                        Err(e) => {
                            if let Some(ref mut log) = log_file {
                                let _ = writeln!(log, "  ERROR reading cluster {} (sector {}): {}", cluster, sector, e);
                                let _ = log.flush();
                            }
                            eprintln!("Warning: Failed to read cluster {}: {}", cluster, e);
                        }
                    }
                }
            }
        } else {
            // exFAT: Process individual clusters from list
            for &cluster in &corrected_clusters {
                if total_written >= deleted_file.size {
                    break;
                }

                // Convert cluster to sector for exFAT
                if cluster < 2 {
                    if let Some(ref mut log) = log_file {
                        let _ = writeln!(log, "ERROR: Invalid cluster number {}", cluster);
                        let _ = log.flush();
                    }
                    eprintln!("Warning: Invalid cluster number {}", cluster);
                    continue;
                }
                let sector = cluster_heap_offset + ((cluster - 2) * sectors_per_cluster);

                if let Some(ref mut log) = log_file {
                    let _ = writeln!(log, "Reading cluster {} -> sector {} ({} sectors)",
                        cluster, sector, sectors_per_cluster);
                    let _ = log.flush();
                }

                match disk.read_sectors(sector, sectors_per_cluster, sector_size) {
                    Ok(data) => {
                        if let Some(ref mut log) = log_file {
                            let _ = writeln!(log, "Read {} bytes from sector {}", data.len(), sector);
                            // Log first 16 bytes as hex
                            let preview: Vec<String> = data.iter().take(16)
                                .map(|b| format!("{:02X}", b))
                                .collect();
                            let _ = writeln!(log, "First 16 bytes: {}", preview.join(" "));
                            let _ = log.flush();
                        }

                        let bytes_to_write = (deleted_file.size - total_written).min(data.len() as u64) as usize;
                        output_file.write_all(&data[..bytes_to_write])
                            .context("Failed to write recovered data")?;
                        total_written += bytes_to_write as u64;

                        if let Some(ref mut log) = log_file {
                            let _ = writeln!(log, "Wrote {} bytes, total: {}", bytes_to_write, total_written);
                            let _ = log.flush();
                        }
                    }
                    Err(e) => {
                        if let Some(ref mut log) = log_file {
                            let _ = writeln!(log, "ERROR reading cluster {}: {}", cluster, e);
                            let _ = log.flush();
                        }
                        eprintln!("Warning: Failed to read cluster {}: {}", cluster, e);
                        // Continue with next cluster
                    }
                }
            }
        }

        if let Some(ref mut log) = log_file {
            let _ = writeln!(log, "Recovery complete: {} bytes written", total_written);
            let _ = writeln!(log, "Destination: {}", destination_path.display());
            let _ = log.flush();
        }

        Ok(())
    }

    fn read_exfat_boot_info(&self, disk: &DiskHandle) -> Result<(u64, u64)> {
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
        ]) as u64;

        let sectors_per_cluster = 1u64 << sectors_per_cluster_shift;

        Ok((sectors_per_cluster, cluster_heap_offset))
    }

    fn read_ntfs_boot_info(&self, disk: &DiskHandle) -> Result<(u64, u64)> {
        let sector_size = disk.get_sector_size()?;
        let boot_data = disk.read_sectors(0, 1, sector_size)?;

        if boot_data.len() < 512 {
            anyhow::bail!("Boot sector too small");
        }

        // Verify NTFS signature
        if &boot_data[3..11] != b"NTFS    " {
            anyhow::bail!("Not an NTFS filesystem");
        }

        let sectors_per_cluster = boot_data[13] as u64;

        // For NTFS, we don't have a cluster heap offset like exFAT
        // Return 0 as the offset (clusters are absolute sector positions in simplified mode)
        Ok((sectors_per_cluster, 0))
    }

    fn get_drive_letter(&self, path: &Path) -> Result<String> {
        let path_str = path.to_string_lossy();

        if path_str.len() >= 2 && path_str.chars().nth(1) == Some(':') {
            Ok(path_str.chars().next().unwrap().to_string())
        } else {
            anyhow::bail!("Cannot determine drive letter from path")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_drive_letter() {
        let recovery = FileRecovery::new('C');

        let path = Path::new("D:\\test\\file.txt");
        assert_eq!(recovery.get_drive_letter(path).unwrap(), "D");

        let path = Path::new("E:\\file.txt");
        assert_eq!(recovery.get_drive_letter(path).unwrap(), "E");
    }

    #[test]
    fn test_same_drive_validation() {
        use std::sync::{Arc, Mutex};

        let recovery = FileRecovery::new('C');
        let deleted_file = DeletedFile {
            name: "test.txt".to_string(),
            path: "C:\\".to_string(),
            size: 1024,
            deleted_time: None,
            file_record: 0,
            clusters: vec![100],
            is_recoverable: true,
            filesystem_type: "NTFS".to_string(),
        };

        let dest = Path::new("C:\\recovered\\test.txt");
        let progress = Arc::new(Mutex::new(String::new()));
        let result = recovery.recover_file(&deleted_file, dest, progress);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("different drive"));
    }
}
