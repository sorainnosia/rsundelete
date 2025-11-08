use super::disk_access::DiskHandle;
use anyhow::Result;
use std::fs::OpenOptions;
use std::io::Write;

/// File signatures for common file types
#[derive(Debug, Clone)]
pub struct FileSignature {
    pub extension: &'static str,
    pub signature: &'static [u8],
    pub description: &'static str,
}

impl FileSignature {
    pub const MKV: FileSignature = FileSignature {
        extension: "mkv",
        signature: &[0x1A, 0x45, 0xDF, 0xA3], // EBML header
        description: "Matroska/MKV video",
    };

    pub const MP4: FileSignature = FileSignature {
        extension: "mp4",
        signature: &[0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], // ftyp
        description: "MP4 video",
    };

    pub const AVI: FileSignature = FileSignature {
        extension: "avi",
        signature: &[0x52, 0x49, 0x46, 0x46], // RIFF
        description: "AVI video",
    };

    pub const ZIP: FileSignature = FileSignature {
        extension: "zip",
        signature: &[0x50, 0x4B, 0x03, 0x04], // PK
        description: "ZIP archive",
    };

    pub const PDF: FileSignature = FileSignature {
        extension: "pdf",
        signature: &[0x25, 0x50, 0x44, 0x46], // %PDF
        description: "PDF document",
    };

    pub const PNG: FileSignature = FileSignature {
        extension: "png",
        signature: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        description: "PNG image",
    };

    pub const JPEG: FileSignature = FileSignature {
        extension: "jpg",
        signature: &[0xFF, 0xD8, 0xFF],
        description: "JPEG image",
    };

    // Microsoft Office documents (ZIP-based formats)
    pub const DOCX: FileSignature = FileSignature {
        extension: "docx",
        signature: &[0x50, 0x4B, 0x03, 0x04], // PK (ZIP format)
        description: "Microsoft Word document (DOCX)",
    };

    pub const XLSX: FileSignature = FileSignature {
        extension: "xlsx",
        signature: &[0x50, 0x4B, 0x03, 0x04], // PK (ZIP format)
        description: "Microsoft Excel spreadsheet (XLSX)",
    };

    pub const PPTX: FileSignature = FileSignature {
        extension: "pptx",
        signature: &[0x50, 0x4B, 0x03, 0x04], // PK (ZIP format)
        description: "Microsoft PowerPoint presentation (PPTX)",
    };

    // Legacy Microsoft Office documents
    pub const DOC: FileSignature = FileSignature {
        extension: "doc",
        signature: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], // OLE2 header
        description: "Microsoft Word document (DOC)",
    };

    pub const XLS: FileSignature = FileSignature {
        extension: "xls",
        signature: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], // OLE2 header
        description: "Microsoft Excel spreadsheet (XLS)",
    };

    pub const PPT: FileSignature = FileSignature {
        extension: "ppt",
        signature: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], // OLE2 header
        description: "Microsoft PowerPoint presentation (PPT)",
    };

    // LibreOffice/OpenOffice documents (ZIP-based)
    pub const ODT: FileSignature = FileSignature {
        extension: "odt",
        signature: &[0x50, 0x4B, 0x03, 0x04], // PK (ZIP format)
        description: "OpenDocument text (ODT)",
    };

    pub const ODS: FileSignature = FileSignature {
        extension: "ods",
        signature: &[0x50, 0x4B, 0x03, 0x04], // PK (ZIP format)
        description: "OpenDocument spreadsheet (ODS)",
    };

    pub const ODP: FileSignature = FileSignature {
        extension: "odp",
        signature: &[0x50, 0x4B, 0x03, 0x04], // PK (ZIP format)
        description: "OpenDocument presentation (ODP)",
    };

    // Additional image formats
    pub const BMP: FileSignature = FileSignature {
        extension: "bmp",
        signature: &[0x42, 0x4D], // BM
        description: "Bitmap image (BMP)",
    };

    pub const GIF: FileSignature = FileSignature {
        extension: "gif",
        signature: &[0x47, 0x49, 0x46, 0x38], // GIF8
        description: "GIF image",
    };

    pub const WEBP: FileSignature = FileSignature {
        extension: "webp",
        signature: &[0x52, 0x49, 0x46, 0x46], // RIFF (check offset 8 for WEBP)
        description: "WebP image",
    };

    pub const TIFF: FileSignature = FileSignature {
        extension: "tiff",
        signature: &[0x49, 0x49, 0x2A, 0x00], // II*\0 (little-endian)
        description: "TIFF image",
    };

    // Video formats
    pub const FLV: FileSignature = FileSignature {
        extension: "flv",
        signature: &[0x46, 0x4C, 0x56, 0x01], // FLV\x01
        description: "Flash video (FLV)",
    };

    pub const THREE_GP: FileSignature = FileSignature {
        extension: "3gp",
        signature: &[0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70], // ftyp
        description: "3GP video",
    };

    pub const MOV: FileSignature = FileSignature {
        extension: "mov",
        signature: &[0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70], // ftyp
        description: "QuickTime movie (MOV)",
    };

    pub const WMV: FileSignature = FileSignature {
        extension: "wmv",
        signature: &[0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11], // ASF header
        description: "Windows Media Video (WMV)",
    };

    pub const WEBM: FileSignature = FileSignature {
        extension: "webm",
        signature: &[0x1A, 0x45, 0xDF, 0xA3], // EBML header (same as MKV)
        description: "WebM video",
    };

    // Audio formats
    pub const MP3: FileSignature = FileSignature {
        extension: "mp3",
        signature: &[0xFF, 0xFB], // MPEG-1 Layer 3
        description: "MP3 audio",
    };

    pub const WAV: FileSignature = FileSignature {
        extension: "wav",
        signature: &[0x52, 0x49, 0x46, 0x46], // RIFF
        description: "WAV audio",
    };

    pub const FLAC: FileSignature = FileSignature {
        extension: "flac",
        signature: &[0x66, 0x4C, 0x61, 0x43], // fLaC
        description: "FLAC audio",
    };

    pub const M4A: FileSignature = FileSignature {
        extension: "m4a",
        signature: &[0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70], // ftyp
        description: "M4A audio",
    };

    // Machine learning models
    pub const SAFETENSORS: FileSignature = FileSignature {
        extension: "safetensors",
        signature: &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 8 bytes length header
        description: "SafeTensors model",
    };

    pub const ONNX: FileSignature = FileSignature {
        extension: "onnx",
        signature: &[0x08], // Protobuf format
        description: "ONNX model",
    };

    // Executables
    pub const EXE: FileSignature = FileSignature {
        extension: "exe",
        signature: &[0x4D, 0x5A], // MZ
        description: "Windows executable (EXE)",
    };

    pub const DLL: FileSignature = FileSignature {
        extension: "dll",
        signature: &[0x4D, 0x5A], // MZ
        description: "Windows library (DLL)",
    };

    // Archives
    pub const RAR: FileSignature = FileSignature {
        extension: "rar",
        signature: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], // Rar!\x1A\x07
        description: "RAR archive",
    };

    pub const SEVEN_ZIP: FileSignature = FileSignature {
        extension: "7z",
        signature: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], // 7z¼¯'\x1C
        description: "7-Zip archive",
    };

    pub const TAR_GZ: FileSignature = FileSignature {
        extension: "tar.gz",
        signature: &[0x1F, 0x8B, 0x08], // GZIP
        description: "Gzipped TAR archive",
    };

    // Database files
    pub const SQLITE: FileSignature = FileSignature {
        extension: "sqlite",
        signature: &[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66], // SQLite format 3
        description: "SQLite database",
    };

    // Disk images
    pub const ISO: FileSignature = FileSignature {
        extension: "iso",
        signature: &[0x43, 0x44, 0x30, 0x30, 0x31], // CD001 (at offset 0x8001)
        description: "ISO disk image",
    };

    pub const VMDK: FileSignature = FileSignature {
        extension: "vmdk",
        signature: &[0x4B, 0x44, 0x4D], // KDM
        description: "VMware disk image",
    };

    // Other popular formats
    pub const TORRENT: FileSignature = FileSignature {
        extension: "torrent",
        signature: &[0x64, 0x38, 0x3A, 0x61, 0x6E, 0x6E, 0x6F, 0x75], // d8:announce
        description: "BitTorrent file",
    };
}

pub struct FileCarver {
    drive_letter: char,
}

impl FileCarver {
    pub fn new(drive_letter: char) -> Self {
        Self { drive_letter }
    }

    /// Scan a specific cluster for file signatures
    pub fn scan_cluster_for_signature(
        &self,
        disk: &DiskHandle,
        cluster: u64,
        sectors_per_cluster: u64,
        cluster_heap_offset: u64,
        sector_size: u64,
        signatures: &[FileSignature],
        log_file: &mut Option<std::fs::File>,
    ) -> Option<(FileSignature, u64)> {
        // Calculate sector for this cluster
        if cluster < 2 {
            return None;
        }

        let sector = cluster_heap_offset + ((cluster - 2) * sectors_per_cluster);

        // Read the cluster
        match disk.read_sectors(sector, sectors_per_cluster, sector_size) {
            Ok(data) => {
                // Check each signature
                for sig in signatures {
                    if data.len() >= sig.signature.len() {
                        if &data[0..sig.signature.len()] == sig.signature {
                            if let Some(ref mut log) = log_file {
                                let _ = writeln!(
                                    log,
                                    "FILE CARVING: Found {} signature at cluster {} (sector {})",
                                    sig.description, cluster, sector
                                );
                                let _ = log.flush();
                            }
                            return Some((sig.clone(), cluster));
                        }
                    }
                }
                None
            }
            Err(_) => None,
        }
    }

    /// Scan a range of clusters looking for file signatures
    /// Returns: Vec<(cluster_number, signature)>
    pub fn carve_clusters(
        &self,
        disk: &DiskHandle,
        start_cluster: u64,
        end_cluster: u64,
        sectors_per_cluster: u64,
        cluster_heap_offset: u64,
        sector_size: u64,
        target_signatures: &[FileSignature],
        log_file: &mut Option<std::fs::File>,
        max_results: usize,
    ) -> Vec<(u64, FileSignature)> {
        let mut results = Vec::new();

        if let Some(ref mut log) = log_file {
            let _ = writeln!(
                log,
                "\n=== FILE CARVING: Scanning clusters {} to {} ===",
                start_cluster, end_cluster
            );
            let _ = writeln!(log, "Looking for signatures:");
            for sig in target_signatures {
                let _ = writeln!(log, "  - {} (.{})", sig.description, sig.extension);
            }
            let _ = log.flush();
        }

        for cluster in start_cluster..=end_cluster {
            if results.len() >= max_results {
                break;
            }

            // Progress update every 1000 clusters
            if cluster % 1000 == 0 {
                if let Some(ref mut log) = log_file {
                    let progress = ((cluster - start_cluster) as f64
                        / (end_cluster - start_cluster) as f64)
                        * 100.0;
                    let _ = writeln!(
                        log,
                        "FILE CARVING: Progress {:.1}% (cluster {})",
                        progress, cluster
                    );
                    let _ = log.flush();
                }
            }

            if let Some((sig, cluster_num)) = self.scan_cluster_for_signature(
                disk,
                cluster,
                sectors_per_cluster,
                cluster_heap_offset,
                sector_size,
                target_signatures,
                log_file,
            ) {
                results.push((cluster_num, sig));
            }
        }

        if let Some(ref mut log) = log_file {
            let _ = writeln!(
                log,
                "\nFILE CARVING: Found {} file(s) with matching signatures",
                results.len()
            );
            let _ = log.flush();
        }

        results
    }

    /// Quick scan around a corrupted cluster to find the actual file
    /// Useful when directory entry has wrong cluster number
    pub fn search_nearby_clusters(
        &self,
        disk: &DiskHandle,
        corrupt_cluster: u64,
        sectors_per_cluster: u64,
        cluster_heap_offset: u64,
        sector_size: u64,
        signature: &FileSignature,
        search_radius: u64,
        log_file: &mut Option<std::fs::File>,
        progress_callback: Option<std::sync::Arc<std::sync::Mutex<String>>>,
    ) -> Option<u64> {
        if let Some(ref mut log) = log_file {
            let _ = writeln!(
                log,
                "\n=== Searching for {} near cluster {} (±{} clusters) ===",
                signature.description, corrupt_cluster, search_radius
            );
            let _ = log.flush();
        }

        let start = corrupt_cluster.saturating_sub(search_radius).max(2);
        let end = corrupt_cluster + search_radius;

        let total_clusters = end - start;
        let mut clusters_scanned = 0u64;

        for cluster in start..=end {
            // Progress update every 10,000 clusters for large scans
            if clusters_scanned % 10000 == 0 {
                let progress = (clusters_scanned as f64 / total_clusters as f64) * 100.0;

                if let Some(ref mut log) = log_file {
                    let _ = writeln!(
                        log,
                        "FILE CARVING: Progress {:.1}% ({}/{} clusters scanned)",
                        progress, clusters_scanned, total_clusters
                    );
                    let _ = log.flush();
                }

                if let Some(ref callback) = progress_callback {
                    *callback.lock().unwrap() = format!(
                        "🔍 Quick search: {:.1}% ({}/{} clusters)",
                        progress, clusters_scanned, total_clusters
                    );
                }
            }

            if let Some((_, found_cluster)) = self.scan_cluster_for_signature(
                disk,
                cluster,
                sectors_per_cluster,
                cluster_heap_offset,
                sector_size,
                &[signature.clone()],
                log_file,
            ) {
                return Some(found_cluster);
            }

            clusters_scanned += 1;
        }

        None
    }

    /// Parse file header to determine actual file size
    /// Returns the size in bytes if successfully parsed, None otherwise
    pub fn parse_file_size(
        &self,
        disk: &DiskHandle,
        cluster: u64,
        sectors_per_cluster: u64,
        cluster_heap_offset: u64,
        sector_size: u64,
        signature: &FileSignature,
        log_file: &mut Option<std::fs::File>,
    ) -> Option<u64> {
        let sector = cluster_heap_offset + ((cluster - 2) * sectors_per_cluster);

        // Read enough clusters to parse headers (read up to 256KB)
        let clusters_to_read = 64u64; // 256KB at 4KB per cluster
        match disk.read_sectors(sector, sectors_per_cluster * clusters_to_read, sector_size) {
            Ok(data) => {
                let size = match signature.extension {
                    "png" => parse_png_size(&data),
                    "jpg" => parse_jpeg_size(&data),
                    "gif" => parse_gif_size(&data),
                    "bmp" => parse_bmp_size(&data),
                    "pdf" => parse_pdf_size(&data),
                    "zip" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" => parse_zip_size(&data),
                    "mp4" | "mov" | "m4a" | "3gp" => parse_mp4_size(&data),
                    "avi" => parse_avi_size(&data),
                    "wav" => parse_wav_size(&data),
                    "doc" | "xls" | "ppt" => parse_ole2_size(&data),
                    "rar" => parse_rar_size(&data),
                    "7z" => parse_7z_size(&data),
                    _ => None,
                };

                if let Some(file_size) = size {
                    if let Some(ref mut log) = log_file {
                        let _ = writeln!(log, "Parsed {} file size: {} bytes ({} KB)",
                            signature.extension, file_size, file_size / 1024);
                        let _ = log.flush();
                    }
                }

                size
            }
            Err(_) => None,
        }
    }

    /// Full disk carving mode - searches entire drive for file signature
    /// Use this when the corrupted cluster is completely wrong
    pub fn search_full_disk(
        &self,
        disk: &DiskHandle,
        sectors_per_cluster: u64,
        cluster_heap_offset: u64,
        sector_size: u64,
        signature: &FileSignature,
        log_file: &mut Option<std::fs::File>,
        progress_callback: Option<std::sync::Arc<std::sync::Mutex<String>>>,
    ) -> Option<u64> {
        // Calculate total disk size and max cluster number
        if let Ok(disk_size) = disk.get_disk_size() {
            let cluster_size_bytes = sectors_per_cluster * sector_size;
            let max_clusters = (disk_size / cluster_size_bytes) as u64;

            if let Some(ref mut log) = log_file {
                let _ = writeln!(
                    log,
                    "\n=== FULL DISK CARVING MODE ==="
                );
                let _ = writeln!(
                    log,
                    "Searching for {} signature across ENTIRE disk",
                    signature.description
                );
                let _ = writeln!(
                    log,
                    "Disk size: {} GB ({} bytes)",
                    disk_size / 1_000_000_000, disk_size
                );
                let _ = writeln!(
                    log,
                    "Cluster size: {} KB ({} bytes)",
                    cluster_size_bytes / 1024, cluster_size_bytes
                );
                let _ = writeln!(
                    log,
                    "Total clusters to scan: {}",
                    max_clusters
                );
                let _ = writeln!(
                    log,
                    "This may take a while for large drives..."
                );
                let _ = log.flush();
            }

            // Start scanning from cluster 2 (first data cluster)
            for cluster in 2..=max_clusters {
                // Progress update every 10,000 clusters
                if (cluster - 2) % 10000 == 0 {
                    let progress = ((cluster - 2) as f64 / max_clusters as f64) * 100.0;
                    let gb_scanned = ((cluster - 2) * cluster_size_bytes) as f64 / 1_000_000_000.0;

                    if let Some(ref mut log) = log_file {
                        let _ = writeln!(
                            log,
                            "FULL DISK CARVING: Progress {:.2}% ({:.1} GB scanned, cluster {})",
                            progress, gb_scanned, cluster
                        );
                        let _ = log.flush();
                    }

                    if let Some(ref callback) = progress_callback {
                        *callback.lock().unwrap() = format!(
                            "💿 Full disk scan: {:.2}% ({:.1} GB / {:.1} GB scanned)",
                            progress, gb_scanned, disk_size as f64 / 1_000_000_000.0
                        );
                    }
                }

                if let Some((_, found_cluster)) = self.scan_cluster_for_signature(
                    disk,
                    cluster,
                    sectors_per_cluster,
                    cluster_heap_offset,
                    sector_size,
                    &[signature.clone()],
                    log_file,
                ) {
                    if let Some(ref mut log) = log_file {
                        let _ = writeln!(
                            log,
                            "\n✅ FULL DISK CARVING SUCCESS at cluster {}!",
                            found_cluster
                        );
                        let _ = log.flush();
                    }
                    return Some(found_cluster);
                }
            }

            if let Some(ref mut log) = log_file {
                let _ = writeln!(
                    log,
                    "\n❌ FULL DISK CARVING FAILED - No {} signature found on entire disk",
                    signature.description
                );
                let _ = log.flush();
            }
        } else {
            if let Some(ref mut log) = log_file {
                let _ = writeln!(log, "ERROR: Could not determine disk size");
                let _ = log.flush();
            }
        }

        None
    }
}

// ============================================================================
// File Format Parsing Functions
// ============================================================================

/// Parse PNG file size by finding IEND chunk
fn parse_png_size(data: &[u8]) -> Option<u64> {
    // PNG format: 8-byte signature + chunks
    // Each chunk: 4-byte length + 4-byte type + data + 4-byte CRC
    // Find IEND chunk which marks end of file

    if data.len() < 8 {
        return None;
    }

    // Verify PNG signature
    if &data[0..8] != &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return None;
    }

    let mut offset = 8;
    while offset + 12 <= data.len() {
        // Read chunk length (big-endian)
        let chunk_len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;

        // Read chunk type
        let chunk_type = &data[offset + 4..offset + 8];

        // Check if this is IEND chunk
        if chunk_type == b"IEND" {
            // IEND found, file ends at: offset + 8 (length+type) + chunk_len (data) + 4 (CRC)
            return Some((offset + 12 + chunk_len) as u64);
        }

        // Move to next chunk
        offset += 12 + chunk_len;
    }

    None
}

/// Parse JPEG file size by finding EOI marker (0xFFD9)
fn parse_jpeg_size(data: &[u8]) -> Option<u64> {
    // JPEG format: markers (0xFF followed by marker byte)
    // EOI (End Of Image) marker: 0xFFD9

    if data.len() < 3 {
        return None;
    }

    // Verify JPEG signature (0xFFD8FF)
    if data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
        return None;
    }

    // Search for EOI marker (0xFFD9)
    for i in 2..data.len() - 1 {
        if data[i] == 0xFF && data[i + 1] == 0xD9 {
            return Some((i + 2) as u64);
        }
    }

    None
}

/// Parse GIF file size
fn parse_gif_size(data: &[u8]) -> Option<u64> {
    // GIF format: signature + logical screen descriptor + color table + image data + trailer (0x3B)

    if data.len() < 6 {
        return None;
    }

    // Verify GIF signature (GIF87a or GIF89a)
    if &data[0..4] != b"GIF8" || (data[4] != b'7' && data[4] != b'9') || data[5] != b'a' {
        return None;
    }

    // Search for GIF trailer (0x3B)
    for i in 6..data.len() {
        if data[i] == 0x3B {
            return Some((i + 1) as u64);
        }
    }

    None
}

/// Parse BMP file size from header
fn parse_bmp_size(data: &[u8]) -> Option<u64> {
    // BMP format: 14-byte file header
    // Bytes 2-5: file size in little-endian

    if data.len() < 6 {
        return None;
    }

    // Verify BMP signature
    if data[0] != 0x42 || data[1] != 0x4D {
        return None;
    }

    // Read file size from header
    let size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as u64;

    if size > 0 && size < data.len() as u64 * 2 {
        Some(size)
    } else {
        None
    }
}

/// Parse PDF file size by finding %%EOF marker
fn parse_pdf_size(data: &[u8]) -> Option<u64> {
    // PDF format: ends with %%EOF marker

    if data.len() < 5 {
        return None;
    }

    // Verify PDF signature
    if &data[0..4] != b"%PDF" {
        return None;
    }

    // Search for %%EOF marker (scanning from end is more efficient)
    let search_bytes = b"%%EOF";
    for i in (0..data.len().saturating_sub(5)).rev() {
        if &data[i..i + 5] == search_bytes {
            // PDF ends shortly after %%EOF (usually with newline/whitespace)
            return Some((i + 5 + 2) as u64); // +2 for typical trailing newline
        }
    }

    None
}

/// Parse ZIP file size from central directory
fn parse_zip_size(data: &[u8]) -> Option<u64> {
    // ZIP format: ends with End of Central Directory (EOCD) record
    // EOCD signature: 0x06054b50

    if data.len() < 22 {
        return None;
    }

    // Verify ZIP signature
    if &data[0..4] != &[0x50, 0x4B, 0x03, 0x04] {
        return None;
    }

    // Search for EOCD signature from end (more efficient)
    for i in (0..data.len().saturating_sub(22)).rev() {
        if data.len() >= i + 4 && &data[i..i + 4] == &[0x50, 0x4B, 0x05, 0x06] {
            // Found EOCD, read comment length
            if data.len() >= i + 22 {
                let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as u64;
                return Some((i as u64) + 22 + comment_len);
            }
        }
    }

    None
}

/// Parse MP4/MOV file size from ftyp and mdat atoms
fn parse_mp4_size(data: &[u8]) -> Option<u64> {
    // MP4 format: series of atoms (boxes)
    // Each atom: 4-byte size + 4-byte type + data

    if data.len() < 8 {
        return None;
    }

    let mut offset = 0;
    let mut total_size = 0u64;

    while offset + 8 <= data.len() {
        // Read atom size (big-endian)
        let atom_size = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as u64;

        if atom_size == 0 {
            // Size 0 means atom extends to end of file
            break;
        }

        if atom_size == 1 {
            // Extended size in next 8 bytes
            if offset + 16 <= data.len() {
                let extended_size = u64::from_be_bytes([
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11],
                    data[offset + 12],
                    data[offset + 13],
                    data[offset + 14],
                    data[offset + 15],
                ]);
                total_size += extended_size;
                offset += extended_size as usize;
            } else {
                break;
            }
        } else {
            total_size += atom_size;
            offset += atom_size as usize;
        }

        // Check if we've read past our buffer - file is larger
        if offset > data.len() {
            return Some(total_size);
        }
    }

    if total_size > 0 {
        Some(total_size)
    } else {
        None
    }
}

/// Parse AVI file size from RIFF header
fn parse_avi_size(data: &[u8]) -> Option<u64> {
    // AVI format: RIFF header with file size
    // Bytes 0-3: "RIFF"
    // Bytes 4-7: file size - 8 (little-endian)
    // Bytes 8-11: "AVI "

    if data.len() < 12 {
        return None;
    }

    // Verify RIFF signature
    if &data[0..4] != b"RIFF" {
        return None;
    }

    // Verify AVI format
    if &data[8..12] != b"AVI " {
        return None;
    }

    // Read file size (add 8 for RIFF header)
    let size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64 + 8;

    if size > 0 {
        Some(size)
    } else {
        None
    }
}

/// Parse WAV file size from RIFF header
fn parse_wav_size(data: &[u8]) -> Option<u64> {
    // WAV format: RIFF header with file size
    // Bytes 0-3: "RIFF"
    // Bytes 4-7: file size - 8 (little-endian)
    // Bytes 8-11: "WAVE"

    if data.len() < 12 {
        return None;
    }

    // Verify RIFF signature
    if &data[0..4] != b"RIFF" {
        return None;
    }

    // Verify WAVE format
    if &data[8..12] != b"WAVE" {
        return None;
    }

    // Read file size (add 8 for RIFF header)
    let size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64 + 8;

    if size > 0 {
        Some(size)
    } else {
        None
    }
}

/// Parse OLE2 (legacy Office) file size
fn parse_ole2_size(data: &[u8]) -> Option<u64> {
    // OLE2 format: complex compound file format
    // For simplicity, we'll estimate based on sector allocation table
    // A proper implementation would parse the entire FAT chain

    if data.len() < 512 {
        return None;
    }

    // Verify OLE2 signature
    if &data[0..8] != &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return None;
    }

    // Read sector size (bytes 30-31, power of 2)
    let sector_shift = u16::from_le_bytes([data[30], data[31]]);
    let sector_size = 1u64 << sector_shift;

    // Read total sectors (bytes 44-47 for version 4)
    if data.len() >= 48 {
        let total_sectors = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as u64;
        if total_sectors > 0 {
            return Some(total_sectors * sector_size);
        }
    }

    None
}

/// Parse RAR archive size
fn parse_rar_size(data: &[u8]) -> Option<u64> {
    // RAR format is complex with multiple versions
    // For RAR 5.0+, we'd need to parse the archive structure
    // For now, we'll look for the terminator block

    if data.len() < 7 {
        return None;
    }

    // Verify RAR signature
    if &data[0..6] != &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] {
        return None;
    }

    // RAR parsing is complex - use estimation fallback
    None
}

/// Parse 7z archive size
fn parse_7z_size(data: &[u8]) -> Option<u64> {
    // 7z format: signature + version + CRC + ... + end header
    // Parsing 7z requires understanding the complex header structure

    if data.len() < 32 {
        return None;
    }

    // Verify 7z signature
    if &data[0..6] != &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return None;
    }

    // Read start header offset and size (bytes 12-19, 20-27)
    if data.len() >= 32 {
        let start_offset = u64::from_le_bytes([
            data[12], data[13], data[14], data[15],
            data[16], data[17], data[18], data[19],
        ]);
        let start_size = u64::from_le_bytes([
            data[20], data[21], data[22], data[23],
            data[24], data[25], data[26], data[27],
        ]);

        // Total size = 32-byte header + start offset + start size
        return Some(32 + start_offset + start_size);
    }

    None
}
