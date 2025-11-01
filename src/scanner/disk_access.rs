use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows::{
    core::PCWSTR,
    Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Win32::Storage::FileSystem::{
        CreateFileW, GetDiskFreeSpaceW, GetVolumeInformationW, FILE_FLAG_NO_BUFFERING,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    Win32::System::IO::DeviceIoControl,
    Win32::System::Ioctl::{IOCTL_DISK_GET_DRIVE_GEOMETRY, DISK_GEOMETRY},
};

pub struct DiskHandle {
    #[cfg(windows)]
    handle: HANDLE,
}

impl DiskHandle {
    #[cfg(windows)]
    pub fn open(drive_letter: char) -> Result<Self> {
        unsafe {
            let path = format!("\\\\.\\{}:", drive_letter);
            let wide_path: Vec<u16> = OsStr::new(&path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let handle = CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                0xC0000000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING,
                HANDLE::default(),
            )
            .context("Failed to open drive")?;

            if handle == INVALID_HANDLE_VALUE {
                anyhow::bail!("Invalid handle when opening drive");
            }

            Ok(Self { handle })
        }
    }

    #[cfg(windows)]
    pub fn read_sectors(&self, start_sector: u64, num_sectors: u64, sector_size: u64) -> Result<Vec<u8>> {
        use windows::Win32::Storage::FileSystem::{ReadFile, SetFilePointerEx, FILE_BEGIN};

        unsafe {
            let offset = (start_sector * sector_size) as i64;
            let mut new_pointer = 0i64;
            SetFilePointerEx(self.handle, offset, Some(&mut new_pointer), FILE_BEGIN)
                .context("Failed to seek to sector")?;

            let buffer_size = (num_sectors * sector_size) as usize;
            let mut buffer = vec![0u8; buffer_size];
            let mut bytes_read = 0u32;

            ReadFile(
                self.handle,
                Some(buffer.as_mut_slice()),
                Some(&mut bytes_read),
                None,
            )
            .context("Failed to read sectors")?;

            buffer.truncate(bytes_read as usize);
            Ok(buffer)
        }
    }

    #[cfg(windows)]
    pub fn get_sector_size(&self) -> Result<u64> {
        unsafe {
            let mut geometry = DISK_GEOMETRY::default();
            let mut bytes_returned = 0u32;

            DeviceIoControl(
                self.handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                None,
                0,
                Some(&mut geometry as *mut _ as *mut _),
                std::mem::size_of::<DISK_GEOMETRY>() as u32,
                Some(&mut bytes_returned),
                None,
            )
            .context("Failed to get disk geometry")?;

            Ok(geometry.BytesPerSector as u64)
        }
    }

    #[cfg(windows)]
    pub fn get_disk_size(&self) -> Result<u64> {
        unsafe {
            let mut geometry = DISK_GEOMETRY::default();
            let mut bytes_returned = 0u32;

            DeviceIoControl(
                self.handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                None,
                0,
                Some(&mut geometry as *mut _ as *mut _),
                std::mem::size_of::<DISK_GEOMETRY>() as u32,
                Some(&mut bytes_returned),
                None,
            )
            .context("Failed to get disk geometry")?;

            // Total size = cylinders * tracks_per_cylinder * sectors_per_track * bytes_per_sector
            let total_size = geometry.Cylinders as u64
                * geometry.TracksPerCylinder as u64
                * geometry.SectorsPerTrack as u64
                * geometry.BytesPerSector as u64;

            Ok(total_size)
        }
    }
}

#[cfg(windows)]
impl Drop for DiskHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileSystemType {
    NTFS,
    ExFAT,
    FAT32,
    Unknown,
}

#[cfg(windows)]
pub fn get_filesystem_type(drive_letter: char) -> Result<FileSystemType> {
    unsafe {
        let root_path = format!("{}:\\", drive_letter);
        let wide_path: Vec<u16> = OsStr::new(&root_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut fs_name = vec![0u16; 256];
        let mut volume_name = vec![0u16; 256];
        let mut serial_number = 0u32;
        let mut max_component_length = 0u32;
        let mut file_system_flags = 0u32;

        GetVolumeInformationW(
            PCWSTR(wide_path.as_ptr()),
            Some(&mut volume_name),
            Some(&mut serial_number),
            Some(&mut max_component_length),
            Some(&mut file_system_flags),
            Some(&mut fs_name),
        )
        .context("Failed to get volume information")?;

        let fs_name_str = String::from_utf16_lossy(&fs_name)
            .trim_end_matches('\0')
            .to_uppercase();

        Ok(match fs_name_str.as_str() {
            "NTFS" => FileSystemType::NTFS,
            "EXFAT" => FileSystemType::ExFAT,
            "FAT32" => FileSystemType::FAT32,
            _ => FileSystemType::Unknown,
        })
    }
}

#[cfg(not(windows))]
pub fn get_filesystem_type(_drive_letter: char) -> Result<FileSystemType> {
    anyhow::bail!("This application only works on Windows");
}

#[cfg(windows)]
pub fn get_available_drives() -> Vec<char> {
    use windows::Win32::Storage::FileSystem::GetLogicalDrives;

    let mut drives = Vec::new();
    unsafe {
        let drive_bits = GetLogicalDrives();
        for i in 0..26 {
            if drive_bits & (1 << i) != 0 {
                drives.push((b'A' + i) as char);
            }
        }
    }
    drives
}

#[cfg(not(windows))]
pub fn get_available_drives() -> Vec<char> {
    Vec::new()
}
