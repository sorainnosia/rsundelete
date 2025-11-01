# rsundelete
A tiny Rust file recovery for NTFS and exFAT file system. Recover deleted file into new drive.

# Operating System
Windows

# Recovery for NTFS and exFAT Drives
Files can be recovered from drive formatted using NTFS and exFAT filesystem as long as the free space is not being overwritten, tested works for even large files in spare drives. *Not tested in Operating System NTFS formatted drive such as C*.

This tool is not intended for deliberate file deletion and recovery. Since the operating system may create temporary files that overwrite data in free space, recovery attempts could result in corrupted or invalid data. If a file is accidentally deleted and needs to be recovered, it is strongly recommended to immediately stop all read and write operations on the system and use a recovery tool as soon as possible—before the data in the free space is overwritten.

# CAUTION
This tool does a lot of read and write access to your Disk Drives which may cause *hardware failures*, *USE IT WITH CAUTION*. Due to large amount of create/delete of files in Operating System NTFS formatted drive this tool is not tested in such drives but tested in spare NTFS and exFAT drives.
