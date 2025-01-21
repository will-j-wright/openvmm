// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::api::LX_UTIL_FS_CONTEXT;
use super::util;
use ::windows::Wdk::Storage::FileSystem;
use ::windows::Wdk::System::SystemServices;
use ::windows::Win32::Storage::FileSystem as W32Fs;
use ::windows::Win32::System::SystemServices as W32Ss;
use bitfield_struct::bitfield;
use std::os::windows::io::OwnedHandle;
use std::path::Path;

const LX_UTIL_DEFAULT_PERMISSIONS: u32 = 0o777;

const LX_UTIL_FS_DIR_WRITE_ACCESS: u32 =
    W32Fs::FILE_ADD_FILE.0 | W32Fs::FILE_ADD_SUBDIRECTORY.0 | W32Fs::FILE_DELETE_CHILD.0;

const LX_UTIL_FS_CALLER_HAS_TRAVERSE_PRIVILEGE: u32 = 0x1;

const LX_UTIL_FS_ALLOCATION_BLOCK_SIZE: u64 = 512;

pub type WriteDirentryFn = fn(
    context: super::DirEnumContext<'_>,
    file_id: u64,
    name: &pal::windows::UnicodeStringRef<'_>,
    entry_type: i32,
    buffer_full: &mut bool,
) -> i32;

pub type TranslateAbsoluteSymlinkFn = fn(
    context: *const super::VolumeState,
    substitute_name: pal::windows::UnicodeStringRef<'_>,
    link_target: pal::windows::UnicodeStringRef<'_>,
) -> i32;

pub struct FsCallbacks {
    pub write_direntry_method: Option<WriteDirentryFn>,
    pub translate_absolute_symlink_method: Option<TranslateAbsoluteSymlinkFn>,
}

#[bitfield(u32)]
pub struct FsCompatibilityFlags {
    supports_query_by_name: bool,
    supports_stat_info: bool,
    supports_stable_file_id: bool,
    supports_case_sensitive_search: bool,
    supports_reparse_points: bool,
    supports_hard_links: bool,
    supports_permission_mapping: bool,
    supports_posix_unlink_rename: bool,
    custom_fallback_mode: bool,
    server_reparse_points: bool,
    asynchronous_mode: bool,
    supports_stat_lx_info: bool,
    supports_metadata: bool,
    supports_case_sensitive_dir: bool,
    supports_xattr: bool,
    supports_ignore_read_only_disposition: bool,
    #[bits(16)]
    _reserved: u16,
}

pub struct FsContext {
    pub callbacks: *const FsCallbacks,
    pub compatibility_flags: FsCompatibilityFlags,
}

// Temporary implementation until all functions are moved over to use FsContext
impl FsContext {
    pub fn new(fs_context: &LX_UTIL_FS_CONTEXT) -> Self {
        FsContext {
            callbacks: fs_context.Callbacks as *const FsCallbacks,
            compatibility_flags: fs_context.CompatibilityFlags.into(),
        }
    }
}

unsafe impl Send for FsContext {}
unsafe impl Sync for FsContext {}

#[bitfield(u8)]
pub struct RenameFlags {
    pub escape_name: bool,
    pub posix_semantics: bool,
    #[bits(6)]
    _reserved: u8,
}

#[derive(Default)]
pub struct InodeAttributes {
    pub uid: Option<lx::uid_t>,
    pub gid: Option<lx::gid_t>,
    pub mode: Option<lx::mode_t>,
    pub device_id: Option<lx::dev_t>,
}

pub fn rename(
    file_handle: &OwnedHandle,
    target_parent: &OwnedHandle,
    target_path: &Path,
    fs_context: &mut FsContext,
    flags: RenameFlags,
) -> lx::Result<()> {
    // Set the POSIX semantics flag if the FS supports POSIX unlink rename
    let new_flags = flags.with_posix_semantics(
        fs_context
            .compatibility_flags
            .supports_posix_unlink_rename(),
    );

    util::rename(file_handle, target_parent, target_path, new_flags)
}

/// Implements the chmod operation.
///
/// N.B. Linux permission bits are not fully supported. Only the read-only
/// attribute can be modified by altering the write bits of the file.
///
/// N.B. For unsupported changes this function returns success even though it
/// did nothing.
pub fn chmod(file_handle: &OwnedHandle, mode: lx::mode_t) -> lx::Result<()> {
    let info: FileSystem::FILE_BASIC_INFORMATION = util::query_information_file(file_handle)?;

    if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        Ok(())
    } else if mode & 0o222 == 0 {
        util::set_readonly_attribute(file_handle, info.FileAttributes, true)
    } else {
        util::set_readonly_attribute(file_handle, info.FileAttributes, false)
    }
}

pub fn delete_file(fs_context: &mut FsContext, file_handle: &OwnedHandle) -> lx::Result<()> {
    let result = delete_file_core(fs_context, file_handle);

    match result {
        Ok(_) => result,
        Err(e) => {
            if e.value() == lx::EIO {
                result
            } else {
                delete_read_only_file(fs_context, file_handle)
            }
        }
    }
}

pub fn delete_file_core(fs_context: &mut FsContext, file_handle: &OwnedHandle) -> lx::Result<()> {
    if fs_context
        .compatibility_flags
        .supports_posix_unlink_rename()
    {
        delete_file_core_posix(fs_context, file_handle)
    } else {
        delete_file_core_non_posix(file_handle)
    }
}

pub fn delete_read_only_file(
    fs_context: &mut FsContext,
    file_handle: &OwnedHandle,
) -> lx::Result<()> {
    let info: FileSystem::FILE_BASIC_INFORMATION = util::query_information_file(file_handle)?;

    if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_READONLY.0 == 0 {
        Err(lx::Error::from_lx(lx::EIO))
    } else {
        delete_file_core(fs_context, file_handle)
    }
}

fn delete_file_core_non_posix(file_handle: &OwnedHandle) -> lx::Result<()> {
    let info = FileSystem::FILE_DISPOSITION_INFORMATION {
        DeleteFile: true.into(),
    };

    util::set_information_file(&file_handle, &info)
}

fn delete_file_core_posix(fs_context: &mut FsContext, file_handle: &OwnedHandle) -> lx::Result<()> {
    loop {
        // Set the flags for FILE_DISPOSITION_INFORMATION_EX and set
        // FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE if the flag is set in
        // fs_context
        let flags: FileSystem::FILE_DISPOSITION_INFORMATION_EX_FLAGS =
            FileSystem::FILE_DISPOSITION_INFORMATION_EX_FLAGS(
                FileSystem::FILE_DISPOSITION_DELETE.0
                    | FileSystem::FILE_DISPOSITION_POSIX_SEMANTICS.0
                    | if fs_context
                        .compatibility_flags
                        .supports_ignore_read_only_disposition()
                    {
                        FileSystem::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE.0
                    } else {
                        0
                    },
            );
        let info = FileSystem::FILE_DISPOSITION_INFORMATION_EX { Flags: flags };

        let result = util::set_information_file(&file_handle, &info);

        match result {
            Ok(_) => return result,
            Err(e) => {
                if e.value() == lx::EPERM
                    && fs_context
                        .compatibility_flags
                        .supports_ignore_read_only_disposition()
                {
                    fs_context
                        .compatibility_flags
                        .set_supports_ignore_read_only_disposition(false);
                    continue;
                }
            }
        }

        return result;
    }
}

/// Convert file attributes and security to a Linux file mode. If any of the metadata
/// fields provided in `info` is invalid, its flag will be removed from the LxFlags field.
pub fn convert_mode(
    fs_context: &FsContext,
    info: &FileSystem::FILE_STAT_LX_INFORMATION,
    flags: u32,
    umask: u32,
    fmask: u32,
    dmask: u32,
) -> lx::Result<lx::mode_t> {
    let mut local_mode: lx::mode_t;
    if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        && (info.ReparseTag == FileSystem::IO_REPARSE_TAG_LX_SYMLINK as u32
            || info.ReparseTag == W32Ss::IO_REPARSE_TAG_SYMLINK
            || info.ReparseTag == W32Ss::IO_REPARSE_TAG_MOUNT_POINT)
    {
        return Ok(lx::S_IFLNK | 0o777);
    }

    if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        local_mode = lx::S_IFDIR;
    } else {
        local_mode = lx::S_IFREG;
    }

    // If the file system doesn't support permission mapping, just return full
    // access.
    //
    // N.B. For read-only files, the write bits are removed from the mode.
    if !fs_context.compatibility_flags.supports_permission_mapping() {
        local_mode |= LX_UTIL_DEFAULT_PERMISSIONS;
        if lx::s_isreg(local_mode) && info.FileAttributes & W32Fs::FILE_ATTRIBUTE_READONLY.0 != 0 {
            local_mode &= !0o222;
        }
    } else {
        // Report read permission if the user has read access to a file, or list
        // access to a directory.
        static_assertions::const_assert_eq!(W32Fs::FILE_READ_DATA.0, W32Fs::FILE_LIST_DIRECTORY.0);

        if info.EffectiveAccess & W32Fs::FILE_READ_DATA.0 != 0 {
            local_mode |= 0o444;
        }

        // Report write permission if the user has write access to a file. For
        // directories, write permission is included if the user either has add
        // file, add subdirectory, or delete child permission.
        //
        // N.B. If the user has only one of the directory permissions reported
        //      as write access, the other operations will fail due to NT access
        //      checks.
        //
        // N.B. For regular files, write permission is not reported if the
        //      read-only attribute is set.
        if !lx::s_isdir(local_mode) {
            if (info.FileAttributes & W32Fs::FILE_ATTRIBUTE_READONLY.0 == 0)
                && (info.EffectiveAccess & W32Fs::FILE_WRITE_DATA.0 != 0)
            {
                local_mode |= 0o222;
            }
        } else if info.EffectiveAccess & LX_UTIL_FS_DIR_WRITE_ACCESS != 0 {
            local_mode |= 0o222;
        }

        // Report execute permission if the user has execute access to a file,
        // or traverse access to a directory. For directories, the bypass
        // traverse checking privilege is also checked.
        static_assertions::const_assert_eq!(W32Fs::FILE_EXECUTE.0, W32Fs::FILE_TRAVERSE.0);

        if info.EffectiveAccess & W32Fs::FILE_EXECUTE.0 == W32Fs::FILE_EXECUTE.0
            || (lx::s_isdir(local_mode) && flags & LX_UTIL_FS_CALLER_HAS_TRAVERSE_PRIVILEGE != 0)
        {
            local_mode |= 0o111;
        }
    }

    // Apply the masks if the mode was automatically determined.
    //
    // N.B. If the mode was present but invalid, the flag for it will have
    //      been removed.
    //
    // N.B. The masks are not applied to symlinks, because they should always
    //      have their access mask set to 777.
    if info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_MODE == 0 {
        debug_assert!(!lx::s_islnk(local_mode));

        local_mode &= umask;
        if lx::s_isdir(local_mode) {
            local_mode &= dmask;
        } else {
            local_mode &= fmask;
        }
    }

    Ok(local_mode)
}

/// Determine the owner and node to use for a file. If any of the metadata fields provided
/// in `info` is invalid, its flag will be removed from the LxFlags field.
pub fn determine_inode_attributes(
    fs_context: &FsContext,
    info: &mut FileSystem::FILE_STAT_LX_INFORMATION,
    flags: u32,
    umask: u32,
    fmask: u32,
    dmask: u32,
) -> lx::Result<InodeAttributes> {
    validate_lx_attributes(info);
    let mut attributes = InodeAttributes::default();

    if (info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_MODE == 0) || lx::s_islnk(info.LxMode) {
        let mode = convert_mode(fs_context, info, flags, umask, fmask, dmask)?;
        attributes.mode = Some(mode);

        debug_assert!(
            info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_MODE == 0
                || !lx::s_islnk(mode)
                || mode == (lx::S_IFLNK | 0o777)
        );
    } else {
        attributes.mode = Some(info.LxMode);
    }

    if info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_UID != 0 {
        attributes.uid = Some(info.LxUid);
    }

    if info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_GID != 0 {
        attributes.gid = Some(info.LxGid);
    }

    if lx::s_ischr(info.LxMode) || lx::s_isblk(info.LxMode) {
        if info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_DEVICE_ID != 0 {
            attributes.device_id = Some(lx::make_dev(info.LxDeviceIdMajor, info.LxDeviceIdMinor));
        } else {
            attributes.device_id = Some(0);
        }
    }

    Ok(attributes)
}

/// Validate the LX attributes on a file and removes flags
/// for invalid attributes
pub fn validate_lx_attributes(info: &mut FileSystem::FILE_STAT_LX_INFORMATION) {
    let mut expected_file_type: lx::mode_t;

    if info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_MODE != 0 {
        if info.LxMode & !lx::MODE_VALID_BITS != 0 {
            info.LxFlags &= !FileSystem::LX_FILE_METADATA_HAS_MODE;
        } else {
            expected_file_type = 0;
            if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                expected_file_type = util::reparse_tag_to_file_mode(info.ReparseTag);
            }

            if expected_file_type == 0 {
                if info.FileAttributes & W32Fs::FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
                    expected_file_type = lx::S_IFDIR;
                } else {
                    expected_file_type = lx::S_IFREG;
                }
            }

            if info.LxMode & lx::S_IFMT != expected_file_type {
                info.LxFlags &= !FileSystem::LX_FILE_METADATA_HAS_MODE;
            }
        }
    }

    if (info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_UID != 0) && (info.LxUid == lx::UID_INVALID)
    {
        info.LxFlags &= !FileSystem::LX_FILE_METADATA_HAS_UID;
    }

    if (info.LxFlags & FileSystem::LX_FILE_METADATA_HAS_GID != 0) && (info.LxUid == lx::GID_INVALID)
    {
        info.LxFlags &= !FileSystem::LX_FILE_METADATA_HAS_GID;
    }
}

/// Convert the allocation size reported by NT to a block count
/// used in the results of the stat system call in Linux
pub fn allocation_size_to_block_count(allocation_size: i64, block_size: u32) -> u64 {
    let mut result = 0;
    let size = allocation_size as u64;

    if size >= block_size as u64 {
        result = size / LX_UTIL_FS_ALLOCATION_BLOCK_SIZE;
        if size % LX_UTIL_FS_ALLOCATION_BLOCK_SIZE != 0 {
            result += 1;
        }
    }

    result
}

/// Convert file information to a stat structure used by Linux.

/// N.B. This routine does not provide all fields. The file system's device ID
/// is not provided.
pub fn get_lx_attr(
    fs_context: &FsContext,
    info: &mut FileSystem::FILE_STAT_LX_INFORMATION,
    flags: u32,
    block_size: u32,
    default_uid: lx::uid_t,
    default_gid: lx::gid_t,
    umask: u32,
    fmask: u32,
    dmask: u32,
) -> lx::Result<lx::Stat> {
    let inode_attr = determine_inode_attributes(fs_context, info, flags, umask, fmask, dmask)?;
    let mode = inode_attr.mode.unwrap_or(0);
    let file_size: u64;
    let block_count: u64;

    if lx::s_isdir(mode) {
        file_size = block_size as u64;
        block_count = 0;
    } else {
        file_size = info.EndOfFile as u64;
        block_count = allocation_size_to_block_count(info.AllocationSize, block_size)
    }

    let stat = lx::Stat {
        uid: inode_attr.uid.unwrap_or(default_uid),
        gid: inode_attr.gid.unwrap_or(default_gid),
        mode,
        device_nr_special: inode_attr.device_id.unwrap_or(0) as u64,
        inode_nr: info.FileId as u64,
        link_count: info.NumberOfLinks as usize,
        access_time: util::nt_time_to_timespec(info.LastAccessTime, true),
        write_time: util::nt_time_to_timespec(info.LastWriteTime, true),
        change_time: if info.ChangeTime == 0 {
            // Some file systems do not provide a change time. If this is the case,
            // use the write time.
            util::nt_time_to_timespec(info.LastWriteTime, true)
        } else {
            util::nt_time_to_timespec(info.ChangeTime, true)
        },
        block_size: block_size as isize,
        file_size,
        block_count,
        device_nr: 0,
        pad0: 0,
        pad1: [0, 0, 0],
    };

    Ok(stat)
}

/// Query the stat information for a handle. If the filesystem does not support FILE_STAT_INFORMATION,
/// one will be constructed using different queries.
pub fn query_stat_information(
    file_handle: &OwnedHandle,
    fs_context: &FsContext,
) -> lx::Result<FileSystem::FILE_STAT_INFORMATION> {
    if fs_context.compatibility_flags.supports_stat_info() {
        util::query_information_file(file_handle)
    } else {
        debug_assert!(!fs_context.compatibility_flags.supports_query_by_name());

        let granted_access = if fs_context.compatibility_flags.supports_permission_mapping() {
            util::check_security(file_handle, W32Ss::MAXIMUM_ALLOWED)?
        } else {
            0
        };

        // TODO: Can this overflow the buffer and still be valid?
        let all_information: FileSystem::FILE_ALL_INFORMATION =
            util::query_information_file(file_handle)?;
        let reparse_tag = if all_information.BasicInformation.FileAttributes
            & W32Fs::FILE_ATTRIBUTE_REPARSE_POINT.0
            != 0
        {
            let tag_information: SystemServices::FILE_ATTRIBUTE_TAG_INFORMATION =
                util::query_information_file(file_handle)?;

            debug_assert!(
                tag_information.FileAttributes & W32Fs::FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            );
            tag_information.ReparseTag
        } else {
            0
        };

        Ok(FileSystem::FILE_STAT_INFORMATION {
            FileId: all_information.InternalInformation.IndexNumber,
            CreationTime: all_information.BasicInformation.CreationTime,
            LastAccessTime: all_information.BasicInformation.LastAccessTime,
            LastWriteTime: all_information.BasicInformation.LastWriteTime,
            ChangeTime: all_information.BasicInformation.ChangeTime,
            AllocationSize: all_information.StandardInformation.AllocationSize,
            EndOfFile: all_information.StandardInformation.EndOfFile,
            FileAttributes: all_information.BasicInformation.FileAttributes,
            ReparseTag: reparse_tag,
            NumberOfLinks: all_information.StandardInformation.NumberOfLinks,
            EffectiveAccess: granted_access,
        })
    }
}

// TODO?: FILE_STAT_LX_INFORMATION is a superset of FILE_STAT_INFORMATION, so it'd be
// possible to do this by creating a buffer large enough for FILE_STAT_LX_INFORMATION
// and casting unsafely a couple of times
fn stat_info_to_stat_lx_info(
    stat_info: FileSystem::FILE_STAT_INFORMATION,
) -> FileSystem::FILE_STAT_LX_INFORMATION {
    FileSystem::FILE_STAT_LX_INFORMATION {
        FileId: stat_info.FileId,
        CreationTime: stat_info.CreationTime,
        LastAccessTime: stat_info.LastAccessTime,
        LastWriteTime: stat_info.LastWriteTime,
        ChangeTime: stat_info.ChangeTime,
        AllocationSize: stat_info.AllocationSize,
        EndOfFile: stat_info.EndOfFile,
        FileAttributes: stat_info.FileAttributes,
        ReparseTag: stat_info.ReparseTag,
        NumberOfLinks: stat_info.NumberOfLinks,
        EffectiveAccess: stat_info.EffectiveAccess,
        ..Default::default()
    }
}

/// Query the stat information with metadata for a handle. If the filesystem does not support FILE_STAT_INFORMATION,
/// one will be constructed using different queries.
pub fn query_stat_lx_information(
    file_handle: &OwnedHandle,
    fs_context: &FsContext,
) -> lx::Result<FileSystem::FILE_STAT_LX_INFORMATION> {
    if fs_context.compatibility_flags.supports_stat_lx_info() {
        util::query_information_file(file_handle)
    } else {
        let stat_info = query_stat_information(file_handle, fs_context)?;
        let mut info = stat_info_to_stat_lx_info(stat_info);

        if fs_context.compatibility_flags.supports_case_sensitive_dir()
            && stat_info.FileAttributes & W32Fs::FILE_ATTRIBUTE_DIRECTORY.0 != 0
        {
            let case_sensitive_info: FileSystem::FILE_CASE_SENSITIVE_INFORMATION =
                util::query_information_file(file_handle)?;

            if case_sensitive_info.Flags & W32Ss::FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
                info.LxFlags |= FileSystem::LX_FILE_CASE_SENSITIVE_DIR;
            }
        }

        Ok(info)
    }
}

/// Query the stat information with metadata for a file based on its name. If the filesystem does not
/// support FILE_STAT_INFORMATION, one will be constructed using different queries.
pub fn query_stat_lx_information_by_name(
    fs_context: &FsContext,
    parent_handle: Option<&OwnedHandle>,
    path: &pal::windows::UnicodeString,
) -> lx::Result<FileSystem::FILE_STAT_LX_INFORMATION> {
    if fs_context.compatibility_flags.supports_stat_lx_info() {
        util::query_information_file_by_name(parent_handle, path)
    } else {
        let stat_info: FileSystem::FILE_STAT_INFORMATION =
            util::query_information_file_by_name(parent_handle, path)?;
        let mut info = stat_info_to_stat_lx_info(stat_info);

        if fs_context.compatibility_flags.supports_case_sensitive_dir()
            && stat_info.FileAttributes & W32Fs::FILE_ATTRIBUTE_DIRECTORY.0 != 0
        {
            let case_sensitive_info: FileSystem::FILE_CASE_SENSITIVE_INFORMATION =
                util::query_information_file_by_name(parent_handle, path)?;

            if case_sensitive_info.Flags & W32Ss::FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
                info.LxFlags |= FileSystem::LX_FILE_CASE_SENSITIVE_DIR;
            }
        }

        Ok(info)
    }
}
