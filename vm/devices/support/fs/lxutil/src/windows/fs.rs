// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::api::LX_UTIL_FS_CONTEXT;
use super::util;
use bitfield_struct::bitfield;
use std::os::windows::io::OwnedHandle;
use windows::Wdk::Storage::FileSystem;
use windows::Win32::Storage::FileSystem as W32Fs;

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

// Implements the chmod operation.

// N.B. Linux permission bits are not fully supported. Only the read-only
// attribute can be modified by altering the write bits of the file.

// N.B. For unsupported changes this function returns success even though it
// did nothing.
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

// Determines the correct owner and mode of an item based on
// the parent's properties.
// mode and owner gid will be updated only if the parent has the setgit bit set.
pub fn determine_creation_info(
    parent_mode: lx::mode_t,
    parent_gid: lx::gid_t,
    mode: &mut lx::mode_t,
    owner_gid: &mut lx::gid_t,
) {
    if parent_mode & lx::S_ISGID != 0 {
        if lx::s_isdir(*mode) {
            *mode |= lx::S_ISGID;
        }

        *owner_gid = parent_gid;
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
