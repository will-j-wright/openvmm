// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(
    non_snake_case,
    non_camel_case_types,
    dead_code,
    clippy::upper_case_acronyms
)]

use ntapi::ntioapi;
use std::ffi;
use std::os::windows::prelude::*;
use winapi::shared::basetsd;
use winapi::shared::ntdef;
use windows::Wdk::Storage::FileSystem;

// Maximum size needed for an EA buffer containing all metadata fields.
pub const LX_UTIL_FS_METADATA_EA_BUFFER_SIZE: usize = 84;

// NT constants missing from ntapi.
pub const LX_FILE_METADATA_HAS_UID: ntdef::ULONG = 0x1;
pub const LX_FILE_METADATA_HAS_GID: ntdef::ULONG = 0x2;
pub const LX_FILE_METADATA_HAS_MODE: ntdef::ULONG = 0x4;
pub const IO_REPARSE_TAG_LX_SYMLINK: ntdef::ULONG = 0xA000001D;
pub const FILE_CS_FLAG_CASE_SENSITIVE_DIR: ntdef::ULONG = 0x1;

// Fallback modes.
pub const LX_DRVFS_DISABLE_NONE: ntdef::ULONG = 0;

// Compatibility flags.
pub const FS_CONTEXT_SUPPORTS_QUERY_BY_NAME: ntdef::ULONG = 0x1;
pub const FS_CONTEXT_SUPPORTS_STAT_INFO: ntdef::ULONG = 0x2;
pub const FS_CONTEXT_SUPPORTS_STABLE_FILE_ID: ntdef::ULONG = 0x4;
pub const FS_CONTEXT_SUPPORTS_CASE_SENSITIVE_SEARCH: ntdef::ULONG = 0x8;
pub const FS_CONTEXT_SUPPORTS_REPARSE_POINTS: ntdef::ULONG = 0x10;
pub const FS_CONTEXT_SUPPORTS_HARD_LINKS: ntdef::ULONG = 0x20;
pub const FS_CONTEXT_SUPPORTS_PERMISSION_MAPPING: ntdef::ULONG = 0x40;
pub const FS_CONTEXT_SUPPORTS_POSIX_UNLINK_RENAME: ntdef::ULONG = 0x80;
pub const FS_CONTEXT_CUSTOM_FALLBACK_MODE: ntdef::ULONG = 0x100;
pub const FS_CONTEXT_SERVER_REPARSE_POINTS: ntdef::ULONG = 0x200;
pub const FS_CONTEXT_ASYNCHRONOUS_MODE: ntdef::ULONG = 0x400;
pub const FS_CONTEXT_SUPPORTS_STAT_LX_INFO: ntdef::ULONG = 0x800;
pub const FS_CONTEXT_SUPPORTS_METADATA: ntdef::ULONG = 0x1000;
pub const FS_CONTEXT_SUPPORTS_CASE_SENSITIVE_DIR: ntdef::ULONG = 0x2000;
pub const FS_CONTEXT_SUPPORTS_XATTR: ntdef::ULONG = 0x4000;
pub const FS_CONTEXT_SUPPORTS_IGNORE_READ_ONLY_DISPOSITION: ntdef::ULONG = 0x8000;

// Flags for converting attributes.
pub const LX_UTIL_FS_CALLER_HAS_TRAVERSE_PRIVILEGE: ntdef::ULONG = 0x1;

// Flags for listing extended attributes.
pub const LX_UTIL_XATTR_LIST_CASE_SENSITIVE_DIR: ntdef::ULONG = 0x1;

// Size of PE header signature.
pub const LX_UTIL_PE_HEADER_SIZE: ntdef::ULONG = 2;

pub type LX_UTIL_FS_WRITE_DIRENTRY = unsafe extern "C" fn(
    context: ntdef::PVOID,
    file_id: ntdef::ULONGLONG,
    name: &pal::windows::UnicodeStringRef<'_>,
    entry_type: i32,
    buffer_full: &mut ntdef::BOOLEAN,
) -> i32;

pub type LX_UTIL_FS_TRANSLATE_ABSOLUTE_NT_SYMLINK = unsafe extern "C" fn(
    context: ntdef::PVOID,
    substitute_name: &ntdef::UNICODE_STRING,
    link_target: &mut ntdef::UNICODE_STRING,
) -> i32;

#[repr(C)]
pub struct LX_UTIL_FS_CALLBACKS {
    pub WriteDirentryMethod: Option<LX_UTIL_FS_WRITE_DIRENTRY>,
    pub TranslateAbsoluteSymlinkMethod: Option<LX_UTIL_FS_TRANSLATE_ABSOLUTE_NT_SYMLINK>,
}

#[repr(C)]
pub struct LX_UTIL_FS_CONTEXT {
    pub Callbacks: *const LX_UTIL_FS_CALLBACKS,
    pub CompatibilityFlags: ntdef::ULONG,
}

unsafe impl Send for LX_UTIL_FS_CONTEXT {}
unsafe impl Sync for LX_UTIL_FS_CONTEXT {}

#[repr(C)]
pub struct LX_UTIL_DIRECTORY_ENUMERATOR {
    Handle: RawHandle,
    Buffer: ntdef::PVOID,
    BufferNextEntry: ntdef::PVOID,
    BufferSize: ntdef::ULONG,
    NextReadIndex: ntdef::ULONG,
    FileInformationClassIndex: ntdef::ULONG,
    Flags: ntdef::ULONG,
}

unsafe impl Send for LX_UTIL_DIRECTORY_ENUMERATOR {}

unsafe impl Sync for LX_UTIL_DIRECTORY_ENUMERATOR {}

#[repr(C)]
pub struct LX_UTIL_BUFFER {
    pub Buffer: ntdef::PVOID,
    pub Size: usize,
    pub Flags: ntdef::ULONG,
}

impl Default for LX_UTIL_BUFFER {
    fn default() -> Self {
        Self {
            Buffer: std::ptr::null_mut(),
            Size: 0,
            Flags: 0,
        }
    }
}

/// Ensures lxutil.dll has been loaded successfully. If this is not called,
/// then the LxUtil* functions may panic if the DLL cannot be loaded.
pub fn delay_load_lxutil() -> std::io::Result<()> {
    get_module().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    Ok(())
}

pal::delayload!("lxutil.dll" {
    pub fn LxUtilDirectoryEnumeratorCleanup(enumerator: &mut LX_UTIL_DIRECTORY_ENUMERATOR) -> ();

    pub fn LxUtilFsCreateLinkReparseBuffer(
        link_target: &ntdef::ANSI_STRING,
        size: &mut ntdef::USHORT,
    ) -> ntioapi::PREPARSE_DATA_BUFFER;

    pub fn LxUtilFsCreateMetadataEaBuffer(
        uid: lx::uid_t,
        gid: lx::gid_t,
        mode: lx::mode_t,
        device_id: lx::dev_t,
        ea_buffer: *mut ffi::c_void,
    ) -> ntdef::ULONG;

    pub fn LxUtilFsCreateNtLinkReparseBuffer(
        link_target: *const ntdef::UNICODE_STRING,
        flags: ntdef::ULONG,
        size: &mut ntdef::USHORT,
    ) -> ntioapi::PREPARSE_DATA_BUFFER;

    pub fn LxUtilFsFileModeToReparseTag(mode: lx::mode_t) -> ntdef::ULONG;

    pub fn LxUtilFsGetFileSystemBlockSize(handle: RawHandle) -> ntdef::ULONG;

    pub fn LxUtilFsGetLxFileSystemAttributes(
        handle: RawHandle,
        fs_type: usize,
        stat_fs: &mut lx::StatFs,
    ) -> i32;

    pub fn LxUtilFsInitialize(
        handle: RawHandle,
        fallback_mode: ntdef::ULONG,
        asynchronous_mode: ntdef::BOOLEAN,
        callbacks: &LX_UTIL_FS_CALLBACKS,
        fs_context: &mut LX_UTIL_FS_CONTEXT,
        information: &mut FileSystem::FILE_STAT_INFORMATION,
    ) -> i32;

    pub fn LxUtilFsIsAppExecLink(attributes: ntdef::ULONG, reparse_tag: ntdef::ULONG) -> ntdef::BOOLEAN;

    pub fn LxUtilFsReadDir(
        fs_context: &LX_UTIL_FS_CONTEXT,
        directory: RawHandle,
        enumerator: &mut LX_UTIL_DIRECTORY_ENUMERATOR,
        offset: &mut lx::off_t,
        context: ntdef::PVOID,
    ) -> i32;

    pub fn LxUtilFsReadAppExecLink(offset:u64, buffer: ntdef::PVOID, buffer_size: basetsd::SIZE_T) -> basetsd::SIZE_T;

    pub fn LxUtilFsReadLinkLength(
        fs_context: &LX_UTIL_FS_CONTEXT,
        handle: RawHandle,
        callback_context: ntdef::PVOID,
        length: &mut ntdef::ULONG,
    ) -> i32;

    pub fn LxUtilFsSetTimes(
        handle: RawHandle,
        accessed_time: &lx::Timespec,
        modified_time: &lx::Timespec,
        change_time: &lx::Timespec,
    ) -> i32;

    pub fn LxUtilFsTruncate(handle: RawHandle, size: ntdef::ULONGLONG) -> i32;

    pub fn LxUtilFsUpdateLxAttributes(
        handle: RawHandle,
        uid: lx::uid_t,
        gid: lx::gid_t,
        mode: lx::mode_t,
    ) -> i32;

    pub fn LxUtilSymlinkRead(link_file: RawHandle, link_target: *mut ntdef::UNICODE_STRING) -> i32;

    pub fn LxUtilXattrGet(
        handle: RawHandle,
        name: &ntdef::ANSI_STRING,
        value: &mut LX_UTIL_BUFFER,
    ) -> isize;

    pub fn LxUtilXattrGetSystem(
        handle: RawHandle,
        name: &ntdef::ANSI_STRING,
        value: &mut LX_UTIL_BUFFER,
    ) -> isize;

    pub fn LxUtilXattrList(handle: RawHandle, flags: ntdef::ULONG, list: *mut *const u8) -> isize;

    pub fn LxUtilXattrRemove(handle: RawHandle, name: &ntdef::ANSI_STRING) -> i32;

    pub fn LxUtilXattrSet(
        handle: RawHandle,
        name: &ntdef::ANSI_STRING,
        value: &LX_UTIL_BUFFER,
        flags: i32,
    ) -> i32;

    pub fn LxUtilXattrSetSystem(
        handle: RawHandle,
        name: &ntdef::ANSI_STRING,
        value: &LX_UTIL_BUFFER,
        flags: i32,
    ) -> i32;
});
