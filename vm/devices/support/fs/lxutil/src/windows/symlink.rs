// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use pal::windows::UnicodeString;
use widestring::U16CString;
use windows::Wdk::Storage::FileSystem;
use windows::Win32::System::SystemServices as W32Ss;

/// Get the symlink substitute name and flags from the reparse data.
fn get_substitute_name(
    reparse: &FileSystem::REPARSE_DATA_BUFFER,
) -> lx::Result<(UnicodeString, u32)> {
    // safety: Caller guarantees that the reparse data buffer is well-formed.
    let (buffer, offset, length, flags) = unsafe {
        match reparse.ReparseTag {
            W32Ss::IO_REPARSE_TAG_SYMLINK => (
                &reparse.Anonymous.SymbolicLinkReparseBuffer.PathBuffer,
                reparse
                    .Anonymous
                    .SymbolicLinkReparseBuffer
                    .SubstituteNameOffset,
                reparse
                    .Anonymous
                    .SymbolicLinkReparseBuffer
                    .SubstituteNameLength,
                reparse.Anonymous.SymbolicLinkReparseBuffer.Flags,
            ),
            W32Ss::IO_REPARSE_TAG_MOUNT_POINT => (
                &reparse.Anonymous.MountPointReparseBuffer.PathBuffer,
                reparse
                    .Anonymous
                    .MountPointReparseBuffer
                    .SubstituteNameOffset,
                reparse
                    .Anonymous
                    .MountPointReparseBuffer
                    .SubstituteNameLength,
                0,
            ),
            _ => return Err(lx::Error::EIO),
        }
    };

    // safety: The validity of the reparse buffer is provided by the caller. If the buffer is valid,
    // the area pointed to by `buffer + offset` is a valid wstring of length `length`, and this operation is safe.
    let substitute_name = unsafe {
        UnicodeString::new(std::slice::from_raw_parts(
            buffer.as_ptr().byte_offset(offset as _),
            (length as usize) / size_of::<u16>(),
        ))
        .map_err(|_| lx::Error::EIO)?
    };

    Ok((substitute_name, flags))
}

/// Translates an absolute NT symlink target to an LX path.
fn translate_absolute_target(
    substitute_name: &UnicodeString,
    state: &super::VolumeState,
) -> lx::Result<UnicodeString> {
    if state.options.sandbox || state.options.symlink_root.is_empty() {
        // EPERM is the default return value if no callback is provided
        return Err(lx::Error::EPERM);
    }

    // Convert from UTF-16 UNICODE_STRING to String
    let name = substitute_name.as_slice();
    if name.len() < 6 {
        return Err(lx::Error::EIO);
    }
    let name = if name[name.len() - 1] == 0 {
        &name[..name.len() - 1]
    } else {
        &name[..name.len()]
    };
    let name = match String::from_utf16(name) {
        Ok(name) => name,
        Err(_) => return Err(lx::Error::EIO),
    };

    // If the symlink does not start with \??\, it is malformed.
    if !name.starts_with("\\??\\") {
        return Err(lx::Error::EIO);
    }

    // Next must be a drive letter, a colon, and another separator.
    // N.B. Mount-point junctions, which use a volume GUID style path, are not supported.
    let (_, name) = name.split_at(4);
    let mut name_as_chars = name.chars();
    let drive_letter = match name_as_chars.next() {
        Some(val) => val,
        None => return Err(lx::Error::EIO),
    };
    if name_as_chars.next() != Some(':') || name_as_chars.next() != Some('\\') {
        return Err(lx::Error::EIO);
    };
    let drive_letter = match drive_letter {
        'a'..='z' => drive_letter,
        'A'..='Z' => ((drive_letter as u8) - b'A' + b'a') as char,
        _ => return Err(lx::Error::EIO),
    };

    let (_, name) = name.split_at(2);
    let name = name.replace('\\', "/");
    let target = format!("{}{}{}", &state.options.symlink_root, drive_letter, name);
    let target = match U16CString::from_str(target) {
        Ok(val) => val,
        Err(_) => return Err(lx::Error::EIO),
    };
    let target = match UnicodeString::new(target.as_ref()) {
        Ok(val) => val,
        Err(_) => return Err(lx::Error::EIO),
    };

    Ok(target)
}

/// Determine the target of an NT symlink. Only relative links are supported.
pub fn read_nt_symlink(
    reparse: &FileSystem::REPARSE_DATA_BUFFER,
    state: &super::VolumeState,
) -> lx::Result<UnicodeString> {
    let (substitute_name, flags) = get_substitute_name(reparse)?;

    if flags & FileSystem::SYMLINK_FLAG_RELATIVE == 0 {
        translate_absolute_target(&substitute_name, state)
    } else {
        if let Some(path) = super::path::unescape_path(&substitute_name)? {
            Ok(path)
        } else {
            Ok(super::path::nt_path_to_lx_path(&substitute_name)?)
        }
    }
}

/// Determine the length of an NT symlink.
pub fn read_nt_symlink_length(
    reparse: &FileSystem::REPARSE_DATA_BUFFER,
    state: &super::VolumeState,
) -> lx::Result<u32> {
    // The length is just the target's UTF-8 length.
    let target = read_nt_symlink(reparse, state)?;
    Ok(String::from_utf16(target.as_slice())
        .map_err(|_| lx::Error::EIO)?
        .len() as u32)
}
