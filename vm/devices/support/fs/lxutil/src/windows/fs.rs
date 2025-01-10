// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::util;
use std::os::windows::io::OwnedHandle;
use windows::Wdk::Storage::FileSystem;

fn delete_file_core_non_posix(file_handle: OwnedHandle) -> lx::Result<()> {
    let info = FileSystem::FILE_DISPOSITION_INFORMATION {
        DeleteFile: true.into(),
    };

    util::set_information_file(&file_handle, &info)
}
