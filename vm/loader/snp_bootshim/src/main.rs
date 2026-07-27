// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Accepts sparse SNP IGVM RAM before entering a direct-boot Linux kernel.

#![cfg_attr(minimal_rt, no_std, no_main)]
// UNSAFETY: The bootshim issues PVALIDATE, reads freshly accepted pages, and
// transfers control directly to the measured Linux entrypoint.
#![cfg_attr(minimal_rt, expect(unsafe_code))]

#[cfg(any(minimal_rt, test))]
use loader_defs::linux::SNP_BOOT_SHIM_PARAMS_MAGIC;
#[cfg(any(minimal_rt, test))]
use loader_defs::linux::SNP_BOOT_SHIM_PARAMS_VERSION;
#[cfg(any(minimal_rt, test))]
use loader_defs::linux::SnpBootShimParams;
#[cfg(any(minimal_rt, test))]
use loader_defs::linux::SnpBootShimRange;

#[cfg(any(minimal_rt, test))]
const PAGE_SIZE: u64 = 4096;

#[cfg(any(minimal_rt, test))]
#[derive(Debug, Eq, PartialEq)]
enum ParamsError {
    UnalignedParams,
    InvalidMagic,
    UnsupportedVersion,
    TooManyRanges,
    InvalidRamEnd,
    InvalidLinuxEntry,
    InvalidLinuxZeroPage,
    ReservedNotZero,
    EmptyRange,
    RangeOverflow,
    RangeOutsideRam,
    UnorderedRanges,
    ParamsRangeOverlap,
}

#[cfg(any(minimal_rt, test))]
fn validate_params(
    params: &SnpBootShimParams,
    params_gpa: u64,
) -> Result<&[SnpBootShimRange], ParamsError> {
    if !params_gpa.is_multiple_of(PAGE_SIZE) {
        return Err(ParamsError::UnalignedParams);
    }
    if params.magic != SNP_BOOT_SHIM_PARAMS_MAGIC {
        return Err(ParamsError::InvalidMagic);
    }
    if params.version != SNP_BOOT_SHIM_PARAMS_VERSION {
        return Err(ParamsError::UnsupportedVersion);
    }
    let range_count =
        usize::try_from(params.range_count).map_err(|_| ParamsError::TooManyRanges)?;
    let ranges = params
        .ranges
        .get(..range_count)
        .ok_or(ParamsError::TooManyRanges)?;
    if params.ram_end == 0 || !params.ram_end.is_multiple_of(PAGE_SIZE) {
        return Err(ParamsError::InvalidRamEnd);
    }
    if params.linux_entry == 0 {
        return Err(ParamsError::InvalidLinuxEntry);
    }
    if !params.linux_zero_page.is_multiple_of(PAGE_SIZE) || params.linux_zero_page >= params.ram_end
    {
        return Err(ParamsError::InvalidLinuxZeroPage);
    }
    if params.reserved != 0 {
        return Err(ParamsError::ReservedNotZero);
    }
    let params_end = params_gpa
        .checked_add(PAGE_SIZE)
        .ok_or(ParamsError::RangeOverflow)?;
    if params_end > params.ram_end {
        return Err(ParamsError::RangeOutsideRam);
    }

    let mut previous_end = 0;
    for range in ranges {
        if range.page_count == 0 {
            return Err(ParamsError::EmptyRange);
        }
        let start = range
            .start_gpn
            .checked_mul(PAGE_SIZE)
            .ok_or(ParamsError::RangeOverflow)?;
        let len = range
            .page_count
            .checked_mul(PAGE_SIZE)
            .ok_or(ParamsError::RangeOverflow)?;
        let end = start.checked_add(len).ok_or(ParamsError::RangeOverflow)?;
        if end > params.ram_end {
            return Err(ParamsError::RangeOutsideRam);
        }
        if start < previous_end {
            return Err(ParamsError::UnorderedRanges);
        }
        if start < params_end && params_gpa < end {
            return Err(ParamsError::ParamsRangeOverlap);
        }
        previous_end = end;
    }

    Ok(ranges)
}

#[cfg(minimal_rt)]
mod arch {
    use super::PAGE_SIZE;
    use core::arch::asm;
    use loader_defs::linux::SnpBootShimRange;
    use minimal_rt::arch::msr::read_msr;
    use minimal_rt::arch::msr::write_msr;
    use x86defs::X86X_AMD_MSR_GHCB;
    use x86defs::snp::GHCB_DATA_PAGE_STATE_LARGE_PAGE;
    use x86defs::snp::GHCB_DATA_PAGE_STATE_PRIVATE;
    use x86defs::snp::GhcbInfo;
    use x86defs::snp::GhcbMsr;

    const LARGE_PAGE_SIZE: u64 = x86defs::X64_LARGE_PAGE_SIZE;

    enum PvalidateStatus {
        Success,
        SizeMismatch,
    }

    #[derive(Debug)]
    pub struct AcceptError;

    fn set_page_private(page_base: u64, large_page: bool) -> Result<(), AcceptError> {
        let extra_data = GHCB_DATA_PAGE_STATE_PRIVATE
            | if large_page {
                GHCB_DATA_PAGE_STATE_LARGE_PAGE
            } else {
                0
            };
        let request = GhcbMsr::new()
            .with_info(GhcbInfo::PAGE_STATE_CHANGE.0)
            .with_pfn(page_base)
            .with_extra_data(extra_data);
        let response = GhcbMsr::from_bits(
            // SAFETY: The request uses the architected GHCB MSR page-state
            // change protocol to assign measured guest RAM as private.
            unsafe {
                write_msr(X86X_AMD_MSR_GHCB, request.into_bits());
                asm!("rep vmmcall", options(nostack));
                read_msr(X86X_AMD_MSR_GHCB)
            },
        );
        if response.into_bits() == GhcbInfo::PAGE_STATE_UPDATED.0 {
            Ok(())
        } else {
            Err(AcceptError)
        }
    }

    fn pvalidate(va: u64, large_page: bool) -> Result<PvalidateStatus, AcceptError> {
        let page_size = large_page as u32;
        let mut error_code: u32;
        let mut carry_flag: u32 = 0;

        // SAFETY: The bootshim invokes PVALIDATE only on identity-mapped private
        // RAM ranges supplied by its measured parameter page.
        unsafe {
            asm!(
                r#"
                pvalidate
                jnc 2f
                inc {carry_flag:e}
                2:
                "#,
                in("rax") va,
                in("ecx") page_size,
                in("edx") 1u32,
                lateout("eax") error_code,
                carry_flag = inout(reg) carry_flag,
            );
        }

        match (error_code, carry_flag) {
            (0, 0) => Ok(PvalidateStatus::Success),
            (6, _) => Ok(PvalidateStatus::SizeMismatch),
            _ => Err(AcceptError),
        }
    }

    unsafe fn fixup_page_cache_state(va: u64) {
        let last = va + PAGE_SIZE - 1;
        for addr in [va, last] {
            let mut byte: u8;
            // SAFETY: The caller has just validated the identity-mapped page.
            // Inline assembly avoids creating a Rust reference for GPA zero.
            unsafe {
                asm!(
                    "mov {byte}, byte ptr [{addr}]",
                    byte = out(reg_byte) byte,
                    addr = in(reg) addr,
                    options(nostack, readonly),
                );
            }
            core::hint::black_box(byte);
        }
    }

    fn fixup_range_cache_state(start: u64, page_count: u64) {
        for page in 0..page_count {
            // SAFETY: `start` names an identity-mapped range that was just
            // successfully validated.
            unsafe {
                fixup_page_cache_state(start + page * PAGE_SIZE);
            }
        }
    }

    pub fn accept_range(range: SnpBootShimRange) -> Result<(), AcceptError> {
        let pages_per_large_page = LARGE_PAGE_SIZE / PAGE_SIZE;
        let mut page_base = range.start_gpn;
        let mut page_count = range.page_count;

        while page_count != 0 {
            if page_base.is_multiple_of(pages_per_large_page)
                && page_count >= pages_per_large_page
                && set_page_private(page_base, true).is_ok()
            {
                let va = page_base * PAGE_SIZE;
                match pvalidate(va, true)? {
                    PvalidateStatus::Success => {
                        fixup_range_cache_state(va, pages_per_large_page);
                        page_base += pages_per_large_page;
                        page_count -= pages_per_large_page;
                        continue;
                    }
                    PvalidateStatus::SizeMismatch => {}
                }
            }

            let va = page_base * PAGE_SIZE;
            set_page_private(page_base, false)?;
            match pvalidate(va, false)? {
                PvalidateStatus::Success => {
                    fixup_range_cache_state(va, 1);
                    page_base += 1;
                    page_count -= 1;
                }
                PvalidateStatus::SizeMismatch => return Err(AcceptError),
            }
        }

        Ok(())
    }
}

#[cfg(minimal_rt)]
const STACK_SIZE: usize = 16 * 1024;

#[cfg(minimal_rt)]
#[repr(C, align(16))]
struct Stack([u8; STACK_SIZE]);

#[cfg(minimal_rt)]
static mut STACK: Stack = Stack([0; STACK_SIZE]);

#[cfg(minimal_rt)]
static mut LINUX_ENTRY: u64 = 0;

#[cfg(minimal_rt)]
static mut LINUX_ZERO_PAGE: u64 = 0;

#[cfg(minimal_rt)]
struct NoAllocator;

#[cfg(minimal_rt)]
// SAFETY: The bootshim performs no dynamic allocation. Returning null makes an
// accidental allocation fail immediately through the normal allocation error
// path instead of consuming untracked guest memory.
unsafe impl core::alloc::GlobalAlloc for NoAllocator {
    unsafe fn alloc(&self, _: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {}
}

#[cfg(minimal_rt)]
#[global_allocator]
static ALLOCATOR: NoAllocator = NoAllocator;

#[cfg(minimal_rt)]
unsafe fn jump_to_linux() -> ! {
    // SAFETY: The caller accepted all omitted RAM and populated these
    // single-threaded handoff statics from the measured parameter page.
    unsafe {
        core::arch::asm!(
            // Clear RAX without relying on its bootshim value.
            "xor eax, eax",
            // Clear RBX to restore the original direct-boot register state.
            "xor ebx, ebx",
            // Clear RCX to restore the original direct-boot register state.
            "xor ecx, ecx",
            // Clear RDX to restore the original direct-boot register state.
            "xor edx, edx",
            // Clear RDI to remove the bootshim parameter-page argument.
            "xor edi, edi",
            // Clear RBP so Linux starts without a bootshim frame pointer.
            "xor ebp, ebp",
            // Clear R8 to restore the original direct-boot register state.
            "xor r8d, r8d",
            // Clear R9 to restore the original direct-boot register state.
            "xor r9d, r9d",
            // Clear R10 to restore the original direct-boot register state.
            "xor r10d, r10d",
            // Clear R11 to restore the original direct-boot register state.
            "xor r11d, r11d",
            // Clear R12, which held the saved bootshim parameter-page GPA.
            "xor r12d, r12d",
            // Clear R13 to restore the original direct-boot register state.
            "xor r13d, r13d",
            // Clear R14 to restore the original direct-boot register state.
            "xor r14d, r14d",
            // Clear R15 to restore the original direct-boot register state.
            "xor r15d, r15d",
            // Stage the architectural initial RFLAGS value after all XORs,
            // since XOR changes the arithmetic flags.
            "push 2",
            // Restore RFLAGS without leaving the staged value on the stack.
            "popfq",
            // Restore RSI to the measured Linux boot-parameter page.
            "mov rsi, qword ptr [rip + {linux_zero_page}]",
            // Explicitly ensure that string operations increment addresses.
            "cld",
            // Use MOV rather than XOR after POPFQ so RFLAGS stays at its
            // architectural direct-boot value.
            "mov rsp, 0",
            // Jump through memory so the Linux entrypoint consumes no GPR.
            "jmp qword ptr [rip + {linux_entry}]",
            linux_entry = sym LINUX_ENTRY,
            linux_zero_page = sym LINUX_ZERO_PAGE,
            options(noreturn),
        )
    }
}

#[cfg(minimal_rt)]
extern "C" fn start(params_gpa: u64) -> ! {
    if !params_gpa.is_multiple_of(PAGE_SIZE) {
        minimal_rt::arch::fault();
    }

    // SAFETY: The VMSA points RSI at a measured, accepted, identity-mapped
    // parameter page whose layout is validated below before any range is used.
    let params = unsafe { &*(params_gpa as *const SnpBootShimParams) };
    let ranges = match validate_params(params, params_gpa) {
        Ok(ranges) => ranges,
        Err(_) => minimal_rt::arch::fault(),
    };

    for &range in ranges {
        if arch::accept_range(range).is_err() {
            minimal_rt::arch::fault();
        }
    }

    // SAFETY: These statics are single-threaded bootshim handoff state. Their
    // values came from the measured parameter page and are consumed
    // immediately by `jump_to_linux`.
    unsafe {
        core::ptr::write_volatile(&raw mut LINUX_ENTRY, params.linux_entry);
        core::ptr::write_volatile(&raw mut LINUX_ZERO_PAGE, params.linux_zero_page);
    }
    // SAFETY: The handoff values have been validated and all omitted RAM has
    // been accepted successfully.
    unsafe { jump_to_linux() }
}

#[cfg(minimal_rt)]
core::arch::global_asm! {
    include_str!("entry.S"),
    relocate = sym minimal_rt::reloc::relocate,
    start = sym start,
    stack = sym STACK,
    STACK_SIZE = const STACK_SIZE,
}

#[cfg(minimal_rt)]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    minimal_rt::arch::fault()
}

#[cfg(not(minimal_rt))]
fn main() {}

#[cfg(test)]
mod tests {
    use super::*;
    use loader_defs::linux::SNP_BOOT_SHIM_MAX_RANGES;

    fn valid_params() -> SnpBootShimParams {
        SnpBootShimParams {
            magic: SNP_BOOT_SHIM_PARAMS_MAGIC,
            version: SNP_BOOT_SHIM_PARAMS_VERSION,
            range_count: 2,
            linux_entry: 0x10_0000,
            linux_zero_page: 0x2000,
            ram_end: 0x20_0000,
            reserved: 0,
            ranges: {
                let mut ranges = [SnpBootShimRange {
                    start_gpn: 0,
                    page_count: 0,
                }; SNP_BOOT_SHIM_MAX_RANGES];
                ranges[0] = SnpBootShimRange {
                    start_gpn: 4,
                    page_count: 3,
                };
                ranges[1] = SnpBootShimRange {
                    start_gpn: 8,
                    page_count: 2,
                };
                ranges
            },
        }
    }

    #[test]
    fn validates_ordered_ranges() {
        let params = valid_params();
        assert_eq!(
            validate_params(&params, 0x1000).unwrap(),
            &params.ranges[..2]
        );
    }

    #[test]
    fn rejects_overlapping_ranges() {
        let mut params = valid_params();
        params.ranges[1].start_gpn = 6;
        assert_eq!(
            validate_params(&params, 0x1000),
            Err(ParamsError::UnorderedRanges)
        );
    }

    #[test]
    fn rejects_parameter_page_overlap() {
        let mut params = valid_params();
        params.ranges[0] = SnpBootShimRange {
            start_gpn: 1,
            page_count: 1,
        };
        assert_eq!(
            validate_params(&params, 0x1000),
            Err(ParamsError::ParamsRangeOverlap)
        );
    }

    #[test]
    fn rejects_out_of_ram_ranges() {
        let mut params = valid_params();
        params.ranges[1] = SnpBootShimRange {
            start_gpn: params.ram_end / PAGE_SIZE,
            page_count: 1,
        };
        assert_eq!(
            validate_params(&params, 0x1000),
            Err(ParamsError::RangeOutsideRam)
        );
    }
}
