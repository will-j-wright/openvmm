# MSHV SNP Support Plan

## Status and scope

This report proposes how to add AMD SEV-SNP support to the current OpenVMM
`virt_mshv` backend. It is based on:

- the current KVM SNP implementation in this branch;
- the current MSHV kernel ABI in
  `~/ai/leafeon/LSG-linux-rolling`;
- the historical prototype in
  `wedsonaf/openvmm@3944f2ca7010d633e73cb6c046f2a10d27172090`.

The prototype is treated as bring-up evidence, not as the target design. It was
built on older SNP/CCA work and contains guest-specific assumptions, stale
kernel workarounds, panic paths, and intentionally incomplete attestation
handling.

The recommended first milestone is **feature parity with the current KVM SNP
Linux direct-boot path on MSHV**. SNP IGVM boot is explicitly out of scope for
this workstream and belongs to a future milestone. The current work may add
backend-neutral launch metadata and VMSA interfaces that the future IGVM loader
will consume, but it must not add SNP IGVM parsing, dispatch, or boot support.
The current IGVM loader still rejects `SnpVpContext` and `SnpIdBlock`, while
the prototype's SNP IGVM loader silently discarded important directives.

All SNP load paths should nevertheless use one VP-context contract from the
start: the loader supplies a VMSA page at a loader-owned GPA regardless of
whether the backend is KVM or MSHV. MSHV imports that page directly. KVM reads
and validates it, translates its state into KVM vCPU state, and then lets KVM
create its internal VMSA at launch finish.

Three launch details must be resolved experimentally against the target kernel
before implementing the dependent MSHV secure-launch and VMGEXIT phases:

- whether an explicit `IsolationState = SECURE` property transition is required
  before encrypted guest-memory mappings, or whether mapping is the only
  host-access transition required by this kernel/hypervisor combination;
- whether launch completion implicitly makes the partition runnable or
  userspace must set `HV_PARTITION_PROPERTY_ISOLATION_CONTROL`;
- whether the target kernel provides the VP GHCB state-page mapping, or
  userspace must access the registered shared GHCB GPA through guest memory.

## Executive summary

MSHV SNP is not a matter of substituting MSHV ioctls for the KVM launch
ioctls. The two backends have materially different ownership and ordering:

1. The loader supplies the authoritative SNP initial VMSA for both backends.
   MSHV imports that page and binds it through `SevControl`. KVM cannot import a
   VMSA page today, so OpenVMM must translate the supplied VMSA back into KVM
   register/sregs/MSR/XCR/XSAVE state before
   `KVM_SEV_SNP_LAUNCH_FINISH`; KVM then creates and seals its internal VMSA.
2. KVM guestmemfd private pages remain host-populatable during launch. MSHV
   guest-memory mapping for an encrypted partition releases host access, so
   memory mapping must be deferred until all loader, CPUID, and VMSA writes
   are complete.
3. KVM handles the SNP execution protocol in-kernel. MSHV forwards
   `HvMessageTypeX64SevVmgexitIntercept` to userspace, so `virt_mshv` needs a
   non-panicking GHCB/VMGEXIT handler.
4. The current MSHV crates already expose the SNP import, completion, PSP
   request, AP creation, and host-access ioctls. No new external dependency is
   required.

The implementation should preserve the current backend-neutral
`virt::AcceptInitialPages` and `InitialPageImportType::VpContext` boundary, add
an MSHV-specific one-shot launch state machine, teach KVM to consume supplied
VMSA state, and keep policy, VMSA construction/translation, CPUID
serialization, and GHCB validation explicit and testable.

## Current state

### Backend-neutral launch contract

`virt::InitialPageImportType` describes normal, unmeasured, shared, VP context,
secrets, CPUID, and CPUID extended-state imports. Visibility is derived from
the import type. `virt::AcceptInitialPages` is the one-shot load-path extension
used after the loader has populated initial memory
(`vmm_core/virt/src/generic.rs:178-222, 351-357, 429-439`).

The current Linux direct loader already:

- configures the SNP C-bit while building page tables;
- emits initial page imports;
- fills uncovered RAM with normal imports as a temporary direct-boot hack.

See `openvmm/openvmm_core/src/worker/vm_loaders/linux.rs:45-91, 145-184` and
`vm/loader/src/linux.rs:614-657`. The prototype's later scan-and-patch of pages
tagged `"linux-pagetables"` is therefore obsolete and should not be copied.

### KVM SNP launch

`KvmPartition` implements `AcceptInitialPages` with a terminal
`NotStarted -> Started -> Finished/Failed` state machine. It starts the SNP
launch, maps each import to a KVM page type, writes the CPUID page, validates
the BSP state, and finishes the launch
(`vmm_core/virt_kvm/src/snp.rs:20-125`).

KVM currently accepts `Normal`, `NormalUnmeasured`, `Secrets`, and `Cpuid`,
and rejects `VpContext`, `Shared`, and `CpuidExtendedState`
(`vmm_core/virt_kvm/src/arch/x86_64/snp.rs:9-27`). The KVM SNP launch-update
UAPI has no VMSA page type (`vm/kvm/src/lib.rs:210-225`), and KVM internally
allocates and populates the VMSA from vCPU state
(`arch/x86/kvm/svm/svm.c:1450-1488`,
`arch/x86/kvm/svm/sev.c:579-662` in the examined Linux tree). Supporting
`VpContext` on KVM therefore means translating the supplied VMSA into KVM state,
not adding it to `KVM_SEV_SNP_LAUNCH_UPDATE`.

The KVM implementation is useful for:

- the backend-neutral API boundary;
- terminal launch-state behavior;
- BSP-state validation requirements;
- CPUID page serialization tests;
- the vCPU state APIs needed for VMSA-to-KVM translation.

It is not a template for MSHV memory ownership or VMSA handling.

### Current MSHV backend

The x86 MSHV backend rejects every isolated partition before creation
(`vmm_core/virt_mshv/src/x86_64/mod.rs:76-79`). It creates ordinary partitions,
registers CPUID intercept results, maps memory immediately, requires a shared VP
register page, and panics on unknown VP exits
(`vmm_core/virt_mshv/src/x86_64/mod.rs:82-139, 229-328, 507-532, 594-624`;
`vmm_core/virt_mshv/src/lib.rs:817-890`).

Those assumptions all need SNP-specific handling:

- create the partition with `MSHV_PT_ISOLATION_SNP`;
- defer encrypted guest-memory mappings;
- consume the loader-supplied BSP VMSA as an isolated-page import;
- avoid requiring the absent shared register page;
- recognize and safely handle the SNP VMGEXIT message.

### Current MSHV userspace ABI availability

The workspace uses `mshv-bindings` and `mshv-ioctls` 0.6.8
(`Cargo.toml:621-622`, `Cargo.lock:4754-4778`). That version already provides:

- `VmFd::modify_gpa_host_access`;
- `VmFd::import_isolated_pages`;
- `VmFd::complete_isolated_import`;
- `VmFd::psp_issue_guest_request`;
- `VmFd::sev_snp_ap_create`.

See the installed crate's `mshv-ioctls-0.6.8/src/ioctls/vm.rs:140-204`.
Bindings also contain SNP policy, VMSA, page-type, GHCB, and `SevControl`
definitions. The implementation should use these wrappers instead of adding
raw ioctl code where wrappers already exist.

## Kernel ABI and ordering constraints

### Partition and VP creation

The kernel maps `MSHV_PT_ISOLATION_SNP` to
`HV_PARTITION_ISOLATION_TYPE_SNP` during partition creation
(`drivers/hv/mshv_root_main.c:3928-4004`). Encrypted VPs receive an intercept
message page and, when available, a GHCB page, but do not receive the normal
shared register page (`drivers/hv/mshv_root_main.c:1737-1847`).

Capability discovery in the driver checks the Hyper-V SNP status and maximum
encrypted partition count (`drivers/hv/mshv_root_main.c:4130-4193, 4408`).
OpenVMM should still fail with a clear typed error when creation or required
properties indicate that SNP is unavailable.

### Memory ownership

For encrypted partitions, `MSHV_SET_GUEST_MEMORY` pins the userspace pages,
releases host access, and maps the GPA range. Mapping failure attempts to
restore host access (`drivers/hv/mshv_root_main.c:2252-2505`). Consequently:

- all initial host writes must finish before encrypted mappings are installed;
- mapping an SNP region during ordinary `PartitionMemoryMap::map_range` is too
  early;
- a partial launch failure is terminal because some pages may already have
  lost host access;
- unmap behavior must distinguish recorded-but-never-mapped regions from
  successfully mapped regions.

The kernel exposes `MSHV_MODIFY_GPA_HOST_ACCESS`, but initial launch should not
use it as a substitute for correct ordering. It is primarily relevant to
runtime guest-request pages and future shared/private transitions
(`include/uapi/linux/mshv.h:390-464`;
`drivers/hv/mshv_root_main.c:3026-3079`).

### Import and completion

`MSHV_IMPORT_ISOLATED_PAGES` accepts only 4 KiB guest PFNs and an explicit page
type. Import, completion, and PSP guest request use the partition's single
asynchronous-hypercall completion state. The kernel holds the partition
`pt_mutex` while waiting for each partition-fd ioctl to complete, so issuing
these operations through that ioctl boundary provides the required
serialization
(`include/uapi/linux/mshv.h:390-464`;
`drivers/hv/mshv_root_main.c:3084-3198`).

`MSHV_COMPLETE_ISOLATED_IMPORT` marks the kernel partition as import-complete
only after the hypercall succeeds. That state changes teardown behavior
(`drivers/hv/mshv_root_main.c:3121-3148, 3535-3578`).

The driver does little semantic validation of the page list or launch
sequence. OpenVMM must validate:

- page alignment and non-empty ranges;
- overflow when converting ranges to PFNs;
- no overlapping imports;
- import types supported by MSHV SNP;
- exactly one initial BSP VMSA for the selected boot mode;
- CPUID page size and entry count;
- completion policy and ID-block consistency.

The UAPI does not by itself establish whether userspace must first set
`HV_PARTITION_PROPERTY_ISOLATION_STATE` to `SECURE`. The prototype does so, but
the current kernel source only makes the mapping-time host-access transition
and the teardown transition to `INSECURE_DIRTY` visible. This must be confirmed
with the target hypervisor/kernel before the launch state machine treats it as
a required independent phase.

Partition-property hypercalls are asynchronous too
(`drivers/hv/mshv_root_main.c:171-180, 1905-1923`). The same serialization
domain must therefore include launch/runtime property changes, not only the
SNP-specific ioctls.

### Teardown hazards

Encrypted teardown clears the runnable state after a completed import, moves
the isolation state to `INSECURE_DIRTY`, and then performs ordinary partition
cleanup. A failure in SNP-state destruction currently returns early from
`destroy_partition`, leaving later cleanup undone
(`drivers/hv/mshv_root_main.c:3535-3695`).

OpenVMM cannot repair that kernel behavior, but it can:

- avoid retries after any secure/mapping/import transition;
- retain all region and VP resources until partition drop;
- log the precise launch phase that failed;
- avoid attempting ad hoc host-access rollback during drop;
- document the minimum tested kernel revision.

## Prototype assessment

### Ideas worth retaining

The historical commit demonstrates a working end-to-end shape:

- SNP-specific partition creation and properties;
- deferred memory mapping;
- a terminal launch state;
- BSP register stashing;
- VMSA construction and import;
- CPUID page population;
- batched isolated-page imports;
- `SevControl` binding;
- time freeze until the first VP run;
- VMGEXIT dispatch for GHCB-MSR, I/O, MMIO, guest request, AP creation, and
  doorbell operations.

Those are useful behavioral requirements. They should be reimplemented against
the current abstractions rather than transplanted.

### Patterns that must not be retained

1. **Raw typed-property ioctl workaround.** The prototype claimed that only
   `MSHV_SET_PARTITION_PROPERTY` marked the partition encrypted. In the current
   kernel, encryption is recorded from `pt_isolation` at creation
   (`drivers/hv/mshv_root.h:252-255`,
   `drivers/hv/mshv_root_main.c:3928-4004`). The typed handler and generic
   property hypercall both end at `hv_call_set_partition_property`
   (`drivers/hv/mshv_root_main.c:1905-1923`), while
   `mshv-ioctls` intentionally uses the generic path. Prefer the existing safe
   wrapper unless testing proves a property-specific current-kernel defect.
2. **Hardcoded RIP and environment override.** The prototype's
   `0x0010_01e1` and `OPENVMM_SNP_RIP` target a specific guest. The VMSA must
   be derived from loader-provided BSP state.
3. **Hardcoded `restrict_injection`.** `SevFeatures` must be selected from an
   explicit supported boot contract, not copied from the prototype guest.
4. **Disabled ID-block verification.** `id_block_enabled = 0` may be acceptable
   only for a clearly named bring-up mode. It must not silently define the
   production policy.
5. **Ignored IGVM directives.** Silently dropping AP VMSAs or `SnpIdBlock`
   breaks the meaning of the IGVM file.
6. **Magic GHCB offsets.** Use `x86defs::snp` layouts and `offset_of!` where
   possible, and validate all guest-provided validity bits, sizes, addresses,
   widths, and VP indices.
7. **Leaked scratch register pages.** Any fallback page must be owned by the VP
   binder/runner and dropped normally.
8. **Silent register-state discards.** MTRR/PAT/register writes before launch
   must either feed VMSA construction or return a specific unsupported-state
   error. Returning success while dropping state hides loader bugs.
9. **Per-page zero scanning.** Do not scan all RAM to infer hardware ZERO page
   imports. The current KVM path intentionally does not infer page type from
   content. Use explicit import semantics.
10. **Panics on untrusted exits.** The prototype improved one catch-all, but
    the current MSHV run loop and some existing SNP handlers still contain
    `panic!`, `assert!`, or `unimplemented!` paths. New `virt_mshv` SNP code
    must return typed errors or inject architecturally appropriate guest
    failures.
11. **Assumed secure-state transition.** Retain the prototype's transition only
    after proving it is required by the target ABI. Do not encode an
    undocumented property sequence as fact.

## Recommended design

### 1. Partition creation and capability setup

Add an x86-only SNP path to `LinuxMshv::new_partition`:

- accept only `IsolationType::Snp`; keep VBS, TDX, and CCA rejected;
- create with `MSHV_PT_ISOLATION_SNP`;
- use the SNP-compatible partition flags validated against the current kernel
  and hypervisor; do not copy the prototype's flag set without tests;
- set an explicit SNP synthetic-feature set before initialization;
- after initialization, set and validate:
  - `IsolationPolicy`;
  - `SevVmgexitOffloads`;
  - `UnimplementedMsrAction`;
  - `TimeFreeze`;
  - `ProcessorsPerSocket`;
- initialize `time_frozen` consistently with the property actually set.

Confirm whether successful import completion makes the isolation-control
runnable bit effective automatically. Teardown explicitly clears that bit only
after a completed import (`drivers/hv/mshv_root_main.c:3541-3560`), but the
current kernel source does not show the corresponding launch-side transition.
If userspace must set it, model that as a distinct validated launch phase and
property operation.

Represent the selected SNP launch policy in a small typed configuration/helper
rather than scattering bit constants. Start with the secure defaults from
`mshv_bindings::snp::get_default_snp_guest_policy`, but copy the values into an
OpenVMM-owned constructor with tests so changes in generated bindings do not
silently alter policy. The current helper enables SMT and VMPLs and disables
migration-agent and debug access
(`mshv-bindings-0.6.8/src/x86_64/snp.rs:700-716`).

### 2. Partition state and memory deferral

Add to `MshvPartitionInner` on x86:

- `isolation: IsolationType`;
- `snp_launch_state: Mutex<SnpLaunchState>`;
- memory-region state that distinguishes `Recorded`, `Mapped`, and `Unmapped`.

Keep the KVM terminal states but make the MSHV phase visible in errors/logging,
for example:

`NotStarted -> Preparing -> [Securing] -> Mapping -> Importing -> Finished`

`Securing` is conditional on the target ABI investigation. Any failure after
the first operation that revokes host access is terminal. Concurrent calls
should return `SnpLaunchInProgress`; repeated success should be idempotent;
repeated failure should return `SnpLaunchFailed` with the original phase
available through inspection/logging.

For SNP, `map_range` should validate and record the complete region but not call
`map_user_memory`. The launch path should map all recorded regions in stable GPA
order after all host writes and any required isolation-state transition.
`unmap_range` should:

- remove a recorded-only region without issuing an ioctl;
- issue exactly one unmap for a mapped region;
- reject partial overlap with a typed error rather than panic.

Do not hold the memory-state mutex across guest-memory reads/writes or ioctls
unless lock ordering is documented and no callback can re-enter the mapper.

### 3. Backend-neutral VMSA contract

The loader, not the hypervisor backend, should define the initial SNP VP
context:

- every SNP boot path emits exactly one BSP `VpContext` import containing a
  `SevVmsa`;
- the loader chooses and reserves the GPA from its own image layout;
- direct Linux boot extends the existing four-page low-memory SNP reservation
  to five pages and uses the fifth page for the VMSA
  (`vm/loader/src/linux.rs:278, 348-422, 680-702`);
- the Linux loader must newly call the existing
  `ImageLoad::set_vp_context_page` hook
  (`vm/loader/src/importer.rs:501-504`);
- an x86-specific wrapper around `vmm_core::vm_loader::Loader<X86Register>`
  implements that currently-unimplemented hook, records the chosen GPA, and
  finalizes the VMSA after all BSP register imports have been collected
  (`vmm_core/vm_loader/src/lib.rs:44-89, 178-188, 265-267`);
- the x86 loader writes the synthesized VMSA bytes into `GuestMemory` at the
  selected GPA and records that range as `BootPageAcceptance::VpContext`;
- `initial_regs_and_page_imports` converts that record into an
  `InitialPageImportType::VpContext` entry. The worker passes the complete
  import list to `PartitionUnit::accept_initial_pages`, so the virt backend
  receives the VMSA GPA and type, then reads the bytes from its existing
  `GuestMemory` mapping;
- `complete_snp_direct_ram_imports` sees that range in the import list and
  therefore does not add a duplicate `Normal` import. This exclusion is not the
  transport mechanism; the `VpContext` entry plus the bytes already written to
  guest memory are;
- no backend injects an extra VMSA page after loader completion.

This matches existing image-loader ownership:

- OpenHCL uses a fixed VMSA slot in its reserved VTL2 region
  (`vm/loader/src/paravisor.rs:822-855`);
- SNP UEFI chooses the first page after its config block and reports it as a
  permanent firmware allocation (`vm/loader/src/uefi/mod.rs:718-737`);
- `igvmfilegen` receives the chosen GPA through `set_vp_context_page`, builds
  the VMSA from imported registers, and emits the VP context at that GPA
  (`vm/loader/igvmfilegen/src/vp_context_builder/snp.rs:119-209, 315-320`).

The existing SNP VMSA builder is in the tool-oriented `igvmfilegen` crate.
Extract its reusable field conversion into an appropriate low-level loader/x86
module rather than adding an `igvmfilegen` dependency to runtime crates. The
builder configuration must make guest policy choices such as injection mode
explicit and must not retain the prototype's guest-specific RIP or environment
override.

The builder must start from the same complete architectural reset state used by
`X86InitialRegs::at_reset`, then overlay loader-imported registers. Direct Linux
does not import every VMSA field: reset values such as `rflags = 2` and the
initial IDTR/TR/LDTR state must not become zero merely because the loader did
not override them. Consistency checks between the VMSA and the register list
apply only to explicitly loader-imported fields; reset-derived values are
validated against the shared reset-state constructor.

`X86InitialRegs::at_reset` requires `X86PartitionCapabilities` and the BSP's
`X86VpInfo`, which the generic loader does not currently own. Add an explicit
`SnpVmsaBuildConfig` to the x86 Linux load configuration and populate it from
the worker layer, where partition capabilities and processor topology are
available. Pass those inputs into `X86Loader`; do not duplicate an incomplete
reset-state implementation inside the loader.

After overlaying loader imports, enforce VMSA invariants that are not ordinary
Linux register imports:

- OR `X64_EFER_SVME` into EFER;
- initialize XCR0 with at least the legacy x87 bit;
- validate MBZ fields and required SNP feature bits;
- select direct-Linux `SevFeatures` explicitly rather than inheriting
  paravisor defaults.

MSHV consumes the resulting import directly:

- validate that there is exactly one BSP VMSA;
- write/finalize it before encrypted memory is mapped;
- import it as `MSHV_ISOLATED_PAGE_VMSA`;
- bind it to the BSP through `HvX64RegisterName::SevControl`.

KVM consumes the same import indirectly:

- read and validate the `SevVmsa` before launch finish;
- translate all supported architectural fields into KVM registers, sregs,
  MSRs, XCR0, XSAVE/FPU, and available SNP VMSA feature attributes;
- treat the VMSA as authoritative for every field it represents;
- for direct Linux boot, retain the shared `at_reset` baseline and existing
  register list as sideband state for values not represented in a VMSA,
  including MTRRs, LAPIC/MSR state, and FPU/XSAVE defaults, and verify that
  explicitly imported overlapping register/VMSA values agree;
- for IGVM boot, require any non-VMSA initial state to come from an explicit
  supported IGVM mechanism or use documented architectural defaults;
- reject nonzero or required fields that KVM cannot represent instead of
  silently dropping them;
- after reading the VMSA, submit its reserved GPA as a `Normal` KVM launch
  update so the page is accepted with the rest of direct-boot RAM; it is not a
  KVM VMSA page and its contents are not used by KVM after translation;
- let KVM construct its internal VMSA from the translated vCPU state.

For KVM, the goal is that the guest starts with the behavior described by the
supplied VMSA. **Matching the IGVM expected launch measurement is explicitly
out of scope** while KVM cannot import the supplied VMSA page. KVM boot support
must not claim that an IGVM ID block or expected SNP measurement was honored
when the internally generated VMSA measurement differs.

This translation is still required even though direct Linux boot already has a
working register path: a future SNP IGVM supplies a VMSA as its initial VP
state and may not supply the current `InitialLoad.regs` representation. Direct
Linux boot should exercise the same VMSA translation path so it does not become
an untested IGVM-only code path.

The reusable builder cannot be a direct move of
`igvmfilegen::SnpHardwareContext`. That type currently assumes vTOM/shared-GPA
configuration, sets paravisor-oriented `SevFeatures`, panics on some register
variants, and ignores MTRRs. Introduce a shared, non-panicking builder with an
explicit mode/configuration:

- direct Linux without a paravisor or vTOM;
- enlightened UEFI;
- OpenHCL/paravisor.

The direct-Linux mode must preserve its MTRR imports as sideband KVM state and
must not set vTOM, restricted injection, debug-swap, or other feature bits
unless the selected guest contract requires them.

`vmm_core::vm_loader::Loader<R>` is generic, so VMSA finalization cannot be
implemented as untyped logic for every `R`, and Rust specialization cannot
override the generic consuming method. Add a concrete `X86Loader` wrapper
around `Loader<X86Register>` that implements `ImageLoad<X86Register>` by
delegation while owning the SNP VP-context builder. Its typed finalization must:

- record the GPA when the Linux loader newly calls `set_vp_context_page`;
- finalize only after all x86 register imports are collected;
- write the complete VMSA bytes to `GuestMemory`;
- add the `VpContext` import metadata without overlapping an existing import;
- return the original register collection for sideband state.

The KVM reverse conversion must exactly invert VMSA encodings, including the
packed segment-attribute representation. Round-trip tests must compare the
resulting KVM/`vp::Registers` state with the reset-plus-import source state, not
merely compare two values derived from the same VMSA.

The VP binder must not call `get_vp_reg_page().expect(...)` for SNP. Give the
runner an explicitly owned scratch/register view only if existing generic code
requires it, and ensure accesses that would incorrectly depend on it return an
error. Skip ordinary APIC register initialization that the hypervisor rejects
for encrypted VPs.

### 4. CPUID page

Do not create a new crate for this. Split the existing code along dependency
boundaries:

- move the SNP CPUID firmware-page wire definitions currently in
  `loader::cpuid` (`HV_PSP_CPUID_PAGE`, leaf layout, and the 64-entry capacity)
  into `x86defs::snp`, which is already shared by `loader`, `virt_kvm`, and
  `virt_mshv`;
- add a backend-neutral runtime serializer under `virt::x86` that accepts
  neutral `virt::CpuidLeaf`-style entries, validates the page size/count and
  reserved fields, and produces the firmware-page bytes;
- keep loader-specific required-leaf lists and placeholder-page construction
  in `loader::cpuid`;
- keep acquisition of effective CPUID values and sanitization in each
  hypervisor backend.

This avoids adding a `loader` dependency to either virt backend and avoids a
new one-function crate. Extract the backend-independent parts of KVM's tested
serializer into the `virt::x86` helper so both backends produce the same
firmware page format and enforce the same capacity and reserved-field rules.

Do not make KVM's CPUID sanitization masks backend-independent. Several masks
remove KVM-synthetic feature bits; MSHV effective CPUID values need a separately
derived and tested sanitization policy. Share only the page layout, validation,
and serialization mechanics unless a mask is proven architectural.

For MSHV, query effective BSP values through `MSHV_GET_VP_CPUID_VALUES` after
partition-wide overrides are registered. Do not use the prototype's UEFI-only
leaf list for Linux direct boot. Define and test the exact leaf set needed by
the current direct-boot contract, including subleaf enumeration and SNP
synthetic-bit sanitization.

### 5. Initial-page import

Make `VpContext` a required SNP BSP import for both KVM and MSHV.

For KVM:

1. accept exactly one BSP `VpContext` import;
2. read and validate its VMSA contents;
3. translate the supported state into the BSP KVM vCPU;
4. apply only non-VMSA sideband state, such as direct-boot MTRRs, from the
   register list;
5. reject conflicting overlapping state or unsupported required VMSA fields;
6. launch-update the `VpContext` GPA as `Normal` so the reserved RAM page is
   accepted, without treating its contents as KVM's VMSA;
7. continue with the existing KVM page updates and launch finish.

Implement `virt::AcceptInitialPages for MshvPartition` and expose it only for
SNP partitions through `Partition::supports_initial_page_acceptance`. Its
launch sequence should be:

1. acquire the one-shot launch state;
2. validate and normalize the complete import plan;
3. populate the CPUID page and validate the loader-supplied VMSA while host
   access remains;
4. if required by the validated target ABI, transition the partition to the
   secure isolation state;
5. map all deferred memory regions;
6. batch contiguous PFNs with the same MSHV page type, respecting ioctl and
   hypercall limits;
7. import normal, unmeasured, secrets, CPUID, and VMSA pages;
8. complete the isolated import with an explicit policy/ID-block choice;
9. if required by the target ABI, set isolation control runnable;
10. bind the BSP VMSA through `SevControl`;
11. mark launch finished; leave time frozen until first VP run.

`Shared` imports should remain unmapped from the isolated import operation and
must have an explicit mapping/visibility design before support is claimed.
`CpuidExtendedState` should be rejected until its MSHV representation is
confirmed. Multiple `VpContext` imports should be rejected for direct boot.

The current direct loader already adds every RAM page to the import list. Keep
that behavior for parity, but preserve its documented status as a slow
bring-up limitation rather than optimizing it through implicit ZERO-page
detection.

### 6. VMGEXIT/GHCB handling

Add `HvMessageTypeX64SevVmgexitIntercept` to the MSHV run loop. Implement a
dedicated handler with a typed error enum and no panic paths.

Minimum direct-boot functionality should be determined from the guest contract,
but likely includes:

- GHCB protocol/version and hypervisor-feature negotiation;
- GHCB GPA registration;
- port I/O;
- MMIO read/write;
- SNP guest request;
- SNP AP creation;
- doorbell page operations if restricted injection is enabled.

Use the forwarded intercept message/GHCB layout provided by the kernel rather
than assuming the prototype's exact access method. The existing OpenHCL
`virt_mshv_vtl` SNP processor is useful for shared types and validation ideas,
but its VTL/paravisor overlay model is not directly reusable
(`openhcl/virt_mshv_vtl/src/processor/snp/mod.rs:1234-1390`).

There are two possible GHCB access paths:

- the kernel-provided VP GHCB state page when
  `is_ghcb_mapping_available()` is true;
- guest-memory access through the registered shared GHCB GPA otherwise.

Select one from the target-kernel contract and test the other as unsupported or
as a fallback. Do not assume the optional state-page mapping always exists.

Every guest-controlled field must be validated before use:

- GHCB info/usage and validity bits;
- GPA alignment, shared/private visibility, and address range;
- I/O width and direction;
- MMIO length and buffer bounds;
- target VP index and VMSA GPA for AP creation;
- guest-request request/response page separation and ownership;
- doorbell operation and GPA.

Unsupported protocol operations should produce a specified GHCB error response
or a typed VP halt/fatal error, not `panic!` or `unimplemented!`. Repeated
guest-triggerable warnings must use `tracelimit`.

The required-operation inventory must explicitly consider MSR read/write,
CPUID, WBINVD, hypervisor-feature negotiation, termination request, and AP reset
hold in addition to I/O, MMIO, guest request, AP creation, and doorbell
operations. At minimum, termination must produce a deterministic VP halt
instead of falling into an unknown-exit panic.

`MSHV_IMPORT_ISOLATED_PAGES`, completion, PSP guest request, and
`HVCALL_SET_PARTITION_PROPERTY` use the partition's asynchronous-hypercall
completion state. The target kernel holds the partition `pt_mutex` across each
partition ioctl and waits for asynchronous completion before releasing it, so
these operations are already serialized at the kernel boundary. SNP AP
creation is different: its ioctl performs synchronous VP-register hypercalls
under the same `pt_mutex`. Keep runtime operations on the partition-fd ioctl
paths so this serialization remains effective, and return deterministic GHCB
errors rather than exposing kernel contention or ioctl failures as fatal exits.

### 7. Attestation and ID block

Do not conflate "guest request ioctl works" with complete attestation support.
The prototype omitted certificate data for extended guest requests and disabled
ID-block verification.

Support two explicit launch modes:

- `NoIdBlock`: complete the SNP launch without ID-block verification. Linux
  direct boot uses this mode for now.
- `IdBlock`: validate and pass a supplied SNP ID block and authentication data
  to launch completion.

Represent this as typed launch metadata, for example
`SnpIdBlockMode::None | Provided { id_block, id_auth }`, rather than a boolean
plus independently optional buffers. Extend the loader-to-backend launch
contract beyond the current page-only `AcceptInitialPages` argument so an
`InitialLoad` can carry:

- the initial page imports;
- optional SNP ID-block/authentication data;
- the SNP policy associated with that data where required.

Linux direct boot always produces `None`. The SNP IGVM loader preserves the
file semantics: `SnpIdBlock` present produces `Provided`, and absence produces
`None`. It must reject duplicate, malformed, incompatible-mask, or
policy-inconsistent ID-block directives rather than silently ignoring them.

The current direct-boot workstream should define the typed optional metadata
and implement/test both backend completion modes, but its only loader producer
is Linux direct boot with `None`. Producing `Provided` from an IGVM file belongs
to the future IGVM milestone.

MSHV must support both modes when calling `complete_isolated_import`: set
`id_block_enabled` and populate the completion data only for `Provided`.
Absence of an ID block is a supported launch mode, not an error or hidden
bring-up switch.

Extended guest request certificate retrieval should be reported unsupported
until a real certificate source and size negotiation are implemented.

KVM loading of an SNP IGVM may use the supplied VMSA to reproduce boot state,
but it cannot reproduce an IGVM measurement that assumes direct import of that
VMSA page with the current KVM UAPI. KVM can launch `NoIdBlock`; if an IGVM
contains `Provided` ID-block data whose expected measurement cannot match KVM's
internally generated VMSA, KVM must reject that launch with a clear unsupported
error rather than drop the ID block or claim verification.

### 8. Future IGVM milestone (out of current scope)

Do not implement SNP IGVM boot in this workstream, and do not add the
prototype's permissive `snp_igvm.rs` unchanged. A later, separately planned
IGVM milestone should extend the current loader so it:

- selects the SNP compatibility mask explicitly;
- imports all applicable page-data directives;
- handles or rejects every `SnpVpContext` deterministically;
- preserves optional `SnpIdBlock`/authentication data as typed launch metadata
  and passes it into launch completion when present;
- gives KVM the same parsed VMSA used by MSHV, with KVM translating it to vCPU
  state and explicitly not claiming VMSA measurement equivalence;
- rejects unsupported directives instead of debug-logging and ignoring them;
- has tests for compatibility filtering, AP contexts, ID blocks, overlap, and
  malformed files.

## Implementation work packages

### A. Establish ABI and policy helpers

- Add typed OpenVMM helpers for SNP creation flags, policy, VMGEXIT offloads,
  import page types, and `SevControl`.
- Extract a backend-neutral SNP VMSA builder/parser from the existing
  `igvmfilegen` implementation.
- Confirm the minimum supported kernel ABI/revision.
- Add compile-time layout assertions around any generated FAM or union types
  used through ioctl wrappers.
- Add unit tests for policy bits and import-type mapping.

### B. Create SNP partitions

- Remove the blanket x86 isolation rejection only for SNP.
- Add creation/property sequencing and capability errors.
- Add SNP-aware time-freeze state.
- Verify ordinary non-isolated MSHV creation remains byte-for-byte behaviorally
  unchanged.

### C. Defer and flush memory mappings

- Refactor memory range state to track recorded versus mapped regions.
- Defer SNP mapping and flush it during launch.
- Replace the current partial-overlap assertion with a typed error on this
  path.
- Add state-machine and mapping-order tests with a mockable ioctl boundary.

### D. Build and import initial state

- Extend the direct Linux SNP boot reservation from four pages to five and
  assign the fifth page to the BSP VMSA.
- Add x86-specific VP-context finalization around
  `vmm_core::vm_loader::Loader<X86Register>` using a typed `X86Loader` wrapper
  rather than generic VMSA logic for every guest register type.
- Implement `ImageLoad::set_vp_context_page` on that wrapper, generate the VMSA
  after all BSP register imports are available, and write it to guest memory.
- Plumb `X86PartitionCapabilities`, BSP `X86VpInfo`, and direct-Linux SNP
  feature policy from the worker into an `SnpVmsaBuildConfig`.
- Emit the same `VpContext` import for KVM and MSHV.
- Add KVM VMSA-to-vCPU-state translation and explicit unsupported-field
  validation.
- Preserve the complete `at_reset` baseline and direct-boot non-VMSA state
  through the existing path as sideband state, while rejecting conflicts for
  fields represented by the VMSA.
- Extract/test shared SNP CPUID serialization.
- Build a validated, sorted import plan and batch ioctl calls.
- Complete import and bind `SevControl`.
- Implement `AcceptInitialPages` exposure for MSHV SNP.

### E. Run SNP VPs

- Make VP binding work without a shared register page.
- Add safe VMGEXIT dispatch and required GHCB operations.
- Wire PSP guest request and AP creation through existing `mshv-ioctls`.
- Replace unknown-exit panic behavior for SNP with typed handling.

### F. Integration and hardening

- Add an MSHV SNP direct-boot VMM test gated on host capability.
- Validate single- and multi-vCPU boot.
- Validate attestation guest request behavior.
- Exercise malformed GHCB operations and invalid AP creation without host
  panic.
- Exercise launch failure at each phase and partition teardown.
- Measure launch time and memory overhead for the full-RAM direct-boot import.

Kernel-backed SNP tests require suitable AMD hardware, firmware, Hyper-V, and a
matching MSHV kernel. They are unlikely to provide ordinary presubmit coverage.
The merge-time safety net must therefore be the unit-testable launch planner,
state machine, VMSA/CPUID builders, import batching, and GHCB parser. Hardware
tests should run in a documented capable environment or gated pipeline and
must not be presented as the only regression protection.

#### Remote build/deploy/run harness

Add one user-facing repository-root script, tentatively
`run-mshv-snp-remote.sh`, that performs the complete developer loop:

1. restore or locate the direct-Linux test artifacts;
2. build OpenVMM locally;
3. validate that the remote host can receive and execute the test;
4. copy all artifacts atomically;
5. run the requested MSHV SNP scenarios;
6. execute guest smoke tests;
7. collect logs and return a reliable exit status;
8. clean up the exact remote process/run directory according to policy.

The default target is the SSH alias `wedson-mshv`, overridable with
`MSHV_SNP_HOST`. At the time of this report, that host is Azure Linux 3.0 with
kernel `6.6.135.mshv2-1.azl3`; `/dev/mshv` exists but is root-only, and
non-interactive `sudo` is available. The script should deploy as the SSH user
and run OpenVMM with `sudo -n`, failing clearly rather than prompting for a
password.

Use the current SNP scripts as behavioral source material:

- `copy-snp-artifacts.sh` for artifact checks and atomic `.new` replacement;
- `run-snp-openvmm.sh` for the direct-Linux OpenVMM command line;
- `run-snp-openvmm-repro.sh` for PTY handling, timeout/error recognition,
  guest-shell detection, virtio smoke tests, OpenVMM control-channel shutdown,
  and exit-code behavior;
- `run-cca-openvmm-repro.sh` for structured local log collection and robust
  process cleanup.

Do not require the developer to invoke those scripts in sequence. The new
script is the single supported entrypoint and may reuse shared helpers or
upload an internal remote runner, but it must not depend on manually prepared
remote state.

##### Local artifact and build stages

The script should resolve defaults relative to the repository root:

- OpenVMM:
  `target/x86_64-unknown-linux-musl/debug/openvmm`, produced by
  `cargo build --target x86_64-unknown-linux-musl -p openvmm`;
- direct-Linux kernel:
  the same known-working Ubuntu SNP guest kernel used by the KVM SNP repro,
  currently `vmlinuz-6.17.0-23-generic` at the repository root;
- direct-Linux initrd:
  `.packages/underhill-deps-private/x64/initrd`.

Run `cargo xflowey restore-packages` before the musl build when the restored
sysroot or packaged initrd is absent. The restored x86_64 sysroot supplies the
static libraries required by the repository's musl configuration. Do not rely
on the stale `target/vmm_tests/x64/initrd` path.

Require the known-working Ubuntu kernel to exist locally or be supplied through
`MSHV_SNP_KERNEL`; do not silently fall back to the generic packaged test
kernel until that kernel has independently demonstrated SNP guest boot.
Permit explicit overrides (`MSHV_SNP_OPENVMM`, `MSHV_SNP_KERNEL`, and
`MSHV_SNP_INITRD`) for iteration.

The musl artifact is intentional: a locally built GNU binary currently requires
GLIBC 2.39 while `wedson-mshv` provides GLIBC 2.38. The static-pie musl build
has been verified to execute on the target host.

Before copying, print the resolved artifacts, sizes, local revision/change ID,
build profile, and hashes. Fail if any artifact is missing, empty, not readable,
or if the OpenVMM binary is not executable.

##### Remote staging and minimal environment checks

Use a unique remote directory such as
`~/mshv-snp-openvmm/runs/<run-id>` so concurrent developers/runs cannot replace
each other's binary. The run ID should include a timestamp and local jj change
ID when available. Upload each artifact to a temporary name, verify its hash,
then rename it within the run directory.

Keep Bash-side checks minimal. They exist only to distinguish deployment
failures from an OpenVMM test result:

- SSH batch-mode connectivity;
- `sudo -n true`;
- `timeout` availability;
- successful creation of the unique remote run directory;
- successful artifact copy, hash verification, and execution of the copied
  binary.

Do not duplicate MSHV/SNP capability detection in Bash. OpenVMM is authoritative
for opening `/dev/mshv`, selecting the MSHV backend, creating an SNP partition,
and reporting unsupported kernel/hypervisor capabilities. Capture those errors
as the scenario result. The script may record `uname` and `/dev/mshv`
permissions in the manifest for diagnostics, but those observations must not
replace an actual OpenVMM launch.

Do not use `pkill`/`killall`. Record the exact remote OpenVMM PID and terminate
only that process tree on timeout or interruption. Because OpenVMM runs as
root, the remote runner should create a separate process group/session, record
its PGID, and clean it with `sudo -n kill -TERM -- -<pgid>`, followed by
`SIGKILL` after a bounded grace period. A local `trap` must attempt that exact
remote cleanup on normal exit, failure, Ctrl-C, and SSH loss. Preserve the
remote run directory on failure by default; remove successful runs unless
`MSHV_SNP_KEEP_REMOTE=1`.

##### Remote launch command

The uploaded runner should derive paths only from its run directory and launch
approximately:

```text
sudo -n env OPENVMM_LOG=<configured filters> timeout --foreground <seconds> \
  ./openvmm --hypervisor mshv --isolation snp --com1 console \
  --kernel ./vmlinux --initrd ./initrd -m <memory> -p <processors> \
  -c "console=ttyS0 earlyprintk=serial earlycon panic=-1" \
  <virtio block/network arguments>
```

Keep the full command line in the captured log. Defaults should match the
working KVM SNP repro where backend-independent, but use
`virt_mshv=trace,mshv=trace` filters rather than KVM filters. All memory,
processor, timeout, logging, and kernel-command-line values should be
overridable without editing the script.

##### Default scenarios and success criteria

A default invocation should run two fresh VMs sequentially:

1. one vCPU, validating partition creation, BSP VMSA import/binding, launch
   completion, and basic execution;
2. two vCPUs, validating the SNP AP-creation path in addition to the BSP path.

Support selecting a single scenario for fast iteration, for example
`--scenario bsp` or `--scenario smp`, but make `--scenario all` the documented
default. Invoke the PTY/console driver separately for each scenario; do not try
to reuse one OpenVMM or SSH PTY session for both VMs.

For each VM, require:

- no known fatal/panic/triple-fault/error marker;
- arrival at the expected initrd shell marker within the boot timeout;
- a deterministic guest marker protocol (`OVMM_SMOKE_*`);
- virtio block enumeration plus write/read verification;
- virtio network enumeration, link setup, and connectivity to the consomme
  user-mode network gateway;
- clean OpenVMM shutdown through the control prompt after success.

The script returns zero only if every selected scenario reports
`OVMM_SMOKE_ALL_PASS` and OpenVMM exits cleanly. Use distinct nonzero statuses
for preflight failure, build/deploy failure, boot timeout, matched crash marker,
smoke-test failure, and cleanup failure.

Determine pass/fail primarily from anchored `OVMM_SMOKE_*` markers and process
exit status. Free-text error matching is secondary diagnostic classification:
scope patterns to explicit fatal/panic lines, do not let incidental trace text
override `OVMM_SMOKE_ALL_PASS`, and preserve marker matching across read
boundaries. Capture full trace output regardless of the decision logic.

##### Logs and reproducibility

Write local logs under `target/mshv-snp/<run-id>/`:

- `manifest.txt`: local change ID, artifact paths/hashes, remote kernel,
  command-line options, and scenario list;
- `deploy.log`: preflight and copy operations;
- `bsp.console.log` and `smp.console.log`: complete SSH/OpenVMM/guest serial;
- `result.json` or another machine-readable summary with per-scenario result,
  duration, failure category, and remote run directory.

Never filter or truncate the captured console stream. Error matching controls
the outcome but the complete output remains available for debugging.

##### Future automated VMM-test milestone (out of current scope)

Petri/VMM-test integration is explicitly future work and is not part of this
MSHV SNP implementation workstream. The current deliverable is the SSH-based
hardware bring-up and developer-iteration harness.

After the MSHV SNP direct-boot path and remote harness are stable, a separately
planned milestone may:

- add a capability-gated MSHV SNP VMM test;
- run it through `cargo xflowey vmm-tests-run`, never raw nextest;
- reuse the same guest success markers and scenario definitions where
  practical;
- keep remote deployment as the fallback for hardware/kernel combinations not
  available in presubmit.

### G. IGVM support

- **Future milestone; not part of the current implementation workstream.**
- Implement strict SNP IGVM parsing and ID-block flow only in that later work.
- Do not make direct-boot completion or the current MSHV SNP series depend on
  this milestone.

## Test plan

### Unit tests

- MSHV import-type mapping, including explicit rejection cases.
- Launch state transitions, concurrency, idempotent success, and terminal
  failure.
- Region recording, stable flush order, unmap-before-launch, unmap-after-map,
  overlap, overflow, and alignment.
- VMSA reservation exclusion from the full-RAM import completion pass.
- VMSA construction from known BSP register fixtures.
- VMSA round-trip fixtures covering loader construction and KVM translation.
- KVM rejection tests for nonzero VMSA fields it cannot represent.
- Direct-boot tests proving MTRRs remain applied while overlapping VMSA/register
  state is checked for equality.
- VMSA builder tests proving unspecified fields retain
  `X86InitialRegs::at_reset` defaults.
- VMSA builder tests proving EFER.SVME and XCR0.x87 are present after loader
  overlays.
- Exact segment selector/attribute pack-and-unpack round-trip tests.
- KVM tests proving the reserved `VpContext` GPA is launch-updated as `Normal`.
- BSP architectural validation failure cases.
- CPUID page serialization, sanitization, subleaf handling, and entry limit.
- Distinct KVM and MSHV CPUID sanitization fixtures.
- Policy bit construction and ID-block consistency.
- GHCB parsing for every supported and unsupported operation.
- I/O/MMIO widths, GPA bounds, VP bounds, and malformed validity maps.
- Import batching at zero, one, boundary, and over-boundary counts.

### Kernel-backed tests

- Successful KVM SNP direct boot using the loader-supplied VMSA contract.
- On `wedson-mshv`, run the single-command remote harness for both the BSP and
  SMP scenarios and archive its manifest/result logs.
- Verify Linux direct boot completes in `NoIdBlock` mode.
- Verify SNP capability unavailable or `/dev/mshv` inaccessible produces a
  preflight/creation error rather than a panic.
- Verify partition creation and clean drop before launch.
- Inject failure before the first host-access-revoking transition.
- Inject failure after host access is revoked but before import completion.
- Verify successful one-vCPU direct boot.
- Verify successful two-vCPU boot using SNP AP creation.
- Verify port I/O and MMIO through the guest console and virtio devices.
- Verify guest-request attestation response separately from ID-block launch
  mode.
- Send repeated unsupported/malformed VMGEXIT input without panic or unbounded
  logging.
- Verify drop after successful launch and after each injected failure point.
- Verify timeout/Ctrl-C cleanup leaves no running OpenVMM process and preserves
  failure logs.
- Verify two unique remote run directories can be staged without artifact
  collision.

### Regression tests

- Existing non-isolated MSHV unit and VMM tests.
- Current KVM SNP direct-boot tests and CPUID tests.
- Loader SNP page-table C-bit tests.
- Cross-guest-architecture compilation using `cfg(guest_arch = "x86_64")`,
  not host `target_arch`.

## Risks and adversarial findings

| Risk | Consequence | Mitigation |
|---|---|---|
| Incorrect secure/map/import ordering | Lost host access, failed launch, or host instability | Terminal phased state machine and failure-injection tests |
| Incomplete VMSA construction or KVM translation | Immediate guest failure or backend-specific boot behavior | Mode-specific shared builder, exhaustive fixtures, reject unsupported fields |
| KVM VMSA translation drops non-VMSA direct-boot state | MTRRs or other setup regresses from current behavior | Preserve explicit sideband state and test it |
| KVM skips the reserved VMSA GPA | A hole remains unaccepted in direct-boot RAM | Read the VMSA, then import that GPA as `Normal` on KVM |
| Loader emits `VpContext` before KVM accepts it | Existing KVM SNP direct boot immediately fails | Loader emission and KVM handling are a non-splittable change |
| KVM IGVM measurement differs from supplied VMSA measurement | Attestation does not match the IGVM expectation | Explicitly out of scope; do not claim ID-block/measurement equivalence |
| Stale prototype property workaround | Unnecessary unsafe ioctl code and maintenance burden | Use current safe wrapper; verify against current kernel |
| Silent policy defaults | Debug, SMT, migration, or VMPL behavior differs from intent | OpenVMM-owned explicit policy constructor and tests |
| Guest-controlled GHCB fields | Host panic, invalid memory access, or device misuse | Typed parsing, bounds/visibility checks, no panic paths |
| Full-RAM direct import | Very slow launch and large import lists | Keep as explicit first-milestone limitation; measure; move to IGVM/guest acceptance |
| Kernel teardown early return | Leaked kernel partition resources after launch failure | Avoid retries/rollback; test supported kernel; surface phase and kernel error |
| Async hypercall serialization | `EBUSY`/failed operations or state corruption | Single launch owner; serialize import/completion/request operations |
| AP creation validation gap | Wrong VP/VMSA binding | Validate VP existence, uniqueness, alignment, import type, and lifecycle |
| ID block omitted | Attestation not bound to expected guest identity | Explicit bring-up gate or required ID-block configuration |

## Recommended change sequence

1. Add policy/import helpers and the MSHV SNP launch state.
2. Build a mode-specific shared SNP VMSA builder/parser and x86 loader
   finalization path.
3. In one atomic change, make direct Linux SNP boot emit a loader-owned
   `VpContext` page and teach KVM to consume/skip that import while preserving
   non-VMSA sideband state and accepting the reserved GPA as `Normal`.
4. Add SNP partition creation and time-freeze sequencing for MSHV.
5. Resolve secure-state, runnable-bit, and GHCB-access ABI questions against
   the target kernel.
6. Refactor MSHV memory mapping into recorded/mapped states.
7. Add CPUID serializer extraction.
8. Implement MSHV `AcceptInitialPages`, imports, completion, and `SevControl`.
9. Make MSHV VP binding work without a shared register page.
10. Add minimal, non-panicking GHCB handling needed for direct boot.
11. Add unit, kernel-backed direct-boot, and failure-path tests.
12. Harden attestation policy and extended guest request behavior.

Each step should be independently reviewable. The memory deferral and VMSA
changes should not be combined with broad IGVM loader changes. SNP IGVM boot
starts only after this workstream is complete.

## Decisions needed before implementation

1. Which VMGEXIT operations are required by the target direct-Linux guest,
   especially
   restricted injection and doorbell-page support?
2. What exact MSHV kernel revision is the compatibility floor?
3. Should the backend-neutral SNP CPUID/VMSA helpers live in `virt`, `x86defs`,
   or a new narrowly scoped shared module?
4. Which VMSA fields must the first KVM implementation reproduce, which
   nonzero unsupported fields should make launch fail, and which direct-boot
   values remain explicit sideband state?
5. Does the target ABI require a distinct `IsolationState = SECURE` property
   transition before mapping/import?
6. Is the VP GHCB state-page mapping guaranteed on the target kernel, or is
   shared guest-memory access the authoritative path?
7. Which concrete `vp_state` setters comprise the complete initial BSP state,
   and when does the backend reject further state changes?
8. Does `complete_isolated_import` make isolation control runnable
    automatically, or must OpenVMM set
    `HV_PARTITION_PROPERTY_ISOLATION_CONTROL` before first VP run?

## Review history

### Adversarial review 1

Verdict: **Minor revisions**.

The review independently verified the report's principal current-tree, crate,
and kernel claims. It required the plan to resolve or explicitly track:

- collision between a new VMSA page and the current full-RAM `Normal` fill;
- lack of current-kernel evidence for a distinct secure-state transition;
- the concrete `vp_state` interception point for BSP state;
- separation of KVM-specific CPUID sanitization from shared serialization;
- runtime contention on the single async-hypercall slot;
- GHCB access when the optional kernel state-page mapping is absent;
- minimum handling for termination and other common GHCB operations;
- the limited presubmit value of hardware-only SNP tests.

This revision incorporates those findings. A second review is required before
the plan is presented for implementation feedback.

### Adversarial review 2

Verdict: **Minor revisions**.

The second review confirmed that all first-review findings were addressed. It
added two related requirements now incorporated above:

- determine whether isolation control must be made runnable explicitly after
  import completion;
- include asynchronous partition-property hypercalls in the same
  partition-level serialization domain as import, completion, PSP request, and
  AP creation.

A final approval pass follows this revision.

### Adversarial review 3

Verdict: **Approved**.

The final review found no remaining high-confidence architecture blocker,
contradiction, or unsafe sequencing assumption. It confirmed that the genuinely
unresolved ABI questions are clearly marked as prerequisites rather than
encoded as implementation facts.

### Adversarial review 4: shared VMSA contract

Initial verdict: **Needs rework**.

The review agreed with loader-owned VMSA placement and MSHV import, but found
the first KVM translation proposal incomplete:

- direct Linux already applies `InitialLoad.regs`, including MTRRs, so the plan
  needed an explicit authority/sideband model instead of two conflicting state
  sources;
- the existing `igvmfilegen` builder is paravisor/vTOM-oriented and cannot be
  moved unchanged into direct Linux loading;
- generic `Loader<R>` cannot synthesize an x86 VMSA without an x86-specific
  finalization abstraction that also writes the bytes to guest memory;
- loader emission and KVM acceptance must land atomically because current KVM
  rejects `VpContext`.

The revised contract makes the VMSA authoritative for represented state,
preserves non-VMSA direct-boot state such as MTRRs as explicit sideband state,
requires a mode-specific non-panicking builder, specifies x86 loader
finalization, and combines loader/KVM support into one change. A follow-up
adversarial review is required.

### Adversarial review 5: shared VMSA follow-up

Verdict: **Minor revisions**.

The review accepted the authority/sideband model, IGVM rationale, mode-specific
builder, and atomic loader/KVM change. It found two remaining boot-critical
details:

- the VMSA builder must seed the full `X86InitialRegs::at_reset` state before
  overlaying loader imports, or unmentioned fields such as RFLAGS and descriptor
  state regress to zero;
- KVM must launch-update the reserved VMSA GPA as `Normal` after reading it, or
  the full-RAM direct-boot flow leaves that page unaccepted.

It also required a concrete x86 finalization mechanism rather than relying on
Rust specialization. The plan now specifies an `X86Loader` wrapper, makes the
loader/KVM change explicitly non-splittable, and adds tests for reset defaults,
MTRR sideband state, and KVM normal-page acceptance. A final adversarial
approval pass follows.

### Adversarial review 6: construction details

Verdict: **Minor revisions**.

The review confirmed the shared VMSA architecture, atomic landing, MTRR
sideband model, KVM normal-page acceptance, and measurement disclaimer. It
required four construction details now incorporated:

- plumb `X86PartitionCapabilities` and BSP `X86VpInfo` from the worker into the
  x86 VMSA builder rather than attempting an incomplete reset-state clone;
- force EFER.SVME after applying Linux register imports;
- initialize XCR0 with x87 and validate other VMSA invariants;
- test exact segment-attribute packing and reverse translation.

### Adversarial review 7: final approval

Verdict: **Approved**.

The final review found no remaining material architecture or boot-correctness
blocker. It confirmed the worker-supplied reset inputs, VMSA invariants, KVM
translation and normal-page acceptance, MSHV import, atomic landing, and
measurement disclaimer. The final clarification broadens KVM sideband state
from MTRRs alone to every reset value not represented in `SevVmsa`, including
relevant LAPIC/MSR and FPU/XSAVE defaults.

### Adversarial review 8: remote harness

Initial verdict: **Needs rework**.

The review verified the artifact-resolution and single-script approach, but
identified deployment blockers and reliability gaps. The plan now incorporates
the findings:

- build a static-pie musl OpenVMM after `restore-packages`; this build was
  verified to execute on `wedson-mshv`, while the GNU build requires GLIBC 2.39
  and the host provides 2.38;
- use the known-working Ubuntu SNP guest kernel
  `vmlinuz-6.17.0-23-generic`, now present at the repository root;
- clean the root-owned OpenVMM process through a recorded process group and
  `sudo -n kill`, never name-based process killing;
- run BSP and SMP as independent PTY sessions;
- determine success primarily from anchored smoke markers, retaining full trace
  logs without allowing incidental trace text to override success;
- describe the network check accurately as consomme gateway connectivity.

Petri/VMM-test integration remains an explicit future milestone.

## Source index

- Current KVM SNP launch:
  `vmm_core/virt_kvm/src/snp.rs`,
  `vmm_core/virt_kvm/src/arch/x86_64/snp.rs`
- Current generic import API:
  `vmm_core/virt/src/generic.rs`
- Current MSHV backend:
  `vmm_core/virt_mshv/src/lib.rs`,
  `vmm_core/virt_mshv/src/x86_64/mod.rs`,
  `vmm_core/virt_mshv/src/x86_64/vp_state.rs`
- Current Linux loader:
  `openvmm/openvmm_core/src/worker/vm_loaders/linux.rs`,
  `vm/loader/src/linux.rs`
- Existing OpenHCL SNP/VMGEXIT implementation:
  `openhcl/virt_mshv_vtl/src/processor/snp/mod.rs`,
  `openhcl/hcl/src/ioctl/snp.rs`
- MSHV kernel UAPI and implementation:
  `~/ai/leafeon/LSG-linux-rolling/include/uapi/linux/mshv.h`,
  `~/ai/leafeon/LSG-linux-rolling/drivers/hv/mshv_root.h`,
  `~/ai/leafeon/LSG-linux-rolling/drivers/hv/mshv_root_main.c`
- Historical prototype:
  <https://github.com/wedsonaf/openvmm/commit/3944f2ca7010d633e73cb6c046f2a10d27172090>
