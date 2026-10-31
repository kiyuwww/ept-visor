// ============================================================================
//  intel_vmm.cpp — Intel VT-x/EPT implementation of the abstract HV_OPERATIONS
//  interface. Everything that touches VMCS, EPT or Intel-specific VM-exit
//  state lives here. The file is self-contained apart from the declarations
//  in common.h and the page-table pool in ept_common.cpp.
// ============================================================================
#include "common.h"

// ----------------------------------------------------------------------------
//  Local forward declarations.
// ----------------------------------------------------------------------------
static NTSTATUS VmxInitialize(VOID);
static VOID     VmxTeardown(VOID);
static NTSTATUS VmxBuildIdentityMap(const HV_IDENTITY_RANGE* Ranges, ULONG Count);
static NTSTATUS VmxProtectRange(UINT64 Gpa, UINT64 Size, UINT64 Perms);
static NTSTATUS VmxSaveAndGrant(UINT64 Gpa, UINT64 Perms, UINT64* OutOriginal);
static NTSTATUS VmxRestoreEntry(UINT64 Gpa, UINT64 OriginalValue);
static NTSTATUS VmxSplitAndGetPte(UINT64 Gpa, PEPT_ENTRY* OutPte);
static VOID     VmxArmSingleStep(PPER_CPU_CONTEXT Cpu);
static VOID     VmxDisarmSingleStep(PPER_CPU_CONTEXT Cpu);
static VOID     VmxInjectException(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa);
static VOID     VmxInvalidateTlbAll(VOID);

// ----------------------------------------------------------------------------
//  The exported operations table. g_HvOps is set to this by DriverEntry when
//  the CPU vendor is GenuineIntel.
// ----------------------------------------------------------------------------
HV_OPERATIONS g_IntelOps = {
    HvVendorIntel,
    "Intel VT-x/EPT",
    VmxInitialize,
    VmxTeardown,
    VmxBuildIdentityMap,
    VmxProtectRange,
    VmxSaveAndGrant,
    VmxRestoreEntry,
    VmxSplitAndGetPte,
    VmxArmSingleStep,
    VmxDisarmSingleStep,
    VmxInjectException,
    VmxInvalidateTlbAll,
};

// ============================================================================
//  EPT internal state. Only this file ever touches it directly.
// ============================================================================
typedef struct _INTEL_EPT_CONTEXT {
    PEPT_ENTRY  Pml4;
    UINT64      Pml4Phys;
    UINT64      Eptp;
    volatile LONG Lock;          // protects every EPT modification + INVEPT
} INTEL_EPT_CONTEXT;

static INTEL_EPT_CONTEXT g_Ept = {};

// ----------------------------------------------------------------------------
//  EptAllocatePage — 4 KB sheet from the pre-allocated pool.
//  Never call MmAllocateContiguousMemory here: this is reached from
//  VmxSplitAndGetPte, which in turn is called from the VM-exit handler.
// ----------------------------------------------------------------------------
static PVOID EptAllocatePage(VOID)
{
    return HvPtPoolAlloc(NULL);
}

static UINT64 EptPhysOf(PVOID Va)
{
    return MmGetPhysicalAddress(Va).QuadPart & ~0xFFFULL;
}

// ----------------------------------------------------------------------------
//  EptMap2MB — identity-map one 2 MB region with given permissions.
//  Only used while building the identity map (PASSIVE_LEVEL).
// ----------------------------------------------------------------------------
static NTSTATUS EptMap2MB(UINT64 Gpa, UINT64 Hpa, UINT64 Flags)
{
    PEPT_ENTRY pml4e = &g_Ept.Pml4[EPT_PML4_INDEX(Gpa)];
    if (!pml4e->Fields.Read) {
        PEPT_ENTRY pdpt = (PEPT_ENTRY)EptAllocatePage();
        if (!pdpt) return STATUS_INSUFFICIENT_RESOURCES;

        pml4e->Value = 0;
        pml4e->Fields.Read     = 1;
        pml4e->Fields.Write    = 1;
        pml4e->Fields.Execute  = 1;
        pml4e->Fields.PhysAddr = EptPhysOf(pdpt) >> 12;
    }

    PEPT_ENTRY pdpt  = (PEPT_ENTRY)(pml4e->Fields.PhysAddr << 12);
    PEPT_ENTRY pdpte = &pdpt[EPT_PDPT_INDEX(Gpa)];
    if (!pdpte->Fields.Read) {
        PEPT_ENTRY pd = (PEPT_ENTRY)EptAllocatePage();
        if (!pd) return STATUS_INSUFFICIENT_RESOURCES;

        pdpte->Value = 0;
        pdpte->Fields.Read     = 1;
        pdpte->Fields.Write    = 1;
        pdpte->Fields.Execute  = 1;
        pdpte->Fields.PhysAddr = EptPhysOf(pd) >> 12;
    }

    PEPT_ENTRY pd  = (PEPT_ENTRY)(pdpte->Fields.PhysAddr << 12);
    PEPT_ENTRY pde = &pd[EPT_PD_INDEX(Gpa)];
    if (pde->Fields.Read || pde->Fields.LargePage)
        return STATUS_UNSUCCESSFUL;

    pde->Value = 0;
    pde->Fields.Read      = (Flags & EPT_PERM_READ)    ? 1 : 0;
    pde->Fields.Write     = (Flags & EPT_PERM_WRITE)   ? 1 : 0;
    pde->Fields.Execute   = (Flags & EPT_PERM_EXECUTE) ? 1 : 0;
    pde->Fields.MemType   = 6;   // Write-Back — required by SDM for RAM
    pde->Fields.LargePage = 1;
    pde->Fields.PhysAddr  = Hpa >> 12;
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  EptInitialize — allocate PML4 and build the boot-time identity map.
//  Called at PASSIVE_LEVEL after g_IdentityRanges has been populated.
// ----------------------------------------------------------------------------
static NTSTATUS EptInitialize(const HV_IDENTITY_RANGE* Ranges, ULONG Count)
{
    g_Ept.Pml4 = (PEPT_ENTRY)EptAllocatePage();
    if (!g_Ept.Pml4) return STATUS_INSUFFICIENT_RESOURCES;

    g_Ept.Pml4Phys = EptPhysOf(g_Ept.Pml4);
    g_Ept.Lock     = 0;

    for (ULONG i = 0; i < Count; i++) {
        UINT64 base = Ranges[i].Base;
        UINT64 size = Ranges[i].Size;

        // Align down / up to 2 MB. We deliberately identity-map every
        // 2 MB block that overlaps a RAM range. The extra pages at the
        // boundaries may fall on MMIO or reserved memory; in an identity
        // map that is acceptable and avoids a 4 KB page-table explosion.
        UINT64 start = base & ~0x1FFFFFULL;
        UINT64 end   = (base + size + 0x1FFFFFULL) & ~0x1FFFFFULL;

        for (UINT64 gpa = start; gpa < end; gpa += 0x200000ULL) {
            NTSTATUS st = EptMap2MB(gpa, gpa, EPT_PERM_RWX);
            if (!NT_SUCCESS(st)) return st;
        }
    }

    // EPTP layout (SDM Vol 3C 25.6.11):
    //   bits 0..2   = 3   (4-level walk)
    //   bits 3..5   = 6   (write-back)
    //   bit  6      = 1   (enable accessed/dirty)
    //   bits 12..51 = PML4 physical address
    g_Ept.Eptp = (g_Ept.Pml4Phys & 0x000FFFFFFFFFF000ULL)
               | (3ULL << 0)
               | (6ULL << 3)
               | (1ULL << 6);

    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  EptInveptSingle — single-context invalidation for the current EPTP.
//  Only flushes the LOCAL processor's translation cache. Callers that
//  change effective permissions must follow up with EptInveptBroadcast().
//  Descriptor must be 16-byte aligned (SDM Vol 3C 25.6.11).
// ----------------------------------------------------------------------------
static VOID EptInveptSingle(VOID)
{
    __declspec(align(16)) struct { UINT64 Eptp; UINT64 Reserved; } desc =
        { g_Ept.Eptp, 0 };
    _invept(1, &desc);   // 1 = single-context
}

// ----------------------------------------------------------------------------
//  EptInveptLocalAll — all-context invalidation on the current processor.
//  Since this hypervisor uses a single shared EPTP, all-context is
//  equivalent to single-context but cheaper to encode for a broadcast.
// ----------------------------------------------------------------------------
static VOID EptInveptLocalAll(VOID)
{
    __declspec(align(16)) struct { UINT64 A; UINT64 B; } desc = { 0, 0 };
    _invept(2, &desc);   // 2 = all-context
}

// ----------------------------------------------------------------------------
//  Cross-core TLB shootdown.
//
//  _invept only invalidates the processor executing it. Any EPT
//  permission change is only architecturally visible to a remote CPU
//  after that CPU has itself run INVEPT. We therefore broadcast via
//  KeGenericCallDpc: each logical CPU enters a DPC, executes a local
//  all-context INVEPT, and synchronizes before KeSignalCallDpcDone so
//  the caller only returns once every core has flushed.
//
//  Called from PASSIVE/DISPATCH_LEVEL contexts (EPT mutation helpers or
//  VMCALL teardown). The DPC routine deliberately does not touch any
//  hypervisor locks: the caller releases g_Ept.Lock before broadcasting
//  so the DPC cannot deadlock against a mutator running on another CPU.
// ----------------------------------------------------------------------------
static VOID EptInveptBroadcastDpc(
    PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    EptInveptLocalAll();

    // Wait for every other CPU to reach this point, then signal the
    // launcher that this DPC is complete.
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static VOID EptInveptBroadcast(VOID)
{
    KeGenericCallDpc(EptInveptBroadcastDpc, NULL);
}

// ----------------------------------------------------------------------------
//  Phase-1 lookup result.
// ----------------------------------------------------------------------------
typedef enum _EPT_LOOKUP_RESULT {
    EptLookupDone,
    EptLookupNeedsSplit,
    EptLookupNotMapped,
} EPT_LOOKUP_RESULT;

typedef struct _EPT_SPLIT_PLAN {
    UINT64 PageGpa;
    UINT64 PdeBaseGpa;
    UINT32 PdIndex;
    UINT64 OriginalHpa;
    UINT64 OriginalPerm;
} EPT_SPLIT_PLAN;

// Caller must hold g_Ept.Lock.
static EPT_LOOKUP_RESULT EptLookupLocked(
    UINT64 Gpa, PEPT_ENTRY* OutPte, EPT_SPLIT_PLAN* OutPlan)
{
    *OutPte = NULL;

    PEPT_ENTRY pml4e = &g_Ept.Pml4[EPT_PML4_INDEX(Gpa)];
    if (!pml4e->Fields.Read) return EptLookupNotMapped;

    PEPT_ENTRY pdpt  = (PEPT_ENTRY)(pml4e->Fields.PhysAddr << 12);
    PEPT_ENTRY pdpte = &pdpt[EPT_PDPT_INDEX(Gpa)];
    if (!pdpte->Fields.Read) return EptLookupNotMapped;

    PEPT_ENTRY pd  = (PEPT_ENTRY)(pdpte->Fields.PhysAddr << 12);
    PEPT_ENTRY pde = &pd[EPT_PD_INDEX(Gpa)];

    if (pde->Fields.LargePage) {
        OutPlan->PageGpa      = Gpa & ~0xFFFULL;
        OutPlan->PdeBaseGpa   = Gpa & ~0x1FFFFFULL;
        OutPlan->PdIndex      = EPT_PD_INDEX(Gpa);
        OutPlan->OriginalHpa  = (pde->Fields.PhysAddr << 12) & ~0x1FFFFFULL;
        OutPlan->OriginalPerm = pde->Value & (EPT_PERM_READ |
                                              EPT_PERM_WRITE |
                                              EPT_PERM_EXECUTE);
        return EptLookupNeedsSplit;
    }
    if (!pde->Fields.Read) return EptLookupNotMapped;

    PEPT_ENTRY pt = (PEPT_ENTRY)(pde->Fields.PhysAddr << 12);
    *OutPte = &pt[EPT_PT_INDEX(Gpa)];
    return EptLookupDone;
}

// ----------------------------------------------------------------------------
//  VmxSplitAndGetPteInternal — one attempt of the deadlock-safe split.
//
//  Phase 1 (locked)   : probe, decide if a split is needed.
//  Phase 2 (unlocked) : pop a 4 KB PT from the pre-allocated pool.
//  Phase 3 (locked)   : re-verify the PDE, commit, INVEPT.
//
//  HvPtPoolAlloc never blocks. If the pool is exhausted this returns
//  STATUS_INSUFFICIENT_RESOURCES; the VM-exit handler must then inject
//  #PF (never call a blocking allocator).
//
//  Returns STATUS_RETRY to indicate a benign race with another CPU that
//  must be retried by the caller.
// ----------------------------------------------------------------------------
static NTSTATUS VmxSplitAndGetPteInternal(UINT64 Gpa, PEPT_ENTRY* OutPte)
{
    EPT_SPLIT_PLAN    plan   = {};
    PEPT_ENTRY        pte    = NULL;
    EPT_LOOKUP_RESULT result;

    // -------- Phase 1: probe under lock --------
    SpinAcquire(&g_Ept.Lock);
    result = EptLookupLocked(Gpa, &pte, &plan);
    SpinRelease(&g_Ept.Lock);

    if (result == EptLookupDone) {
        if (OutPte) *OutPte = pte;
        return STATUS_SUCCESS;
    }
    if (result != EptLookupNeedsSplit) return STATUS_UNSUCCESSFUL;

    // -------- Phase 2: pop a PT from the pre-allocated pool --------
    PEPT_ENTRY newPt = (PEPT_ENTRY)HvPtPoolAlloc(NULL);
    if (!newPt) return STATUS_INSUFFICIENT_RESOURCES;

    // Replicate the original 2 MB mapping as 512 4 KB PTEs.
    // MemType = 6 (Write-Back) is mandatory for RAM; zero would make
    // the CPU treat the page as uncached and trigger an EPT misconfig
    // on some microarchitectures.
    for (UINT32 i = 0; i < 512; i++) {
        newPt[i].Value = 0;
        newPt[i].Fields.Read      = (plan.OriginalPerm & EPT_PERM_READ)    ? 1 : 0;
        newPt[i].Fields.Write     = (plan.OriginalPerm & EPT_PERM_WRITE)   ? 1 : 0;
        newPt[i].Fields.Execute   = (plan.OriginalPerm & EPT_PERM_EXECUTE) ? 1 : 0;
        newPt[i].Fields.MemType   = 6;   // WB
        newPt[i].Fields.PhysAddr  = (plan.OriginalHpa +
                                     (UINT64)i * PAGE_SIZE) >> 12;
    }

    // -------- Phase 3: commit under lock, re-verify --------
    SpinAcquire(&g_Ept.Lock);

    PEPT_ENTRY pml4e = &g_Ept.Pml4[EPT_PML4_INDEX(plan.PageGpa)];
    PEPT_ENTRY pdpt  = pml4e->Fields.Read
                     ? (PEPT_ENTRY)(pml4e->Fields.PhysAddr << 12) : NULL;
    PEPT_ENTRY pdpte = pdpt ? &pdpt[EPT_PDPT_INDEX(plan.PageGpa)] : NULL;
    PEPT_ENTRY pd    = (pdpte && pdpte->Fields.Read)
                     ? (PEPT_ENTRY)(pdpte->Fields.PhysAddr << 12) : NULL;
    PEPT_ENTRY pde   = pd ? &pd[plan.PdIndex] : NULL;

    if (!pde || !pde->Fields.Read) {
        HvPtPoolFree(newPt);
        SpinRelease(&g_Ept.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    if (!pde->Fields.LargePage) {
        // Another CPU already split this 2 MB page. Use its PT and free ours.
        PEPT_ENTRY existingPt  = (PEPT_ENTRY)(pde->Fields.PhysAddr << 12);
        PEPT_ENTRY existingPte = &existingPt[EPT_PT_INDEX(plan.PageGpa)];

        UINT64 existingHpa = (existingPte->Fields.PhysAddr << 12) & ~0xFFFULL;
        UINT64 expectedHpa = plan.OriginalHpa +
                             (UINT64)EPT_PT_INDEX(plan.PageGpa) * PAGE_SIZE;
        if (existingHpa != expectedHpa) {
            HvPtPoolFree(newPt);
            SpinRelease(&g_Ept.Lock);
            return STATUS_RETRY;
        }

        if (OutPte) *OutPte = existingPte;
        HvPtPoolFree(newPt);
        // The split mapping is functionally identical to the original
        // 2 MB entry: this CPU only needs a local flush to see it.
        EptInveptSingle();
        SpinRelease(&g_Ept.Lock);
        return STATUS_SUCCESS;
    }

    // Still large — validate the HPA is what phase 1 saw.
    UINT64 currentHpa = (pde->Fields.PhysAddr << 12) & ~0x1FFFFFULL;
    if (currentHpa != plan.OriginalHpa) {
        HvPtPoolFree(newPt);
        SpinRelease(&g_Ept.Lock);
        return STATUS_RETRY;
    }

    // Commit: point the PDE at our PT.
    pde->Value = 0;
    pde->Fields.Read      = 1;
    pde->Fields.Write     = 1;
    pde->Fields.Execute   = 1;
    pde->Fields.LargePage = 0;
    pde->Fields.PhysAddr  = EptPhysOf(newPt) >> 12;

    if (OutPte) *OutPte = &newPt[EPT_PT_INDEX(plan.PageGpa)];

    EptInveptSingle();
    SpinRelease(&g_Ept.Lock);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  VmxSplitAndGetPte — bounded retry wrapper.
//
//  Multithreaded splits may race and produce STATUS_RETRY. Absorb that
//  entirely inside the allocator so callers always receive a definitive
//  STATUS_SUCCESS or a hard failure.
// ----------------------------------------------------------------------------
static NTSTATUS VmxSplitAndGetPte(UINT64 Gpa, PEPT_ENTRY* OutPte)
{
    for (ULONG attempt = 0; attempt < 5; attempt++) {
        NTSTATUS st = VmxSplitAndGetPteInternal(Gpa, OutPte);
        if (st != STATUS_RETRY) return st;
    }
    return STATUS_UNSUCCESSFUL;
}

// ----------------------------------------------------------------------------
//  VmxProtectRange — set permissions on a 4 KB-aligned GPA range.
//  Modifications are applied per-page under the EPT lock with a local
//  INVEPT; a single cross-core broadcast flushes remote TLBs once the
//  whole range has been rewritten.
// ----------------------------------------------------------------------------
static NTSTATUS VmxProtectRange(UINT64 Gpa, UINT64 Size, UINT64 Perms)
{
    if ((Gpa & 0xFFF) || (Size & 0xFFF) || Size == 0)
        return STATUS_INVALID_PARAMETER;

    for (UINT64 p = Gpa; p < Gpa + Size; p += PAGE_SIZE) {
        PEPT_ENTRY pte = NULL;
        NTSTATUS st = VmxSplitAndGetPte(p, &pte);
        if (!NT_SUCCESS(st)) return st;
        if (!pte) return STATUS_UNSUCCESSFUL;

        SpinAcquire(&g_Ept.Lock);
        pte->Fields.Read    = (Perms & EPT_PERM_READ)    ? 1 : 0;
        pte->Fields.Write   = (Perms & EPT_PERM_WRITE)   ? 1 : 0;
        pte->Fields.Execute = (Perms & EPT_PERM_EXECUTE) ? 1 : 0;
        if (pte->Fields.Write) pte->Fields.Read = 1;   // W implies R
        EptInveptSingle();
        SpinRelease(&g_Ept.Lock);
    }

    // Remote CPUs still hold the pre-change translations in their TLBs.
    // Broadcast an all-context INVEPT across every logical processor.
    EptInveptBroadcast();
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  VmxSaveAndGrant — atomically OR permission bits into an EPT entry and
//  return the previous value so the caller can restore it on the next exit.
//  Broadcasts after the mutation to flush remote TLBs.
// ----------------------------------------------------------------------------
static NTSTATUS VmxSaveAndGrant(UINT64 Gpa, UINT64 Perms, UINT64* OutOriginal)
{
    UINT64 pageGpa = Gpa & ~0xFFFULL;

    PEPT_ENTRY pte = NULL;
    NTSTATUS st = VmxSplitAndGetPte(pageGpa, &pte);
    if (!NT_SUCCESS(st)) return st;
    if (!pte) return STATUS_UNSUCCESSFUL;

    SpinAcquire(&g_Ept.Lock);

    // Re-walk defensively in case the entry moved.
    PEPT_ENTRY live = NULL;
    EPT_SPLIT_PLAN dummy = {};
    if (EptLookupLocked(pageGpa, &live, &dummy) != EptLookupDone || !live) {
        SpinRelease(&g_Ept.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    if (OutOriginal) *OutOriginal = live->Value;

    if (Perms & EPT_PERM_READ)    live->Fields.Read    = 1;
    if (Perms & EPT_PERM_WRITE) { live->Fields.Write   = 1; live->Fields.Read = 1; }
    if (Perms & EPT_PERM_EXECUTE) live->Fields.Execute = 1;

    EptInveptSingle();
    SpinRelease(&g_Ept.Lock);

    // Permission change must be visible to every core before we return.
    EptInveptBroadcast();
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  VmxRestoreEntry — write back a previously saved EPT entry value.
//  Called from the MTF handler; broadcast is required so that any CPU
//  which observed the granted permission sees the original value.
// ----------------------------------------------------------------------------
static NTSTATUS VmxRestoreEntry(UINT64 Gpa, UINT64 OriginalValue)
{
    UINT64 pageGpa = Gpa & ~0xFFFULL;

    SpinAcquire(&g_Ept.Lock);

    PEPT_ENTRY live = NULL;
    EPT_SPLIT_PLAN dummy = {};
    if (EptLookupLocked(pageGpa, &live, &dummy) != EptLookupDone || !live) {
        SpinRelease(&g_Ept.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    live->Value = OriginalValue;
    EptInveptSingle();
    SpinRelease(&g_Ept.Lock);

    EptInveptBroadcast();
    return STATUS_SUCCESS;
}

// ============================================================================
//  Segment and descriptor-table helpers
// ============================================================================

// Extract the 64-bit base from a long-mode system descriptor (SDM Vol 3A 3.4.5).
static UINT64 SegmentDescriptorBase64(const SEGMENT_DESCRIPTOR64* d)
{
    UINT64 base = 0;
    base |= (UINT64)d->Base15_0;
    base |= (UINT64)d->Base23_16 << 16;
    base |= (UINT64)d->Base31_24 << 24;
    base |= (UINT64)d->Base63_32 << 32;
    return base;
}

// There is no architectural MSR for IA32_TR_BASE on Intel. Walk the GDT at
// the selector returned by STR. Returns 0 on failure.
static UINT64 ReadTssBase(VOID)
{
    DESCRIPTOR_TABLE_REGISTER64 gdtr = {};
    __sgdt(&gdtr);

    UINT16 trSelector = VmxReadTr();
    if (trSelector & 0x4) return 0;   // LDT-based, unsupported

    UINT32 offset = trSelector & ~0x7;
    if ((UINT64)offset + sizeof(SEGMENT_DESCRIPTOR64) > gdtr.Limit + 1ULL)
        return 0;

    const SEGMENT_DESCRIPTOR64* desc =
        (const SEGMENT_DESCRIPTOR64*)(gdtr.Base + offset);
    return SegmentDescriptorBase64(desc);
}

// Build the VMCS Access Rights (AR) value from a standard descriptor.
// This matches KVM's vmx_segment_access_rights().
static UINT32 BuildAccessRights(
    UINT8 Type, UINT8 S, UINT8 Dpl, UINT8 Present,
    UINT8 Avl, UINT8 L, UINT8 Db, UINT8 G)
{
    UINT32 ar = 0;
    ar |= (Type & 0xF);
    ar |= (S & 1) << 4;
    ar |= (Dpl & 3) << 5;
    ar |= (Present & 1) << 7;
    ar |= (Avl & 1) << 12;
    ar |= (L & 1) << 13;
    ar |= (Db & 1) << 14;
    ar |= (G & 1) << 15;
    return ar;
}

// Write a complete guest segment (selector, base, limit, AR).
static VOID VmxSetupGuestSegment(
    UINT64 SelectorField, UINT64 BaseField, UINT64 LimitField, UINT64 ArField,
    UINT16 Selector, UINT64 Base, UINT32 Limit, UINT32 Ar)
{
    VmWrite16(SelectorField, Selector);
    VmWrite64(BaseField, Base);
    VmWrite32(LimitField, Limit);
    VmWrite32(ArField, Ar);
}

// ============================================================================
//  VmxInitializeVmcs — full VMCS programming for a single logical processor.
// ============================================================================
static NTSTATUS VmxInitializeVmcs(PPER_CPU_CONTEXT Cpu)
{
    // ---- 1. Stamp Revision ID onto both regions before clear/ptrld ----
    // SDM Vol 3C 24.11.5: the 31-bit revision identifier must be written
    // to bits 30:0 of the first 4 bytes of the VMXON region and the VMCS
    // region. The CPU never writes this field.
    UINT64 vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    UINT32 revisionId = (UINT32)(vmxBasic & 0x7FFFFFFF);

    *(UINT32*)Cpu->VmxonVa = revisionId;
    *(UINT32*)Cpu->VmcsVa  = revisionId;

    if (__vmx_vmclear(&Cpu->VmcsPa) != 0) return STATUS_UNSUCCESSFUL;
    if (__vmx_vmptrld(&Cpu->VmcsPa) != 0) return STATUS_UNSUCCESSFUL;

    // ---- 2. MSR bitmap: 4 KB all-zero page ----
    PVOID msrBitmap = MmAllocateContiguousMemorySpecifyCacheNode(
        PAGE_SIZE,
        (PHYSICAL_ADDRESS) { 0 },
        (PHYSICAL_ADDRESS) { MAXULONG64 },
        (PHYSICAL_ADDRESS) { 0 },
        MmCached,
        MM_ANY_NODE_OK);
    if (!msrBitmap) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(msrBitmap, PAGE_SIZE);
    Cpu->MsrBitmapVa = msrBitmap;
    Cpu->MsrBitmapPa = MmGetPhysicalAddress(msrBitmap).QuadPart & ~0xFFFULL;
    VmWrite64(VMCS_MSR_BITMAP, Cpu->MsrBitmapPa);

    // ---- 3. Pin-based controls ----
    UINT32 pinCtl = 0;
    VmxAdjustControls(&pinCtl, MSR_IA32_VMX_PINBASED_CTLS);
    VmWrite32(VMCS_PIN_BASED_CTLS, pinCtl);

    // ---- 4. Primary processor-based controls ----
    // Only EPT and MSR bitmap; no CR3/DR/HLT/MWAIT trapping because we
    // do not emulate them — trapping them without emulation causes an
    // infinite VM-exit loop.
    UINT32 procCtl = CPU_BASED_USE_MSR_BITMAPS
                   | CPU_BASED_ACTIVATE_SECONDARY;
    VmxAdjustControls(&procCtl, MSR_IA32_VMX_PROCBASED_CTLS);
    VmWrite32(VMCS_PROC_BASED_CTLS, procCtl);

    // ---- 5. Secondary controls: enable EPT ----
    UINT32 procCtl2 = CPU_BASED2_ENABLE_EPT;
    VmxAdjustControls(&procCtl2, MSR_IA32_VMX_PROCBASED_CTLS2);
    if (!(procCtl2 & CPU_BASED2_ENABLE_EPT))
        return STATUS_NOT_SUPPORTED;
    VmWrite32(VMCS_PROC_BASED_CTLS2, procCtl2);

    // ---- 6. Exit controls ----
    // PAT/EFER must round-trip through their VMCS fields on both
    // transitions. Otherwise guest changes to PAT (WC/PAT semantics) or
    // EFER (SCE/NXE/LMSLE) silently leak into the host on VM exit and
    // corrupt host paging or SYSCALL state.
    UINT32 exitCtl = VM_EXIT_HOST_ADDR_SPACE_SIZE
                   | VM_EXIT_ACK_INTR_ON_EXIT
                   | VM_EXIT_LOAD_IA32_PAT
                   | VM_EXIT_LOAD_IA32_EFER;
    VmxAdjustControls(&exitCtl, MSR_IA32_VMX_EXIT_CTLS);
    VmWrite32(VMCS_EXIT_CTLS, exitCtl);

    // ---- 7. Entry controls ----
    UINT32 entryCtl = VM_ENTRY_IA32E_MODE
                    | VM_ENTRY_LOAD_IA32_PAT
                    | VM_ENTRY_LOAD_IA32_EFER;
    VmxAdjustControls(&entryCtl, MSR_IA32_VMX_ENTRY_CTLS);
    VmWrite32(VMCS_ENTRY_CTLS, entryCtl);

    // ---- 8. VMCS link pointer: invalid (no VMCS shadowing) ----
    // SDM Vol 3C 22.3.1.5; KVM uses -1ull.
    VmWrite64(VMCS_VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFULL);

    // ---- 9. EPTP ----
    VmWrite64(VMCS_EPTP, g_Ept.Eptp);

    // ---- 10. Guest CR0 / CR4 with Intel fixed-bit masks ----
    UINT64 cr0Fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    UINT64 cr0Fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    UINT64 cr0 = __readcr0();
    cr0 |=  cr0Fixed0;          // mandatory 1 bits
    cr0 &=  cr0Fixed1;          // mandatory 0 bits
    VmWrite64(VMCS_GUEST_CR0, cr0);

    UINT64 cr4Fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
    UINT64 cr4Fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);
    UINT64 cr4 = __readcr4() | X86_CR4_VMXE;
    cr4 |=  cr4Fixed0;
    cr4 &=  cr4Fixed1;
    VmWrite64(VMCS_GUEST_CR4, cr4);

    VmWrite64(VMCS_GUEST_CR3, __readcr3());

    // GUEST_DR7: mirror the live debug-control register. Some fuzzers
    // and debuggers run with non-default DR7 settings; syncing avoids
    // any post-launch DR-access inconsistency.
    VmWrite64(VMCS_GUEST_DR7, __readdr(7));

    // ---- 11. GUEST_IA32_EFER / PAT — synchronize with live host MSRs ----
    // LMA and LME must be consistent with CR0.PG and CR4.PAE; since we
    // are mirroring the current OS state, the live MSR is correct.
    // Both fields are only touched when the corresponding load control
    // is actually supported on this CPU.
    UINT64 efer = __readmsr(MSR_IA32_EFER);
    UINT64 pat  = __readmsr(MSR_IA32_PAT);
    if (entryCtl & VM_ENTRY_LOAD_IA32_EFER)
        VmWrite64(VMCS_GUEST_IA32_EFER, efer);
    if (entryCtl & VM_ENTRY_LOAD_IA32_PAT)
        VmWrite64(VMCS_GUEST_IA32_PAT, pat);

    // ---- 12. Guest segment state ----
    // In long mode CS/SS/DS/ES bases are 0 and limits are 0xFFFFFFFF.
    // Access rights: CS = 0x9B, SS/DS/ES = 0x93 (KVM defaults).
    // FS/GS bases come from the respective MSRs.
    DESCRIPTOR_TABLE_REGISTER64 gdtr = {};
    DESCRIPTOR_TABLE_REGISTER64 idtr = {};
    __sgdt(&gdtr);
    __sidt(&idtr);

    UINT64 trBase = ReadTssBase();
    if (trBase == 0) return STATUS_UNSUCCESSFUL;

    // CS: L=1, D=0, P=1, DPL=0, S=1, Type=0xB (execute/read, accessed)
    UINT32 csAr = BuildAccessRights(0xB, 1, 0, 1, 0, 1, 0, 1);
    VmxSetupGuestSegment(VMCS_GUEST_CS_SEL, VMCS_GUEST_CS_BASE,
                         VMCS_GUEST_CS_LIMIT, VMCS_GUEST_CS_AR,
                         0x08, 0, 0xFFFFFFFF, csAr);

    // SS: D=1, P=1, DPL=0, S=1, Type=0x3 (data read/write, accessed)
    UINT32 ssAr = BuildAccessRights(0x3, 1, 0, 1, 0, 0, 1, 1);
    VmxSetupGuestSegment(VMCS_GUEST_SS_SEL, VMCS_GUEST_SS_BASE,
                         VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_AR,
                         0x10, 0, 0xFFFFFFFF, ssAr);

    // DS/ES: same as SS in long mode.
    VmxSetupGuestSegment(VMCS_GUEST_DS_SEL, VMCS_GUEST_DS_BASE,
                         VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_AR,
                         0x18, 0, 0xFFFFFFFF, ssAr);
    VmxSetupGuestSegment(VMCS_GUEST_ES_SEL, VMCS_GUEST_ES_BASE,
                         VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_AR,
                         0x20, 0, 0xFFFFFFFF, ssAr);

    // FS/GS: base from MSRs.
    UINT64 fsBase = __readmsr(MSR_IA32_FS_BASE);
    UINT64 gsBase = __readmsr(MSR_IA32_GS_BASE);
    VmxSetupGuestSegment(VMCS_GUEST_FS_SEL, VMCS_GUEST_FS_BASE,
                         VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_AR,
                         0x28, fsBase, 0xFFFFFFFF, ssAr);
    VmxSetupGuestSegment(VMCS_GUEST_GS_SEL, VMCS_GUEST_GS_BASE,
                         VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_AR,
                         0x30, gsBase, 0xFFFFFFFF, ssAr);

    // LDTR: unusable in long mode (AR bit 16 = unusable), selector/base 0.
    VmWrite16(VMCS_GUEST_LDTR_SEL, 0);
    VmWrite64(VMCS_GUEST_LDTR_BASE, 0);
    VmWrite32(VMCS_GUEST_LDTR_LIMIT, 0);
    VmWrite32(VMCS_GUEST_LDTR_AR, 0x10000);   // unusable

    // TR: base from the GDT walk; limit 0x67 (64-bit TSS), AR 0x8B.
    VmWrite16(VMCS_GUEST_TR_SEL, VmxReadTr());
    VmWrite64(VMCS_GUEST_TR_BASE, trBase);
    VmWrite32(VMCS_GUEST_TR_LIMIT, 0x67);
    VmWrite32(VMCS_GUEST_TR_AR, BuildAccessRights(0xB, 0, 0, 1, 0, 0, 0, 0));

    // GDTR / IDTR: mirror the live host tables.
    VmWrite64(VMCS_GUEST_GDTR_BASE, gdtr.Base);
    VmWrite32(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
    VmWrite64(VMCS_GUEST_IDTR_BASE, idtr.Base);
    VmWrite32(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);

    // SYSENTER state: SYSENTER_CS must be copied from the live MSR to
    // satisfy VMLAUNCH consistency checks. SYSENTER_ESP / _EIP must be
    // written explicitly (zero) even though a 64-bit guest will use
    // SYSCALL — VMLAUNCH validates these as required writable fields.
    VmWrite32(VMCS_GUEST_SYSENTER_CS, (UINT32)__readmsr(MSR_IA32_SYSENTER_CS));
    VmWrite64(VMCS_GUEST_SYSENTER_ESP, 0);
    VmWrite64(VMCS_GUEST_SYSENTER_EIP, 0);

    // RFLAGS: preserve the live flag state but mask out reserved bits.
    // Bit 1 is reserved and must be forced to 1 per Intel architecture.
    // Bits 3, 5, 15, 22..63 are reserved and must be zero.
    UINT64 rflags = __readeflags() & 0x3F7FD5ULL;
    rflags |= 0x2ULL;
    VmWrite64(VMCS_GUEST_RFLAGS, rflags);

    // ---- 13. Host state ----
    VmWrite64(VMCS_HOST_CR0, __readcr0());
    VmWrite64(VMCS_HOST_CR3, __readcr3());
    VmWrite64(VMCS_HOST_CR4, __readcr4() | X86_CR4_VMXE);

    // PAT / EFER host fields, only when the corresponding exit load
    // controls were successfully negotiated by VmxAdjustControls.
    if (exitCtl & VM_EXIT_LOAD_IA32_PAT)
        VmWrite64(VMCS_HOST_IA32_PAT, pat);
    if (exitCtl & VM_EXIT_LOAD_IA32_EFER)
        VmWrite64(VMCS_HOST_IA32_EFER, efer);

    VmWrite16(VMCS_HOST_CS_SEL, __readcs());
    VmWrite16(VMCS_HOST_SS_SEL, __readss());
    VmWrite16(VMCS_HOST_DS_SEL, __readds());
    VmWrite16(VMCS_HOST_ES_SEL, __reades());
    VmWrite16(VMCS_HOST_FS_SEL, __readfs());
    VmWrite16(VMCS_HOST_GS_SEL, __readgs());
    VmWrite16(VMCS_HOST_TR_SEL, VmxReadTr());

    VmWrite64(VMCS_HOST_FS_BASE, fsBase);
    VmWrite64(VMCS_HOST_GS_BASE, gsBase);
    VmWrite64(VMCS_HOST_TR_BASE, trBase);
    VmWrite64(VMCS_HOST_GDTR_BASE, gdtr.Base);
    VmWrite64(VMCS_HOST_IDTR_BASE, idtr.Base);

    // Host SYSENTER state must be initialized for symmetry even though
    // the host runs in long mode; leaving stale zeroes can trip
    // VM-entry checks on some microarchitectures.
    VmWrite32(VMCS_HOST_SYSENTER_CS, (UINT32)__readmsr(MSR_IA32_SYSENTER_CS));
    VmWrite64(VMCS_HOST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    VmWrite64(VMCS_HOST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    VmWrite64(VMCS_HOST_RSP, Cpu->HostStackTop);
    VmWrite64(VMCS_HOST_RIP, (UINT64)VmxVmExitEntry);

    // CR masks: allow the guest to change benign bits without exit.
    VmWrite64(VMCS_CR0_GUEST_HOST_MASK, X86_CR0_PE | X86_CR0_NE | X86_CR0_PG);
    VmWrite64(VMCS_CR4_GUEST_HOST_MASK, X86_CR4_PAE);

    return STATUS_SUCCESS;
}

// ============================================================================
//  Per-CPU bring-up
// ============================================================================
static NTSTATUS VmxSetupCurrentCpu(PVOID /*Context*/)
{
    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu) return STATUS_UNSUCCESSFUL;

    __writecr4(__readcr4() | X86_CR4_VMXE);

    UINT64 vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    UINT32 revisionId = (UINT32)(vmxBasic & 0x7FFFFFFF);
    *(UINT32*)cpu->VmxonVa = revisionId;

    if (__vmx_vmxon(&cpu->VmxonPa) != 0) return STATUS_UNSUCCESSFUL;
    if (!NT_SUCCESS(VmxInitializeVmcs(cpu))) {
        __vmx_vmxoff();
        return STATUS_UNSUCCESSFUL;
    }

    // cpu->Launched is deliberately NOT set here. A CPU that has
    // completed VMXON + VMCS setup is not yet running guest code: the
    // flag is used to gate VMCALL-based teardown, and VMCALL from root
    // mode would fault. The flag is only raised after VMLAUNCH succeeds
    // (see VmxLaunchCurrentCpu).
    return STATUS_SUCCESS;
}

static NTSTATUS VmxLaunchCurrentCpu(VOID)
{
    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu) return STATUS_UNSUCCESSFUL;

    UINT8 err = VmxLaunch();
    if (err != 0) {
        UINT32 vmcsErr = VmRead32(VMCS_VM_INSTRUCTION_ERROR);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[HV] VMLAUNCH failed on CPU %u: err=0x%X vmcs_err=0x%X\n",
            cpu->CpuIndex, err, vmcsErr);

        // Bare-metal recovery on this core: discard the VMCS, leave VMX
        // operation and clear CR4.VMXE so this processor can continue
        // executing normally. Without this path, a partial multi-CPU
        // launch leaves the failed CPU in an undefined root state.
        __vmx_vmclear(&cpu->VmcsPa);
        __vmx_vmxoff();
        __writecr4(__readcr4() & ~X86_CR4_VMXE);
        return STATUS_UNSUCCESSFUL;
    }

    // Transition to guest context succeeded. Mark the CPU as live so
    // teardown paths will VMCALL it back to root.
    cpu->Launched = TRUE;
    return STATUS_SUCCESS;
}

// ============================================================================
//  Teardown
//
//  VMCALL is the only safe way to step down from guest mode. The exit
//  handler (vmexit.cpp) dispatches HV_HYPERCALL_TEARDOWN to
//  IntelHandleTeardownVmcall(), which executes VMCLEAR, INVVPID all-context,
//  VMXOFF and clears CR4.VMXE in root mode.
// ============================================================================
#define HV_HYPERCALL_TEARDOWN  0x48566D78ULL   // 'HVmx'

// Executed in root mode inside the VMCALL exit handler.
NTSTATUS IntelHandleTeardownVmcall(PPER_CPU_CONTEXT Cpu)
{
    if (!Cpu || !Cpu->Launched) return STATUS_SUCCESS;

    // 1. VMCLEAR — flush VMCS state to memory (SDM 24.11.5).
    __vmx_vmclear(&Cpu->VmcsPa);

    // 2. INVVPID all-context — flush cached VPID translations.
    //    SDM recommends this immediately before VMXOFF.
    __declspec(align(16)) struct { UINT64 A; UINT64 B; } invvpidDesc = { 0, 0 };
    _invvpid(2, &invvpidDesc);   // 2 = all-context

    // 3. Leave VMX operation.
    __vmx_vmxoff();

    // 4. Clear CR4.VMXE.
    __writecr4(__readcr4() & ~X86_CR4_VMXE);

    Cpu->Launched = FALSE;
    return STATUS_SUCCESS;
}

static VOID VmxTeardownDpc(
    PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu || !cpu->Launched) return;

    // Execute VMCALL. The exit handler will run IntelHandleTeardownVmcall
    // in root mode and step this CPU down to bare metal.
    UINT64 status = __vmx_vmcall(HV_HYPERCALL_TEARDOWN, 0, 0);
    if (status != 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[HV] VMCALL teardown failed on CPU %u: 0x%llX\n",
            cpu->CpuIndex, status);
    }
}

static VOID VmxTeardown(VOID)
{
    InterlockedExchange(&g_ShuttingDown, 1);

    // Iterate strictly over the static boot-time CPU count. Runtime
    // hot-plug processors are intentionally NOT touched here: they were
    // never brought up under this hypervisor and their per-CPU context
    // does not exist in g_PerCpu.
    ULONG count = g_CpuCount;

    for (ULONG i = 0; i < count; i++) {
        PROCESSOR_NUMBER pn;
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) continue;

        GROUP_AFFINITY aff = {};
        aff.Group = pn.Group;
        aff.Mask  = 1ULL << pn.Number;
        GROUP_AFFINITY old = {};
        KeSetSystemGroupAffinityThread(&aff, &old);
        VmxTeardownDpc(NULL, NULL, NULL, NULL);
        KeRevertToUserGroupAffinityThread(&old);
    }

    // Free per-CPU resources. Use the exact matching deallocator for each
    // allocation API.
    if (g_PerCpu) {
        for (ULONG i = 0; i < g_CpuCount; i++) {
            if (g_PerCpu[i].MsrBitmapVa) {
                MmFreeContiguousMemory(g_PerCpu[i].MsrBitmapVa);
                g_PerCpu[i].MsrBitmapVa = NULL;
            }
            if (g_PerCpu[i].HostStack) {
                ExFreePoolWithTag(g_PerCpu[i].HostStack, 'HvSt');
                g_PerCpu[i].HostStack = NULL;
            }
            if (g_PerCpu[i].VmcsVa) {
                MmFreeContiguousMemory(g_PerCpu[i].VmcsVa);
                g_PerCpu[i].VmcsVa = NULL;
            }
            if (g_PerCpu[i].VmxonVa) {
                MmFreeContiguousMemory(g_PerCpu[i].VmxonVa);
                g_PerCpu[i].VmxonVa = NULL;
            }
        }
        ExFreePoolWithTag(g_PerCpu, 'HvC0');
        g_PerCpu = NULL;
    }

    // Free committed EPT page tables before draining the pool.
    if (g_Ept.Pml4) {
        for (UINT32 pml4i = 0; pml4i < 512; pml4i++) {
            PEPT_ENTRY pml4e = &g_Ept.Pml4[pml4i];
            if (!pml4e->Fields.Read) continue;

            PEPT_ENTRY pdpt = (PEPT_ENTRY)(pml4e->Fields.PhysAddr << 12);
            for (UINT32 pdpti = 0; pdpti < 512; pdpti++) {
                PEPT_ENTRY pdpte = &pdpt[pdpti];
                if (!pdpte->Fields.Read) continue;

                PEPT_ENTRY pd = (PEPT_ENTRY)(pdpte->Fields.PhysAddr << 12);
                for (UINT32 pdi = 0; pdi < 512; pdi++) {
                    PEPT_ENTRY pde = &pd[pdi];
                    if (!pde->Fields.Read) continue;
                    if (!pde->Fields.LargePage) {
                        // Return the PT to the pool; the pool owns it.
                        HvPtPoolFree((PVOID)(pde->Fields.PhysAddr << 12));
                    }
                }
                // PD/PDPT/PML4 were also taken from the pool at init.
                HvPtPoolFree(pd);
            }
            HvPtPoolFree(pdpt);
        }
        HvPtPoolFree(g_Ept.Pml4);
        g_Ept.Pml4 = NULL;
    }

    HvPtPoolDestroy();
    InterlockedExchange(&g_HypervisorActive, 0);
}

// ============================================================================
//  Remaining callbacks
// ============================================================================

static NTSTATUS VmxInitialize(VOID)
{
    // g_IdentityRanges must already be populated by DriverEntry via
    // HvCollectPhysicalRanges(). Build the full dynamic identity map.
    NTSTATUS st = EptInitialize(g_IdentityRanges, g_IdentityRangeCount);
    if (!NT_SUCCESS(st)) return st;

    ULONG count = g_CpuCount;
    for (ULONG i = 0; i < count; i++) {
        PROCESSOR_NUMBER pn;
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) continue;

        GROUP_AFFINITY aff = {};
        aff.Group = pn.Group;
        aff.Mask  = 1ULL << pn.Number;
        GROUP_AFFINITY old = {};
        KeSetSystemGroupAffinityThread(&aff, &old);
        st = VmxSetupCurrentCpu(NULL);
        KeRevertToUserGroupAffinityThread(&old);
        if (!NT_SUCCESS(st)) return st;
    }

    for (ULONG i = 0; i < count; i++) {
        PROCESSOR_NUMBER pn;
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) continue;

        GROUP_AFFINITY aff = {};
        aff.Group = pn.Group;
        aff.Mask  = 1ULL << pn.Number;
        GROUP_AFFINITY old = {};
        KeSetSystemGroupAffinityThread(&aff, &old);
        st = VmxLaunchCurrentCpu();
        KeRevertToUserGroupAffinityThread(&old);
        if (!NT_SUCCESS(st)) return st;
    }

    InterlockedExchange(&g_HypervisorActive, 1);
    return STATUS_SUCCESS;
}

static NTSTATUS VmxBuildIdentityMap(const HV_IDENTITY_RANGE* Ranges, ULONG Count)
{
    return EptInitialize(Ranges, Count);
}

static VOID VmxArmSingleStep(PPER_CPU_CONTEXT Cpu)
{
    UNREFERENCED_PARAMETER(Cpu);
    UINT32 ctl = VmRead32(VMCS_PROC_BASED_CTLS);
    ctl |= CPU_BASED_MONITOR_TRAP_FLAG;   // bit 26
    VmWrite32(VMCS_PROC_BASED_CTLS, ctl);
}

static VOID VmxDisarmSingleStep(PPER_CPU_CONTEXT Cpu)
{
    UNREFERENCED_PARAMETER(Cpu);
    UINT32 ctl = VmRead32(VMCS_PROC_BASED_CTLS);
    ctl &= ~CPU_BASED_MONITOR_TRAP_FLAG;
    VmWrite32(VMCS_PROC_BASED_CTLS, ctl);
}

static VOID VmxInjectException(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa)
{
    // VM-entry interruption-information field (SDM Vol 3C 24.8.3):
    //   bit 31    = valid
    //   bit 11    = deliver error code
    //   bits 10:8 = interruption type (3 = hardware exception)
    //   bits 7:0  = vector
    //
    // Vectors that architecturally push an error code onto the stack:
    //   #DF (8), #TS (10), #NP (11), #SS (12), #GP (13), #PF (14),
    //   #AC (17), #CP (21), #VC (29), #SX (30).
    // Failing to set bit 11 for those vectors, or setting it for the
    // others, causes a VM-entry consistency failure.
    BOOLEAN hasErrorCode = (Vector == 8  || Vector == 10 || Vector == 11 ||
                            Vector == 12 || Vector == 13 || Vector == 14 ||
                            Vector == 17 || Vector == 21 || Vector == 29 ||
                            Vector == 30);

    UINT32 info = (1U << 31) | (3U << 8) | (Vector & 0xFF);

    if (hasErrorCode) {
        info |= (1U << 11);
        VmWrite32(VMCS_ENTRY_EXCEPTION_ERR, ErrorCode);

        // #PF requires the faulting linear address in GUEST_CR2. For an
        // EPT violation the address delivered here is the GPA the guest
        // faulted on (the exit handler supplies it via FaultingGpa).
        if (Vector == 14) {
            VmWrite64(VMCS_GUEST_CR2, FaultingGpa);
        }
    } else {
        info &= ~(1U << 11);
        VmWrite32(VMCS_ENTRY_EXCEPTION_ERR, 0);
    }

    VmWrite32(VMCS_ENTRY_INTR_INFO, info);
}

static VOID VmxInvalidateTlbAll(VOID)
{
    // Full EPT flush: local INVEPT plus a cross-core broadcast so every
    // logical CPU drops stale translations of the shared EPTP.
    EptInveptLocalAll();
    EptInveptBroadcast();
}
