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
static NTSTATUS VmxInjectException(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa);
static VOID     VmxInjectExceptionCompat(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa);
static VOID     VmxInvalidateTlbAll(VOID);

// ----------------------------------------------------------------------------
//  The exported operations table.
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
    VmxInjectExceptionCompat,
    VmxInvalidateTlbAll,
};

// ============================================================================
//  EPT internal state.
// ============================================================================
typedef struct _INTEL_EPT_CONTEXT {
    PEPT_ENTRY  Pml4;
    UINT64      Pml4Phys;
    UINT64      Eptp;
    volatile LONG Lock;
} INTEL_EPT_CONTEXT;

static INTEL_EPT_CONTEXT g_Ept = {};

// ----------------------------------------------------------------------------
//  EptAllocatePage — 4 KB sheet from the pre-allocated pool.
// ----------------------------------------------------------------------------
static PVOID EptAllocatePage(VOID)
{
    return HvPtPoolAlloc(NULL);
}

static UINT64 EptPhysOf(PVOID Va)
{
    return MmGetPhysicalAddress(Va).QuadPart & ~0xFFFULL;
}

// Resolve a page-table physical address to its current virtual mapping.
static PEPT_ENTRY EptVaFromPhys(UINT64 Phys)
{
    return (PEPT_ENTRY)HvPtPoolVaFromPa(Phys & ~0xFFFULL);
}

// ----------------------------------------------------------------------------
//  EptMap2MB — identity-map one 2 MB region with given permissions.
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

    PEPT_ENTRY pdpt  = EptVaFromPhys(pml4e->Fields.PhysAddr << 12);
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

    PEPT_ENTRY pd  = EptVaFromPhys(pdpte->Fields.PhysAddr << 12);
    PEPT_ENTRY pde = &pd[EPT_PD_INDEX(Gpa)];
    if (pde->Fields.Read || pde->Fields.LargePage)
        return STATUS_UNSUCCESSFUL;

    pde->Value = 0;
    pde->Fields.Read      = (Flags & EPT_PERM_READ)    ? 1 : 0;
    pde->Fields.Write     = (Flags & EPT_PERM_WRITE)   ? 1 : 0;
    pde->Fields.Execute   = (Flags & EPT_PERM_EXECUTE) ? 1 : 0;
    pde->Fields.MemType   = 6;   // Write-Back
    pde->Fields.LargePage = 1;
    pde->Fields.PhysAddr  = Hpa >> 12;
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  EptInitialize — allocate PML4 and build the boot-time identity map.
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

        UINT64 start = base & ~0x1FFFFFULL;
        UINT64 end   = (base + size + 0x1FFFFFULL) & ~0x1FFFFFULL;

        for (UINT64 gpa = start; gpa < end; gpa += 0x200000ULL) {
            NTSTATUS st = EptMap2MB(gpa, gpa, EPT_PERM_RWX);
            if (!NT_SUCCESS(st)) return st;
        }
    }

    // EPTP: 4-level walk, write-back, accessed/dirty enabled.
    g_Ept.Eptp = (g_Ept.Pml4Phys & 0x000FFFFFFFFFF000ULL)
               | (3ULL << 0)
               | (6ULL << 3)
               | (1ULL << 6);

    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  Local INVEPT helpers.
// ----------------------------------------------------------------------------
static VOID EptInveptSingle(VOID)
{
    __declspec(align(16)) struct { UINT64 Eptp; UINT64 Reserved; } desc =
        { g_Ept.Eptp, 0 };
    _invept(1, &desc);
}

static VOID EptInveptLocalAll(VOID)
{
    __declspec(align(16)) struct { UINT64 A; UINT64 B; } desc = { 0, 0 };
    _invept(2, &desc);
}

// ----------------------------------------------------------------------------
//  Cross-core TLB shootdown.
// ----------------------------------------------------------------------------
static VOID EptInveptBroadcastDpc(
    PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    EptInveptLocalAll();

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static VOID EptInveptBroadcast(VOID)
{
    KeGenericCallDpc(EptInveptBroadcastDpc, NULL);
}

// ----------------------------------------------------------------------------
//  EPT lookup / split machinery.
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

static EPT_LOOKUP_RESULT EptLookupLocked(
    UINT64 Gpa, PEPT_ENTRY* OutPte, EPT_SPLIT_PLAN* OutPlan)
{
    *OutPte = NULL;

    PEPT_ENTRY pml4e = &g_Ept.Pml4[EPT_PML4_INDEX(Gpa)];
    if (!pml4e->Fields.Read) return EptLookupNotMapped;

    PEPT_ENTRY pdpt  = EptVaFromPhys(pml4e->Fields.PhysAddr << 12);
    PEPT_ENTRY pdpte = &pdpt[EPT_PDPT_INDEX(Gpa)];
    if (!pdpte->Fields.Read) return EptLookupNotMapped;

    PEPT_ENTRY pd  = EptVaFromPhys(pdpte->Fields.PhysAddr << 12);
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

    PEPT_ENTRY pt = EptVaFromPhys(pde->Fields.PhysAddr << 12);
    *OutPte = &pt[EPT_PT_INDEX(Gpa)];
    return EptLookupDone;
}

// ----------------------------------------------------------------------------
//  VmxSplitAndGetPteInternal — one attempt of the deadlock-safe split.
// ----------------------------------------------------------------------------
static NTSTATUS VmxSplitAndGetPteInternal(UINT64 Gpa, PEPT_ENTRY* OutPte)
{
    EPT_SPLIT_PLAN    plan   = {};
    PEPT_ENTRY        pte    = NULL;
    EPT_LOOKUP_RESULT result;

    SpinAcquire(&g_Ept.Lock);
    result = EptLookupLocked(Gpa, &pte, &plan);
    SpinRelease(&g_Ept.Lock);

    if (result == EptLookupDone) {
        if (OutPte) *OutPte = pte;
        return STATUS_SUCCESS;
    }
    if (result != EptLookupNeedsSplit) return STATUS_UNSUCCESSFUL;

    PEPT_ENTRY newPt = (PEPT_ENTRY)HvPtPoolAlloc(NULL);
    if (!newPt) return STATUS_INSUFFICIENT_RESOURCES;

    for (UINT32 i = 0; i < 512; i++) {
        newPt[i].Value = 0;
        newPt[i].Fields.Read      = (plan.OriginalPerm & EPT_PERM_READ)    ? 1 : 0;
        newPt[i].Fields.Write     = (plan.OriginalPerm & EPT_PERM_WRITE)   ? 1 : 0;
        newPt[i].Fields.Execute   = (plan.OriginalPerm & EPT_PERM_EXECUTE) ? 1 : 0;
        newPt[i].Fields.MemType   = 6;
        newPt[i].Fields.PhysAddr  = (plan.OriginalHpa +
                                     (UINT64)i * PAGE_SIZE) >> 12;
    }

    PEPT_ENTRY freeAfterUnlock = NULL;
    NTSTATUS   status          = STATUS_UNSUCCESSFUL;

    SpinAcquire(&g_Ept.Lock);

    PEPT_ENTRY pml4e = &g_Ept.Pml4[EPT_PML4_INDEX(plan.PageGpa)];
    PEPT_ENTRY pdpt  = pml4e->Fields.Read
                     ? EptVaFromPhys(pml4e->Fields.PhysAddr << 12) : NULL;
    PEPT_ENTRY pdpte = pdpt ? &pdpt[EPT_PDPT_INDEX(plan.PageGpa)] : NULL;
    PEPT_ENTRY pd    = (pdpte && pdpte->Fields.Read)
                     ? EptVaFromPhys(pdpte->Fields.PhysAddr << 12) : NULL;
    PEPT_ENTRY pde   = pd ? &pd[plan.PdIndex] : NULL;

    if (!pde || !pde->Fields.Read) {
        freeAfterUnlock = newPt;
        status = STATUS_UNSUCCESSFUL;
        goto unlock_and_out;
    }

    if (!pde->Fields.LargePage) {
        PEPT_ENTRY existingPt  = EptVaFromPhys(pde->Fields.PhysAddr << 12);
        PEPT_ENTRY existingPte = &existingPt[EPT_PT_INDEX(plan.PageGpa)];

        UINT64 existingHpa = (existingPte->Fields.PhysAddr << 12) & ~0xFFFULL;
        UINT64 expectedHpa = plan.OriginalHpa +
                             (UINT64)EPT_PT_INDEX(plan.PageGpa) * PAGE_SIZE;
        if (existingHpa != expectedHpa) {
            freeAfterUnlock = newPt;
            status = STATUS_RETRY;
            goto unlock_and_out;
        }

        if (OutPte) *OutPte = existingPte;
        freeAfterUnlock = newPt;
        EptInveptSingle();
        status = STATUS_SUCCESS;
        goto unlock_and_out;
    }

    UINT64 currentHpa = (pde->Fields.PhysAddr << 12) & ~0x1FFFFFULL;
    if (currentHpa != plan.OriginalHpa) {
        freeAfterUnlock = newPt;
        status = STATUS_RETRY;
        goto unlock_and_out;
    }

    pde->Value = 0;
    pde->Fields.Read      = 1;
    pde->Fields.Write     = 1;
    pde->Fields.Execute   = 1;
    pde->Fields.LargePage = 0;
    pde->Fields.PhysAddr  = EptPhysOf(newPt) >> 12;

    if (OutPte) *OutPte = &newPt[EPT_PT_INDEX(plan.PageGpa)];

    EptInveptSingle();
    status = STATUS_SUCCESS;

unlock_and_out:
    SpinRelease(&g_Ept.Lock);
    if (freeAfterUnlock) HvPtPoolFree(freeAfterUnlock);
    return status;
}

// ----------------------------------------------------------------------------
//  VmxSplitAndGetPte — bounded retry wrapper.
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
//  VmxProtectRange — batch permission update with one broadcast flush.
// ----------------------------------------------------------------------------
static NTSTATUS VmxProtectRange(UINT64 Gpa, UINT64 Size, UINT64 Perms)
{
    if ((Gpa & 0xFFF) || (Size & 0xFFF) || Size == 0)
        return STATUS_INVALID_PARAMETER;

    // First pass: ensure every 4 KB page is represented by a PTE.
    for (UINT64 p = Gpa; p < Gpa + Size; p += PAGE_SIZE) {
        PEPT_ENTRY pte = NULL;
        NTSTATUS st = VmxSplitAndGetPte(p, &pte);
        if (!NT_SUCCESS(st)) return st;
    }

    // Second pass: update all targeted PTEs under one lock sequence.
    SpinAcquire(&g_Ept.Lock);
    for (UINT64 p = Gpa; p < Gpa + Size; p += PAGE_SIZE) {
        PEPT_ENTRY live = NULL;
        EPT_SPLIT_PLAN dummy = {};
        EPT_LOOKUP_RESULT res = EptLookupLocked(p, &live, &dummy);
        if (res != EptLookupDone || !live) {
            SpinRelease(&g_Ept.Lock);
            return STATUS_UNSUCCESSFUL;
        }

        live->Fields.Read    = (Perms & EPT_PERM_READ)    ? 1 : 0;
        live->Fields.Write   = (Perms & EPT_PERM_WRITE)   ? 1 : 0;
        live->Fields.Execute = (Perms & EPT_PERM_EXECUTE) ? 1 : 0;
        if (live->Fields.Write) live->Fields.Read = 1;
    }
    SpinRelease(&g_Ept.Lock);

    VmxInvalidateTlbAll();
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  VmxSaveAndGrant / VmxRestoreEntry.
// ----------------------------------------------------------------------------
static NTSTATUS VmxSaveAndGrant(UINT64 Gpa, UINT64 Perms, UINT64* OutOriginal)
{
    UINT64 pageGpa = Gpa & ~0xFFFULL;

    PEPT_ENTRY pte = NULL;
    NTSTATUS st = VmxSplitAndGetPte(pageGpa, &pte);
    if (!NT_SUCCESS(st)) return st;
    if (!pte) return STATUS_UNSUCCESSFUL;

    SpinAcquire(&g_Ept.Lock);

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

    EptInveptBroadcast();
    return STATUS_SUCCESS;
}

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
//  Segment and descriptor-table helpers.
// ============================================================================
static UINT64 SegmentDescriptorBase64(const SEGMENT_DESCRIPTOR64* d)
{
    UINT64 base = 0;
    base |= (UINT64)d->Base15_0;
    base |= (UINT64)d->Base23_16 << 16;
    base |= (UINT64)d->Base31_24 << 24;
    base |= (UINT64)d->Base63_32 << 32;
    return base;
}

static UINT64 ReadTssBase(VOID)
{
    DESCRIPTOR_TABLE_REGISTER64 gdtr = {};
    __sgdt(&gdtr);

    UINT16 trSelector = VmxReadTr();
    if (trSelector & 0x4) return 0;

    UINT32 offset = trSelector & ~0x7;
    if ((UINT64)offset + sizeof(SEGMENT_DESCRIPTOR64) > gdtr.Limit + 1ULL)
        return 0;

    const SEGMENT_DESCRIPTOR64* desc =
        (const SEGMENT_DESCRIPTOR64*)(gdtr.Base + offset);
    return SegmentDescriptorBase64(desc);
}

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
    UINT64 vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    UINT32 revisionId = (UINT32)(vmxBasic & 0x7FFFFFFF);

    *(UINT32*)Cpu->VmxonVa = revisionId;
    *(UINT32*)Cpu->VmcsVa  = revisionId;

    if (__vmx_vmclear(&Cpu->VmcsPa) != 0) return STATUS_UNSUCCESSFUL;
    if (__vmx_vmptrld(&Cpu->VmcsPa) != 0) return STATUS_UNSUCCESSFUL;

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

    UINT32 pinCtl = 0;
    VmxAdjustControls(&pinCtl, MSR_IA32_VMX_PINBASED_CTLS);
    VmWrite32(VMCS_PIN_BASED_CTLS, pinCtl);

    UINT32 procCtl = CPU_BASED_USE_MSR_BITMAPS
                   | CPU_BASED_ACTIVATE_SECONDARY;
    VmxAdjustControls(&procCtl, MSR_IA32_VMX_PROCBASED_CTLS);
    VmWrite32(VMCS_PROC_BASED_CTLS, procCtl);

    UINT32 procCtl2 = CPU_BASED2_ENABLE_EPT;
    VmxAdjustControls(&procCtl2, MSR_IA32_VMX_PROCBASED_CTLS2);
    if (!(procCtl2 & CPU_BASED2_ENABLE_EPT))
        return STATUS_NOT_SUPPORTED;
    VmWrite32(VMCS_PROC_BASED_CTLS2, procCtl2);

    UINT32 exitCtl = VM_EXIT_HOST_ADDR_SPACE_SIZE
                   | VM_EXIT_ACK_INTR_ON_EXIT
                   | VM_EXIT_LOAD_IA32_PAT
                   | VM_EXIT_LOAD_IA32_EFER;
    VmxAdjustControls(&exitCtl, MSR_IA32_VMX_EXIT_CTLS);
    VmWrite32(VMCS_EXIT_CTLS, exitCtl);

    UINT32 entryCtl = VM_ENTRY_IA32E_MODE
                    | VM_ENTRY_LOAD_IA32_PAT
                    | VM_ENTRY_LOAD_IA32_EFER;
    VmxAdjustControls(&entryCtl, MSR_IA32_VMX_ENTRY_CTLS);
    VmWrite32(VMCS_ENTRY_CTLS, entryCtl);

    VmWrite64(VMCS_VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFULL);
    VmWrite64(VMCS_EPTP, g_Ept.Eptp);

    UINT64 cr0Fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    UINT64 cr0Fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    UINT64 cr0 = __readcr0();
    cr0 |=  cr0Fixed0;
    cr0 &=  cr0Fixed1;
    VmWrite64(VMCS_GUEST_CR0, cr0);

    UINT64 cr4Fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
    UINT64 cr4Fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);
    UINT64 cr4 = __readcr4() | X86_CR4_VMXE;
    cr4 |=  cr4Fixed0;
    cr4 &=  cr4Fixed1;
    VmWrite64(VMCS_GUEST_CR4, cr4);

    VmWrite64(VMCS_GUEST_CR3, __readcr3());
    VmWrite64(VMCS_GUEST_DR7, __readdr(7));

    UINT64 efer = __readmsr(MSR_IA32_EFER);
    UINT64 pat  = __readmsr(MSR_IA32_PAT);
    if (entryCtl & VM_ENTRY_LOAD_IA32_EFER)
        VmWrite64(VMCS_GUEST_IA32_EFER, efer);
    if (entryCtl & VM_ENTRY_LOAD_IA32_PAT)
        VmWrite64(VMCS_GUEST_IA32_PAT, pat);

    DESCRIPTOR_TABLE_REGISTER64 gdtr = {};
    DESCRIPTOR_TABLE_REGISTER64 idtr = {};
    __sgdt(&gdtr);
    __sidt(&idtr);

    UINT64 trBase = ReadTssBase();
    if (trBase == 0) return STATUS_UNSUCCESSFUL;

    UINT32 csAr = BuildAccessRights(0xB, 1, 0, 1, 0, 1, 0, 1);
    VmxSetupGuestSegment(VMCS_GUEST_CS_SEL, VMCS_GUEST_CS_BASE,
                         VMCS_GUEST_CS_LIMIT, VMCS_GUEST_CS_AR,
                         0x08, 0, 0xFFFFFFFF, csAr);

    UINT32 ssAr = BuildAccessRights(0x3, 1, 0, 1, 0, 0, 1, 1);
    VmxSetupGuestSegment(VMCS_GUEST_SS_SEL, VMCS_GUEST_SS_BASE,
                         VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_AR,
                         0x10, 0, 0xFFFFFFFF, ssAr);

    VmxSetupGuestSegment(VMCS_GUEST_DS_SEL, VMCS_GUEST_DS_BASE,
                         VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_AR,
                         0x18, 0, 0xFFFFFFFF, ssAr);
    VmxSetupGuestSegment(VMCS_GUEST_ES_SEL, VMCS_GUEST_ES_BASE,
                         VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_AR,
                         0x20, 0, 0xFFFFFFFF, ssAr);

    UINT64 fsBase = __readmsr(MSR_IA32_FS_BASE);
    UINT64 gsBase = __readmsr(MSR_IA32_GS_BASE);
    VmxSetupGuestSegment(VMCS_GUEST_FS_SEL, VMCS_GUEST_FS_BASE,
                         VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_AR,
                         0x28, fsBase, 0xFFFFFFFF, ssAr);
    VmxSetupGuestSegment(VMCS_GUEST_GS_SEL, VMCS_GUEST_GS_BASE,
                         VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_AR,
                         0x30, gsBase, 0xFFFFFFFF, ssAr);

    VmWrite16(VMCS_GUEST_LDTR_SEL, 0);
    VmWrite64(VMCS_GUEST_LDTR_BASE, 0);
    VmWrite32(VMCS_GUEST_LDTR_LIMIT, 0);
    VmWrite32(VMCS_GUEST_LDTR_AR, 0x10000);

    VmWrite16(VMCS_GUEST_TR_SEL, VmxReadTr());
    VmWrite64(VMCS_GUEST_TR_BASE, trBase);
    VmWrite32(VMCS_GUEST_TR_LIMIT, 0x67);
    VmWrite32(VMCS_GUEST_TR_AR, BuildAccessRights(0xB, 0, 0, 1, 0, 0, 0, 0));

    VmWrite64(VMCS_GUEST_GDTR_BASE, gdtr.Base);
    VmWrite32(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
    VmWrite64(VMCS_GUEST_IDTR_BASE, idtr.Base);
    VmWrite32(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);

    VmWrite32(VMCS_GUEST_SYSENTER_CS, (UINT32)__readmsr(MSR_IA32_SYSENTER_CS));
    VmWrite64(VMCS_GUEST_SYSENTER_ESP, 0);
    VmWrite64(VMCS_GUEST_SYSENTER_EIP, 0);

    UINT64 rflags = __readeflags() & 0x3F7FD5ULL;
    rflags |= 0x2ULL;
    VmWrite64(VMCS_GUEST_RFLAGS, rflags);

    VmWrite64(VMCS_HOST_CR0, __readcr0());
    VmWrite64(VMCS_HOST_CR3, __readcr3());
    VmWrite64(VMCS_HOST_CR4, __readcr4() | X86_CR4_VMXE);

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

    VmWrite32(VMCS_HOST_SYSENTER_CS, (UINT32)__readmsr(MSR_IA32_SYSENTER_CS));
    VmWrite64(VMCS_HOST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    VmWrite64(VMCS_HOST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    VmWrite64(VMCS_HOST_RSP, Cpu->HostStackTop);
    VmWrite64(VMCS_HOST_RIP, (UINT64)VmxVmExitEntry);

    VmWrite64(VMCS_CR0_GUEST_HOST_MASK, X86_CR0_PE | X86_CR0_NE | X86_CR0_PG);
    VmWrite64(VMCS_CR4_GUEST_HOST_MASK, X86_CR4_PAE);

    return STATUS_SUCCESS;
}

// ============================================================================
//  Per-CPU bring-up.
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

        __vmx_vmclear(&cpu->VmcsPa);
        __vmx_vmxoff();
        __writecr4(__readcr4() & ~X86_CR4_VMXE);
        return STATUS_UNSUCCESSFUL;
    }

    cpu->Launched = TRUE;
    return STATUS_SUCCESS;
}

// ============================================================================
//  Teardown.
// ============================================================================
#define HV_HYPERCALL_TEARDOWN  0x48566D78ULL

NTSTATUS IntelHandleTeardownVmcall(PPER_CPU_CONTEXT Cpu)
{
    if (!Cpu || !Cpu->Launched) return STATUS_SUCCESS;

    __vmx_vmclear(&Cpu->VmcsPa);

    __declspec(align(16)) struct { UINT64 A; UINT64 B; } invvpidDesc = { 0, 0 };
    _invvpid(2, &invvpidDesc);

    __vmx_vmxoff();
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

    if (g_Ept.Pml4) {
        for (UINT32 pml4i = 0; pml4i < 512; pml4i++) {
            PEPT_ENTRY pml4e = &g_Ept.Pml4[pml4i];
            if (!pml4e->Fields.Read) continue;

            PEPT_ENTRY pdpt = EptVaFromPhys(pml4e->Fields.PhysAddr << 12);
            for (UINT32 pdpti = 0; pdpti < 512; pdpti++) {
                PEPT_ENTRY pdpte = &pdpt[pdpti];
                if (!pdpte->Fields.Read) continue;

                PEPT_ENTRY pd = EptVaFromPhys(pdpte->Fields.PhysAddr << 12);
                for (UINT32 pdi = 0; pdi < 512; pdi++) {
                    PEPT_ENTRY pde = &pd[pdi];
                    if (!pde->Fields.Read) continue;
                    if (!pde->Fields.LargePage) {
                        PEPT_ENTRY pt = EptVaFromPhys(pde->Fields.PhysAddr << 12);
                        HvPtPoolFree(pt);
                    }
                }
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
//  Remaining callbacks.
// ============================================================================
static NTSTATUS VmxInitialize(VOID)
{
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
    ctl |= CPU_BASED_MONITOR_TRAP_FLAG;
    VmWrite32(VMCS_PROC_BASED_CTLS, ctl);
}

static VOID VmxDisarmSingleStep(PPER_CPU_CONTEXT Cpu)
{
    UNREFERENCED_PARAMETER(Cpu);
    UINT32 ctl = VmRead32(VMCS_PROC_BASED_CTLS);
    ctl &= ~CPU_BASED_MONITOR_TRAP_FLAG;
    VmWrite32(VMCS_PROC_BASED_CTLS, ctl);
}

// ----------------------------------------------------------------------------
//  High-precision exception injection.
// ----------------------------------------------------------------------------
static NTSTATUS VmxInjectException(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa)
{
    if (VmRead32(VMCS_ENTRY_INTR_INFO) & (1U << 31))
        return STATUS_UNSUCCESSFUL;

    static const UINT32 ErrorCodeVectorsMask =
        (1U << 8)  | (1U << 10) | (1U << 11) | (1U << 12) |
        (1U << 13) | (1U << 14) | (1U << 17) | (1U << 21) |
        (1U << 29) | (1U << 30);

    BOOLEAN hasErrorCode =
        (Vector < 32) && ((ErrorCodeVectorsMask >> Vector) & 1);

    UINT32 info = (1U << 31) | (3U << 8) | (Vector & 0xFF);

    if (hasErrorCode) {
        info |= (1U << 11);
        VmWrite32(VMCS_ENTRY_EXCEPTION_ERR, ErrorCode);

        if (Vector == 14) {
            VmWrite64(VMCS_GUEST_CR2, FaultingGpa);
        }
    } else {
        info &= ~(1U << 11);
        VmWrite32(VMCS_ENTRY_EXCEPTION_ERR, 0);
    }

    VmWrite32(VMCS_ENTRY_INTR_INFO, info);
    return STATUS_SUCCESS;
}

static VOID VmxInjectExceptionCompat(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa)
{
    (VOID)VmxInjectException(Vector, ErrorCode, FaultingGpa);
}

static VOID VmxInvalidateTlbAll(VOID)
{
    __declspec(align(16)) struct { UINT64 A; UINT64 B; } desc = { 0, 0 };
    _invept(2, &desc);
    EptInveptBroadcast();
}
