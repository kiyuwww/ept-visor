// ============================================================================
//  amd_svm.cpp — AMD-V / SVM / NPT implementation of HV_OPERATIONS.
//
//  References are to the AMD64 Architecture Programmer's Manual Volume 2:
//  System Programming and Appendix B, VMCB Layout.
// ============================================================================
#include "common.h"
#include <intrin.h>

// ----------------------------------------------------------------------------
//  Forward declarations.
// ----------------------------------------------------------------------------
static NTSTATUS SvmInitialize(VOID);
static VOID     SvmTeardown(VOID);
static NTSTATUS SvmBuildIdentityMap(const HV_IDENTITY_RANGE* Ranges, ULONG Count);
static NTSTATUS SvmProtectRange(UINT64 Gpa, UINT64 Size, UINT64 Perms);
static NTSTATUS SvmSaveAndGrant(UINT64 Gpa, UINT64 Perms, UINT64* OutOriginal);
static NTSTATUS SvmRestoreEntry(UINT64 Gpa, UINT64 OriginalValue);
static NTSTATUS SvmSplitAndGetPte(UINT64 Gpa, PEPT_ENTRY* OutPte);
static VOID     SvmArmSingleStep(PPER_CPU_CONTEXT Cpu);
static VOID     SvmDisarmSingleStep(PPER_CPU_CONTEXT Cpu);
static VOID     SvmInjectException(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa);
static VOID     SvmInvalidateTlbAll(VOID);

// ----------------------------------------------------------------------------
//  Exported operations table.
// ----------------------------------------------------------------------------
HV_OPERATIONS g_AmdOps = {
    HvVendorAmd,
    "AMD SVM/NPT",
    SvmInitialize,
    SvmTeardown,
    SvmBuildIdentityMap,
    SvmProtectRange,
    SvmSaveAndGrant,
    SvmRestoreEntry,
    SvmSplitAndGetPte,
    SvmArmSingleStep,
    SvmDisarmSingleStep,
    SvmInjectException,
    SvmInvalidateTlbAll,
};

// ----------------------------------------------------------------------------
//  SVM/NPT constants.
// ----------------------------------------------------------------------------
#define SVM_GUEST_ASID          1U
#define SVM_NPT_ENABLE          1ULL
#define SVM_INTERCEPT_DB        (1U << 1)

// ============================================================================
//  VMCB layout definitions (AMD APM Vol 2, App. B).
//
//  Control area: 0x000–0x3FF (1024 bytes)
//  Save area   : 0x400–0x7FF (1024 bytes used by architectural fields)
// ============================================================================
#pragma pack(push, 1)

typedef struct _VMCB_SEG {
    UINT16 Selector;
    UINT16 Attrib;
    UINT32 Limit;
    UINT64 Base;
} VMCB_SEG;

typedef struct _VMCB_CONTROL_AREA {
    // 0x000 — CR/DR read/write intercepts
    UINT16 InterceptCrRead;
    UINT16 InterceptCrWrite;
    UINT16 InterceptDrRead;
    UINT16 InterceptDrWrite;

    // 0x008 — exception intercepts (bit N = vector N)
    UINT32 InterceptExceptions;

    // 0x00C — misc intercepts
    UINT32 InterceptMisc1;
    UINT32 InterceptMisc2;
    UINT32 InterceptMisc3;

    UINT8  Reserved0[0x28];

    // 0x040
    UINT64 IopmBasePa;
    UINT64 MsrpmBasePa;
    UINT64 TscOffset;

    // 0x058
    UINT32 Asid;
    UINT8  TlbCtl;
    UINT8  Reserved1[3];

    // 0x060
    UINT32 IntCtl;
    UINT32 IntVector;
    UINT32 IntState;
    UINT8  Reserved2[4];

    // 0x070
    UINT32 ExitCode;
    UINT32 ExitCodeHi;
    UINT64 ExitInfo1;
    UINT64 ExitInfo2;
    UINT32 ExitIntInfo;
    UINT32 ExitIntInfoErr;

    // 0x090
    UINT64 NestedCtl;          // bit 0 = NPT enable
    UINT8  Reserved3[16];

    // 0x0A8 — lower 32 bits: event info; upper 32 bits: exception error code
    UINT64 EventInj;

    // 0x0B0
    UINT64 NestedCr3;          // NPT PML4 physical address
    UINT64 LbrCtl;
    UINT64 LbrVirtCtl;

    UINT8  Reserved4[0x338];
} VMCB_CONTROL_AREA;

typedef struct _VMCB_SAVE_AREA {
    // 0x000 (relative to 0x400) — ES
    VMCB_SEG Es;
    // 0x010 — CS
    VMCB_SEG Cs;
    // 0x020 — SS
    VMCB_SEG Ss;
    // 0x030 — DS
    VMCB_SEG Ds;
    // 0x040 — FS
    VMCB_SEG Fs;
    // 0x050 — GS
    VMCB_SEG Gs;
    // 0x060 — GDTR
    VMCB_SEG Gdtr;
    // 0x070 — LDTR
    VMCB_SEG Ldtr;
    // 0x080 — IDTR
    VMCB_SEG Idtr;
    // 0x090 — TR
    VMCB_SEG Tr;

    UINT8  Reserved0[0x2B];

    // 0x0CB — CPL
    UINT8  Cpl;
    UINT8  Reserved1[0x04];

    // 0x0D0 — EFER
    UINT64 Efer;

    UINT8  Reserved2[0x70];

    // 0x148 — CR4
    UINT64 Cr4;
    // 0x150 — CR3
    UINT64 Cr3;
    // 0x158 — CR0
    UINT64 Cr0;
    // 0x160 — DR7
    UINT64 Dr7;
    // 0x168 — DR6
    UINT64 Dr6;
    // 0x170 — RFLAGS
    UINT64 Rflags;
    // 0x178 — RIP
    UINT64 Rip;

    UINT8  Reserved3[0x58];

    // 0x1D8 — RSP
    UINT64 Rsp;
    // 0x1E0 — S_CET
    UINT64 SCet;
    // 0x1E8 — SSP
    UINT64 Ssp;
    // 0x1F0 — ISST_ADDR
    UINT64 IsstAddr;
    // 0x1F8 — RAX
    UINT64 Rax;
    // 0x200 — STAR
    UINT64 Star;
    // 0x208 — LSTAR
    UINT64 Lstar;
    // 0x210 — CSTAR
    UINT64 Cstar;
    // 0x218 — SFMASK
    UINT64 Sfmask;
    // 0x220 — KernelGsBase
    UINT64 KernelGsBase;
    // 0x228 — SYSENTER_CS
    UINT64 SysenterCs;
    // 0x230 — SYSENTER_ESP
    UINT64 SysenterEsp;
    // 0x238 — SYSENTER_EIP
    UINT64 SysenterEip;
    // 0x240 — CR2
    UINT64 Cr2;

    UINT8  Reserved4[0x28];

    // 0x270 — G_PAT
    UINT64 GPat;

    UINT8  Reserved5[0x50];
} VMCB_SAVE_AREA;

typedef struct _VMCB {
    VMCB_CONTROL_AREA Control;
    VMCB_SAVE_AREA    Save;
} VMCB, *PVMCB;

#pragma pack(pop)

// ============================================================================
//  NPT state.
// ============================================================================
typedef struct _AMD_NPT_CONTEXT {
    PEPT_ENTRY  Pml4;
    UINT64      Pml4Phys;
    volatile LONG Lock;
} AMD_NPT_CONTEXT;

static AMD_NPT_CONTEXT g_Npt = {};

// ----------------------------------------------------------------------------
//  NPT physical-to-virtual translation. NPT entries store host physical
//  addresses; traversal and deallocation require valid kernel virtual
//  addresses derived through MmGetVirtualForPhysical.
// ----------------------------------------------------------------------------
static PEPT_ENTRY NptVaFromPhys(UINT64 Phys)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = Phys & ~0xFFFULL;
    return (PEPT_ENTRY)MmGetVirtualForPhysical(pa);
}

static PVOID NptAllocatePage(VOID)
{
    PVOID page = HvPtPoolAlloc(NULL);
    if (page) RtlZeroMemory(page, PAGE_SIZE);
    return page;
}

static UINT64 NptPhysOf(PVOID Va)
{
    return MmGetPhysicalAddress(Va).QuadPart & ~0xFFFULL;
}

// Map one 2 MB NPT large page. Bit 7 is the PS flag (large page).
// A large-page descriptor requires both GPA and HPA to be 2 MB aligned.
static NTSTATUS NptMap2MB(UINT64 Gpa, UINT64 Hpa, UINT64 Flags)
{
    if ((Gpa & 0x1FFFFFULL) || (Hpa & 0x1FFFFFULL))
        return STATUS_INVALID_PARAMETER;

    if (Flags & NPT_PERM_WRITE)
        Flags |= NPT_PERM_READ;

    PEPT_ENTRY pml4e = &g_Npt.Pml4[EPT_PML4_INDEX(Gpa)];
    if (!pml4e->Fields.Read) {
        PEPT_ENTRY pdpt = (PEPT_ENTRY)NptAllocatePage();
        if (!pdpt) return STATUS_INSUFFICIENT_RESOURCES;

        pml4e->Value = 0;
        pml4e->Fields.Read     = 1;
        pml4e->Fields.Write    = 1;
        pml4e->Fields.Execute  = 1;
        pml4e->Fields.PhysAddr = NptPhysOf(pdpt) >> 12;
    }

    PEPT_ENTRY pdpt = NptVaFromPhys((UINT64)pml4e->Fields.PhysAddr << 12);
    if (!pdpt) return STATUS_UNSUCCESSFUL;

    PEPT_ENTRY pdpte = &pdpt[EPT_PDPT_INDEX(Gpa)];
    if (!pdpte->Fields.Read) {
        PEPT_ENTRY pd = (PEPT_ENTRY)NptAllocatePage();
        if (!pd) return STATUS_INSUFFICIENT_RESOURCES;

        pdpte->Value = 0;
        pdpte->Fields.Read     = 1;
        pdpte->Fields.Write    = 1;
        pdpte->Fields.Execute  = 1;
        pdpte->Fields.PhysAddr = NptPhysOf(pd) >> 12;
    }

    PEPT_ENTRY pd = NptVaFromPhys((UINT64)pdpte->Fields.PhysAddr << 12);
    if (!pd) return STATUS_UNSUCCESSFUL;

    PEPT_ENTRY pde = &pd[EPT_PD_INDEX(Gpa)];
    if (pde->Fields.Read || pde->Fields.LargePage)
        return STATUS_UNSUCCESSFUL;

    pde->Value = 0;
    pde->Fields.Read      = (Flags & NPT_PERM_READ)    ? 1 : 0;
    pde->Fields.Write     = (Flags & NPT_PERM_WRITE)   ? 1 : 0;
    pde->Fields.Execute   = (Flags & NPT_PERM_EXECUTE) ? 1 : 0;
    pde->Fields.MemType   = 6;   // Write-Back
    pde->Fields.LargePage = 1;
    pde->Fields.PhysAddr  = Hpa >> 12;

    return STATUS_SUCCESS;
}

static NTSTATUS NptInitialize(const HV_IDENTITY_RANGE* Ranges, ULONG Count)
{
    g_Npt.Pml4 = (PEPT_ENTRY)NptAllocatePage();
    if (!g_Npt.Pml4) return STATUS_INSUFFICIENT_RESOURCES;

    g_Npt.Pml4Phys = NptPhysOf(g_Npt.Pml4);
    g_Npt.Lock     = 0;

    for (ULONG i = 0; i < Count; i++) {
        UINT64 start = Ranges[i].Base & ~0x1FFFFFULL;
        UINT64 end   = (Ranges[i].Base + Ranges[i].Size + 0x1FFFFFULL) & ~0x1FFFFFULL;

        for (UINT64 gpa = start; gpa < end; gpa += 0x200000ULL) {
            NTSTATUS st = NptMap2MB(gpa, gpa, NPT_PERM_RWX);
            if (!NT_SUCCESS(st)) return st;
        }
    }
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  NPT flush. INVLPGA flushes translation cache entries for the active ASID.
// ----------------------------------------------------------------------------
static VOID NptInvalidateAll(VOID)
{
    __svm_invlpga(0, SVM_GUEST_ASID);
}

// ----------------------------------------------------------------------------
//  Phase-1 lookup.
// ----------------------------------------------------------------------------
typedef enum _NPT_LOOKUP_RESULT {
    NptLookupDone,
    NptLookupNeedsSplit,
    NptLookupNotMapped,
} NPT_LOOKUP_RESULT;

typedef struct _NPT_SPLIT_PLAN {
    UINT64 PageGpa;
    UINT32 PdIndex;
    UINT64 OriginalHpa;
    UINT64 OriginalPerm;
} NPT_SPLIT_PLAN;

static NPT_LOOKUP_RESULT NptLookupLocked(
    UINT64 Gpa, PEPT_ENTRY* OutPte, NPT_SPLIT_PLAN* OutPlan)
{
    *OutPte = NULL;

    PEPT_ENTRY pml4e = &g_Npt.Pml4[EPT_PML4_INDEX(Gpa)];
    if (!pml4e->Fields.Read) return NptLookupNotMapped;

    PEPT_ENTRY pdpt = NptVaFromPhys((UINT64)pml4e->Fields.PhysAddr << 12);
    if (!pdpt) return NptLookupNotMapped;

    PEPT_ENTRY pdpte = &pdpt[EPT_PDPT_INDEX(Gpa)];
    if (!pdpte->Fields.Read) return NptLookupNotMapped;

    PEPT_ENTRY pd = NptVaFromPhys((UINT64)pdpte->Fields.PhysAddr << 12);
    if (!pd) return NptLookupNotMapped;

    PEPT_ENTRY pde = &pd[EPT_PD_INDEX(Gpa)];

    if (pde->Fields.LargePage) {
        OutPlan->PageGpa      = Gpa & ~0xFFFULL;
        OutPlan->PdIndex      = EPT_PD_INDEX(Gpa);
        OutPlan->OriginalHpa  = (UINT64)pde->Fields.PhysAddr << 12;
        OutPlan->OriginalPerm = pde->Value & (NPT_PERM_READ |
                                              NPT_PERM_WRITE |
                                              NPT_PERM_EXECUTE);
        return NptLookupNeedsSplit;
    }

    if (!pde->Fields.Read) return NptLookupNotMapped;

    PEPT_ENTRY pt = NptVaFromPhys((UINT64)pde->Fields.PhysAddr << 12);
    if (!pt) return NptLookupNotMapped;

    *OutPte = &pt[EPT_PT_INDEX(Gpa)];
    return NptLookupDone;
}

// ----------------------------------------------------------------------------
//  Deadlock-safe NPT split. Pool allocation and pool free occur outside the
//  g_Npt.Lock spinlock; the split is revalidated after reacquiring the lock.
// ----------------------------------------------------------------------------
static NTSTATUS SvmSplitAndGetPte(UINT64 Gpa, PEPT_ENTRY* OutPte)
{
    NPT_SPLIT_PLAN    plan = {};
    PEPT_ENTRY        pte  = NULL;
    NPT_LOOKUP_RESULT result;
    NTSTATUS          status = STATUS_SUCCESS;
    PEPT_ENTRY        redundantPt = NULL;

    SpinAcquire(&g_Npt.Lock);
    result = NptLookupLocked(Gpa, &pte, &plan);
    SpinRelease(&g_Npt.Lock);

    if (result == NptLookupDone) {
        if (OutPte) *OutPte = pte;
        return STATUS_SUCCESS;
    }
    if (result != NptLookupNeedsSplit) return STATUS_UNSUCCESSFUL;

    PEPT_ENTRY newPt = (PEPT_ENTRY)NptAllocatePage();
    if (!newPt) return STATUS_INSUFFICIENT_RESOURCES;

    for (UINT32 i = 0; i < 512; i++) {
        newPt[i].Value = 0;
        newPt[i].Fields.Read      = (plan.OriginalPerm & NPT_PERM_READ)    ? 1 : 0;
        newPt[i].Fields.Write     = (plan.OriginalPerm & NPT_PERM_WRITE)   ? 1 : 0;
        newPt[i].Fields.Execute   = (plan.OriginalPerm & NPT_PERM_EXECUTE) ? 1 : 0;
        newPt[i].Fields.MemType   = 6;   // Write-Back
        newPt[i].Fields.PhysAddr  = (plan.OriginalHpa +
                                     (UINT64)i * PAGE_SIZE) >> 12;
    }

    SpinAcquire(&g_Npt.Lock);

    PEPT_ENTRY pml4e = &g_Npt.Pml4[EPT_PML4_INDEX(plan.PageGpa)];
    if (!pml4e->Fields.Read) {
        status = STATUS_UNSUCCESSFUL;
        redundantPt = newPt;
        goto Exit;
    }

    PEPT_ENTRY pdpt = NptVaFromPhys((UINT64)pml4e->Fields.PhysAddr << 12);
    if (!pdpt) {
        status = STATUS_UNSUCCESSFUL;
        redundantPt = newPt;
        goto Exit;
    }

    PEPT_ENTRY pdpte = &pdpt[EPT_PDPT_INDEX(plan.PageGpa)];
    if (!pdpte->Fields.Read) {
        status = STATUS_UNSUCCESSFUL;
        redundantPt = newPt;
        goto Exit;
    }

    PEPT_ENTRY pd = NptVaFromPhys((UINT64)pdpte->Fields.PhysAddr << 12);
    if (!pd) {
        status = STATUS_UNSUCCESSFUL;
        redundantPt = newPt;
        goto Exit;
    }

    PEPT_ENTRY pde = &pd[plan.PdIndex];
    if (!pde->Fields.Read) {
        status = STATUS_UNSUCCESSFUL;
        redundantPt = newPt;
        goto Exit;
    }

    if (!pde->Fields.LargePage) {
        PEPT_ENTRY existingPt = NptVaFromPhys((UINT64)pde->Fields.PhysAddr << 12);
        if (!existingPt) {
            status = STATUS_UNSUCCESSFUL;
            redundantPt = newPt;
            goto Exit;
        }

        PEPT_ENTRY existingPte = &existingPt[EPT_PT_INDEX(plan.PageGpa)];
        if (!existingPte->Fields.Read) {
            status = STATUS_UNSUCCESSFUL;
            redundantPt = newPt;
            goto Exit;
        }

        UINT64 existingHpa = (UINT64)existingPte->Fields.PhysAddr << 12;
        UINT64 expectedHpa = plan.OriginalHpa +
                             (UINT64)EPT_PT_INDEX(plan.PageGpa) * PAGE_SIZE;
        if (existingHpa != expectedHpa) {
            status = STATUS_RETRY;
            redundantPt = newPt;
            goto Exit;
        }

        if (OutPte) *OutPte = existingPte;
        redundantPt = newPt;
        NptInvalidateAll();
        status = STATUS_SUCCESS;
        goto Exit;
    }

    UINT64 currentHpa = (UINT64)pde->Fields.PhysAddr << 12;
    if (currentHpa != plan.OriginalHpa) {
        status = STATUS_RETRY;
        redundantPt = newPt;
        goto Exit;
    }

    pde->Value = 0;
    pde->Fields.Read      = 1;
    pde->Fields.Write     = 1;
    pde->Fields.Execute   = 1;
    pde->Fields.LargePage = 0;
    pde->Fields.PhysAddr  = NptPhysOf(newPt) >> 12;

    if (OutPte) *OutPte = &newPt[EPT_PT_INDEX(plan.PageGpa)];

    NptInvalidateAll();
    status = STATUS_SUCCESS;

Exit:
    SpinRelease(&g_Npt.Lock);
    if (redundantPt) HvPtPoolFree(redundantPt);
    return status;
}

// ============================================================================
//  Segment descriptor helpers.
// ============================================================================

// Convert a 64-bit descriptor's attribute bits into the VMCB 16-bit Attrib
// layout: Type[3:0], S[4], DPL[6:5], P[7], AVL[8], L[9], DB[10], G[11].
static UINT16 SvmDescriptorAttrib(const SEGMENT_DESCRIPTOR64* Desc)
{
    UINT16 attrib = 0;

    attrib |= (UINT16)(Desc->Type & 0x0F);
    attrib |= (UINT16)((Desc->S   & 0x01) << 4);
    attrib |= (UINT16)((Desc->Dpl & 0x03) << 5);
    attrib |= (UINT16)((Desc->P   & 0x01) << 7);
    attrib |= (UINT16)((Desc->Avl & 0x01) << 8);
    attrib |= (UINT16)((Desc->L   & 0x01) << 9);
    attrib |= (UINT16)((Desc->Db  & 0x01) << 10);
    attrib |= (UINT16)((Desc->G   & 0x01) << 11);

    return attrib;
}

// Read a GDT descriptor and encode it into a VMCB segment save field.
static BOOLEAN SvmReadSegment(UINT16 Selector, VMCB_SEG* Seg)
{
    if ((Selector & ~3U) == 0) {
        Seg->Selector = Selector;
        Seg->Attrib   = 0;
        Seg->Limit    = 0;
        Seg->Base     = 0;
        return TRUE;
    }

    if (Selector & 0x4)
        return FALSE;

    DESCRIPTOR_TABLE_REGISTER64 gdtr = {};
    __sgdt(&gdtr);

    UINT32 offset = Selector & ~0x7U;
    if ((UINT64)offset + sizeof(SEGMENT_DESCRIPTOR64) > (UINT64)gdtr.Limit + 1ULL)
        return FALSE;

    const SEGMENT_DESCRIPTOR64* desc =
        (const SEGMENT_DESCRIPTOR64*)(gdtr.Base + offset);

    UINT64 base = 0;
    base |= (UINT64)desc->Base15_0;
    base |= (UINT64)desc->Base23_16 << 16;
    base |= (UINT64)desc->Base31_24 << 24;
    base |= (UINT64)desc->Base63_32 << 32;

    UINT32 limit = (UINT32)desc->Limit15_0 |
                   ((UINT32)desc->Limit19_16 << 16);
    if (desc->G)
        limit = (limit << 12) | 0xFFF;

    Seg->Selector = Selector;
    Seg->Attrib   = SvmDescriptorAttrib(desc);
    Seg->Limit    = limit;
    Seg->Base     = base;

    return TRUE;
}

static VOID SvmSetupSegment(
    VMCB_SEG* Seg, UINT16 Selector, UINT64 Base, UINT32 Limit, UINT16 Attrib)
{
    Seg->Selector = Selector;
    Seg->Attrib   = Attrib;
    Seg->Limit    = Limit;
    Seg->Base     = Base;
}

extern "C" UINT16 VmxReadTr(VOID);

// ============================================================================
//  VMCB initialisation.
// ============================================================================
static NTSTATUS SvmInitializeVmcb(PPER_CPU_CONTEXT Cpu)
{
    int regs[4] = {};

    __cpuid(regs, 0x80000000);
    if ((UINT32)regs[0] < 0x8000000A)
        return STATUS_NOT_SUPPORTED;

    __cpuid(regs, 0x8000000A);
    if (!(regs[3] & 0x1))
        return STATUS_NOT_SUPPORTED;

    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    RtlZeroMemory(vmcb, sizeof(VMCB));

    // ---- Control area: intercepts ----
    // CPUID and VMMCALL only. With NPT active, #PF and CR0/CR3/CR4 accesses
    // are resolved by hardware and must not be intercepted.
    vmcb->Control.InterceptMisc1 |= SVM_INTERCEPT_CPUID;
    vmcb->Control.InterceptMisc2 |= SVM_INTERCEPT_VMMCALL;
    vmcb->Control.InterceptExceptions |= SVM_INTERCEPT_DB;

    // ---- Control area: NPT ----
    vmcb->Control.Asid      = SVM_GUEST_ASID;
    vmcb->Control.NestedCtl = SVM_NPT_ENABLE;
    vmcb->Control.NestedCr3 = g_Npt.Pml4Phys;

    // ---- Control area: MSR bitmap ----
    if (Cpu->MsrBitmapVa) {
        vmcb->Control.MsrpmBasePa =
            MmGetPhysicalAddress(Cpu->MsrBitmapVa).QuadPart & ~0xFFFULL;
    }

    // ---- Save area: control registers ----
    vmcb->Save.Cr0  = __readcr0();
    vmcb->Save.Cr3  = __readcr3();
    vmcb->Save.Cr4  = __readcr4() | X86_CR4_PAE;
    vmcb->Save.Efer = __readmsr(MSR_IA32_EFER) | X86_EFER_SVME;
    vmcb->Save.Dr7  = 0x400;

    // ---- Save area: segments ----
    DESCRIPTOR_TABLE_REGISTER64 gdtr = {};
    DESCRIPTOR_TABLE_REGISTER64 idtr = {};
    __sgdt(&gdtr);
    __sidt(&idtr);

    VMCB_SEG cs = {};
    VMCB_SEG ss = {};
    VMCB_SEG ds = {};
    VMCB_SEG es = {};
    VMCB_SEG fs = {};
    VMCB_SEG gs = {};
    VMCB_SEG tr = {};

    if (!SvmReadSegment(__readcs(), &cs)) return STATUS_UNSUCCESSFUL;
    if (!SvmReadSegment(__readss(), &ss)) return STATUS_UNSUCCESSFUL;
    if (!SvmReadSegment(__readds(), &ds)) return STATUS_UNSUCCESSFUL;
    if (!SvmReadSegment(__reades(), &es)) return STATUS_UNSUCCESSFUL;
    if (!SvmReadSegment(__readfs(), &fs)) return STATUS_UNSUCCESSFUL;
    if (!SvmReadSegment(__readgs(), &gs)) return STATUS_UNSUCCESSFUL;

    UINT16 trSelector = VmxReadTr();
    if (!SvmReadSegment(trSelector, &tr)) return STATUS_UNSUCCESSFUL;

    fs.Base = __readmsr(MSR_IA32_FS_BASE);
    gs.Base = __readmsr(MSR_IA32_GS_BASE);

    vmcb->Save.Cs = cs;
    vmcb->Save.Ss = ss;
    vmcb->Save.Ds = ds;
    vmcb->Save.Es = es;
    vmcb->Save.Fs = fs;
    vmcb->Save.Gs = gs;
    vmcb->Save.Tr = tr;

    SvmSetupSegment(&vmcb->Save.Ldtr, 0, 0, 0, 0x0082);

    SvmSetupSegment(&vmcb->Save.Gdtr, 0, gdtr.Base, gdtr.Limit, 0);
    SvmSetupSegment(&vmcb->Save.Idtr, 0, idtr.Base, idtr.Limit, 0);

    // ---- Save area: RFLAGS, RIP, RSP ----
    // RIP and RSP are overwritten by the launch sequence.
    vmcb->Save.Rflags = __readeflags();
    vmcb->Save.Rip    = 0;
    vmcb->Save.Rsp    = 0;

    return STATUS_SUCCESS;
}

// ============================================================================
//  Per-CPU bring-up.
// ============================================================================
static NTSTATUS SvmSetupCurrentCpu(PVOID /*Context*/)
{
    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu) return STATUS_UNSUCCESSFUL;

    UINT64 efer = __readmsr(MSR_IA32_EFER);
    __writemsr(MSR_IA32_EFER, efer | X86_EFER_SVME);

    NTSTATUS st = SvmInitializeVmcb(cpu);
    if (!NT_SUCCESS(st)) return st;

    cpu->Launched = TRUE;
    return STATUS_SUCCESS;
}

// ============================================================================
//  Launch: VMRUN.
// ============================================================================
static NTSTATUS SvmLaunchCurrentCpu(VOID)
{
    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu) return STATUS_UNSUCCESSFUL;

    UINT8 err = SvmLaunch();
    if (err != 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[HV] VMRUN failed on CPU %u: %u\n", cpu->CpuIndex, err);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

// ============================================================================
//  Teardown.
// ============================================================================
#define HV_HYPERCALL_TEARDOWN  0x48566D78ULL   // 'HVmx'

NTSTATUS SvmHandleTeardownVmcall(PPER_CPU_CONTEXT Cpu)
{
    if (!Cpu || !Cpu->Launched) return STATUS_SUCCESS;

    __svm_clgi();
    __svm_vmsave(Cpu->VmcbPa);

    UINT64 efer = __readmsr(MSR_IA32_EFER);
    __writemsr(MSR_IA32_EFER, efer & ~X86_EFER_SVME);

    Cpu->Launched = FALSE;
    return STATUS_SUCCESS;
}

static VOID SvmTeardownDpc(
    PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu || !cpu->Launched) return;

    __svm_vmmcall(HV_HYPERCALL_TEARDOWN, 0, 0);
}

static VOID SvmTeardown(VOID)
{
    InterlockedExchange(&g_ShuttingDown, 1);

    ULONG count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (count == 0) count = KeQueryActiveProcessorCount(NULL);

    for (ULONG i = 0; i < count; i++) {
        PROCESSOR_NUMBER pn;
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) continue;

        GROUP_AFFINITY aff = {};
        aff.Group = pn.Group;
        aff.Mask  = 1ULL << pn.Number;
        GROUP_AFFINITY old = {};
        KeSetSystemGroupAffinityThread(&aff, &old);
        SvmTeardownDpc(NULL, NULL, NULL, NULL);
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
            if (g_PerCpu[i].VmcbVa) {
                MmFreeContiguousMemory(g_PerCpu[i].VmcbVa);
                g_PerCpu[i].VmcbVa = NULL;
            }
        }
        ExFreePoolWithTag(g_PerCpu, 'HvC0');
        g_PerCpu = NULL;
    }

    if (g_Npt.Pml4) {
        for (UINT32 pml4i = 0; pml4i < 512; pml4i++) {
            PEPT_ENTRY pml4e = &g_Npt.Pml4[pml4i];
            if (!pml4e->Fields.Read) continue;

            PEPT_ENTRY pdpt = NptVaFromPhys((UINT64)pml4e->Fields.PhysAddr << 12);
            if (!pdpt) continue;

            for (UINT32 pdpti = 0; pdpti < 512; pdpti++) {
                PEPT_ENTRY pdpte = &pdpt[pdpti];
                if (!pdpte->Fields.Read) continue;

                PEPT_ENTRY pd = NptVaFromPhys((UINT64)pdpte->Fields.PhysAddr << 12);
                if (!pd) continue;

                for (UINT32 pdi = 0; pdi < 512; pdi++) {
                    PEPT_ENTRY pde = &pd[pdi];
                    if (!pde->Fields.Read) continue;

                    if (!pde->Fields.LargePage) {
                        PVOID ptVa = NptVaFromPhys((UINT64)pde->Fields.PhysAddr << 12);
                        if (ptVa) HvPtPoolFree(ptVa);
                    }
                }

                HvPtPoolFree(pd);
            }

            HvPtPoolFree(pdpt);
        }

        HvPtPoolFree(g_Npt.Pml4);
        g_Npt.Pml4 = NULL;
    }

    HvPtPoolDestroy();
    InterlockedExchange(&g_HypervisorActive, 0);
}

// ============================================================================
//  Remaining callbacks.
// ============================================================================

static NTSTATUS SvmInitialize(VOID)
{
    NTSTATUS st = NptInitialize(g_IdentityRanges, g_IdentityRangeCount);
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
        st = SvmSetupCurrentCpu(NULL);
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
        st = SvmLaunchCurrentCpu();
        KeRevertToUserGroupAffinityThread(&old);
        if (!NT_SUCCESS(st)) return st;
    }

    InterlockedExchange(&g_HypervisorActive, 1);
    return STATUS_SUCCESS;
}

static NTSTATUS SvmBuildIdentityMap(const HV_IDENTITY_RANGE* Ranges, ULONG Count)
{
    return NptInitialize(Ranges, Count);
}

static NTSTATUS SvmProtectRange(UINT64 Gpa, UINT64 Size, UINT64 Perms)
{
    if ((Gpa & 0xFFF) || (Size & 0xFFF) || Size == 0)
        return STATUS_INVALID_PARAMETER;

    if (Perms & NPT_PERM_WRITE)
        Perms |= NPT_PERM_READ;

    SIZE_T pageCount = (SIZE_T)(Size / PAGE_SIZE);
    if (pageCount == 0 || pageCount > ((SIZE_T)-1) / sizeof(UINT64))
        return STATUS_INVALID_PARAMETER;

    PUINT64 originals = (PUINT64)ExAllocatePoolWithTag(
        NonPagedPoolNx, pageCount * sizeof(UINT64), 'HvRB');
    if (!originals) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T committed = 0;

    for (SIZE_T i = 0; i < pageCount; i++) {
        UINT64 pageGpa = Gpa + (UINT64)i * PAGE_SIZE;
        PEPT_ENTRY pte = NULL;

        status = SvmSplitAndGetPte(pageGpa, &pte);
        if (!NT_SUCCESS(status)) break;

        SpinAcquire(&g_Npt.Lock);

        PEPT_ENTRY live = NULL;
        NPT_SPLIT_PLAN dummy = {};
        if (NptLookupLocked(pageGpa, &live, &dummy) != NptLookupDone || !live) {
            SpinRelease(&g_Npt.Lock);
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        originals[committed] = live->Value;

        live->Fields.Read    = (Perms & NPT_PERM_READ)    ? 1 : 0;
        live->Fields.Write   = (Perms & NPT_PERM_WRITE)   ? 1 : 0;
        live->Fields.Execute = (Perms & NPT_PERM_EXECUTE) ? 1 : 0;
        if (live->Fields.Write) live->Fields.Read = 1;

        NptInvalidateAll();
        SpinRelease(&g_Npt.Lock);

        committed++;
    }

    if (!NT_SUCCESS(status)) {
        for (SIZE_T j = 0; j < committed; j++) {
            UINT64 pageGpa = Gpa + (UINT64)j * PAGE_SIZE;

            SpinAcquire(&g_Npt.Lock);

            PEPT_ENTRY live = NULL;
            NPT_SPLIT_PLAN dummy = {};
            if (NptLookupLocked(pageGpa, &live, &dummy) == NptLookupDone && live) {
                live->Value = originals[j];
                NptInvalidateAll();
            }

            SpinRelease(&g_Npt.Lock);
        }

        ExFreePoolWithTag(originals, 'HvRB');
        return status;
    }

    ExFreePoolWithTag(originals, 'HvRB');
    return STATUS_SUCCESS;
}

static NTSTATUS SvmSaveAndGrant(UINT64 Gpa, UINT64 Perms, UINT64* OutOriginal)
{
    UINT64 pageGpa = Gpa & ~0xFFFULL;

    if (Perms & NPT_PERM_WRITE)
        Perms |= NPT_PERM_READ;

    PEPT_ENTRY pte = NULL;
    NTSTATUS st = SvmSplitAndGetPte(pageGpa, &pte);
    if (!NT_SUCCESS(st)) return st;
    if (!pte) return STATUS_UNSUCCESSFUL;

    SpinAcquire(&g_Npt.Lock);

    PEPT_ENTRY live = NULL;
    NPT_SPLIT_PLAN dummy = {};
    if (NptLookupLocked(pageGpa, &live, &dummy) != NptLookupDone || !live) {
        SpinRelease(&g_Npt.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    if (OutOriginal) *OutOriginal = live->Value;

    if (Perms & NPT_PERM_READ)    live->Fields.Read    = 1;
    if (Perms & NPT_PERM_WRITE) { live->Fields.Write   = 1; live->Fields.Read = 1; }
    if (Perms & NPT_PERM_EXECUTE) live->Fields.Execute = 1;

    NptInvalidateAll();
    SpinRelease(&g_Npt.Lock);
    return STATUS_SUCCESS;
}

static NTSTATUS SvmRestoreEntry(UINT64 Gpa, UINT64 OriginalValue)
{
    UINT64 pageGpa = Gpa & ~0xFFFULL;

    SpinAcquire(&g_Npt.Lock);

    PEPT_ENTRY live = NULL;
    NPT_SPLIT_PLAN dummy = {};
    if (NptLookupLocked(pageGpa, &live, &dummy) != NptLookupDone || !live) {
        SpinRelease(&g_Npt.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    live->Value = OriginalValue;
    NptInvalidateAll();
    SpinRelease(&g_Npt.Lock);
    return STATUS_SUCCESS;
}

static VOID SvmArmSingleStep(PPER_CPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb) return;

    vmcb->Save.Rflags |= X86_RFLAGS_TF;
    vmcb->Control.InterceptExceptions |= SVM_INTERCEPT_DB;
}

static VOID SvmDisarmSingleStep(PPER_CPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb) return;

    vmcb->Save.Rflags &= ~X86_RFLAGS_TF;
    vmcb->Control.InterceptExceptions &= ~SVM_INTERCEPT_DB;
}

// AMD EVENTINJ is a 64-bit field: lower 32 bits contain event type/vector,
// bit 11 indicates a valid error code, and bits 63:32 contain the error code.
static VOID SvmInjectException(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa)
{
    UNREFERENCED_PARAMETER(FaultingGpa);

    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu || !cpu->VmcbVa) return;

    PVMCB vmcb = (PVMCB)cpu->VmcbVa;

    UINT64 eventInj = 0;
    eventInj |= (1ULL << 31);              // valid
    eventInj |= (3ULL << 8);               // hardware exception
    eventInj |= (Vector & 0xFF);

    if (Vector == 14) {
        eventInj |= (1ULL << 11);          // error-code valid
        eventInj |= ((UINT64)ErrorCode << 32);
    }

    vmcb->Control.EventInj = eventInj;
}

static VOID SvmInvalidateTlbAll(VOID)
{
    NptInvalidateAll();
}
