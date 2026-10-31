// ============================================================================
//  amd_svm.cpp — AMD-V / SVM / NPT implementation of HV_OPERATIONS.
//
//  All references are to the AMD64 Architecture Programmer's Manual
//  Volume 2: System Programming, Rev. 3.41 (June 2023).
// ============================================================================
#include "common.h"

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

// ============================================================================
//  VMCB layout definitions (AMD APM Vol 2, App. B)
//
//  Control area: 0x000–0x3FF (1024 bytes)
//  Save area   : 0x400–0x7FF (1032 bytes)
// ============================================================================
#pragma pack(push, 1)

typedef struct _VMCB_SEG {
    UINT16 Selector;
    UINT16 Attrib;
    UINT32 Limit;
    UINT64 Base;
} VMCB_SEG;

typedef struct _VMCB_CONTROL_AREA {
    // 0x000 — CR read/write intercepts
    UINT32 InterceptCrRead;
    UINT32 InterceptCrWrite;
    // 0x008 — exception intercepts (bit N = vector N)
    UINT32 InterceptExceptions;
    // 0x00C — misc intercepts 1
    UINT32 InterceptMisc1;
    // 0x010
    UINT32 InterceptMisc2;
    UINT8  Reserved0[0x28];
    // 0x040
    UINT64 IopmBasePa;
    // 0x048
    UINT64 MsrpmBasePa;
    // 0x050
    UINT64 TscOffset;
    UINT8  Reserved1[0x30];
    // 0x088
    UINT32 Asid;
    UINT8  Reserved2[0x4C];
    // 0x0D8
    UINT64 NestedCtl;          // bit 0 = NPT enable
    // 0x0E0
    UINT64 NestedCr3;          // NPT PML4 physical address
    UINT8  Reserved3[0x08];
    // 0x0F0
    UINT64 ExitCode;
    UINT64 ExitInfo1;
    UINT64 ExitInfo2;
    UINT64 ExitIntInfo;
    UINT8  Reserved4[0x10];
    // 0x120
    UINT64 EventInj;
    UINT64 Nrip;
    UINT8  Reserved5[0xE8];
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
//  NPT state
// ============================================================================
typedef struct _AMD_NPT_CONTEXT {
    PEPT_ENTRY  Pml4;
    UINT64      Pml4Phys;
    volatile LONG Lock;
} AMD_NPT_CONTEXT;

static AMD_NPT_CONTEXT g_Npt = {};

// ----------------------------------------------------------------------------
//  NPT entry helpers. AMD NPT uses the same 4-level x64 format as long-mode
//  paging, except that bit 63 (SuppressVe on Intel EPT) is reserved and
//  MUST be zero. We never set it.
// ----------------------------------------------------------------------------
static PVOID NptAllocatePage(VOID)
{
    return HvPtPoolAlloc(NULL);
}

static UINT64 NptPhysOf(PVOID Va)
{
    return MmGetPhysicalAddress(Va).QuadPart & ~0xFFFULL;
}

// Map one 2 MB NPT large page. Bit 7 is the PS flag (large page).
static NTSTATUS NptMap2MB(UINT64 Gpa, UINT64 Hpa, UINT64 Flags)
{
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

    PEPT_ENTRY pdpt  = (PEPT_ENTRY)(pml4e->Fields.PhysAddr << 12);
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

    PEPT_ENTRY pd  = (PEPT_ENTRY)(pdpte->Fields.PhysAddr << 12);
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
    // Bit 63 (SuppressVe) deliberately left 0 — reserved on AMD.
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
//  NPT flush: INVLPGA with ASID 0 and address 0 flushes all NPT entries
//  for the current ASID (AMD APM Vol 2, 15.16.2). We use the raw encoding
//  because the WDK does not expose __invlpga in all toolchain versions.
// ----------------------------------------------------------------------------
static VOID NptInvalidateAll(VOID)
{
    UINT64 rax = 0;   // address 0 = all entries
    UINT64 rcx = 0;   // ASID 0
    __asm {
        mov rax, rax
        mov rcx, rcx
        _emit 0x0F
        _emit 0x01
        _emit 0xDF      // invlpga
    }
}

// ----------------------------------------------------------------------------
//  Phase-1 lookup, identical semantics to the Intel version.
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

    PEPT_ENTRY pdpt  = (PEPT_ENTRY)(pml4e->Fields.PhysAddr << 12);
    PEPT_ENTRY pdpte = &pdpt[EPT_PDPT_INDEX(Gpa)];
    if (!pdpte->Fields.Read) return NptLookupNotMapped;

    PEPT_ENTRY pd  = (PEPT_ENTRY)(pdpte->Fields.PhysAddr << 12);
    PEPT_ENTRY pde = &pd[EPT_PD_INDEX(Gpa)];

    if (pde->Fields.LargePage) {
        OutPlan->PageGpa      = Gpa & ~0xFFFULL;
        OutPlan->PdIndex      = EPT_PD_INDEX(Gpa);
        OutPlan->OriginalHpa  = (pde->Fields.PhysAddr << 12) & ~0x1FFFFFULL;
        OutPlan->OriginalPerm = pde->Value & (NPT_PERM_READ |
                                              NPT_PERM_WRITE |
                                              NPT_PERM_EXECUTE);
        return NptLookupNeedsSplit;
    }
    if (!pde->Fields.Read) return NptLookupNotMapped;

    PEPT_ENTRY pt = (PEPT_ENTRY)(pde->Fields.PhysAddr << 12);
    *OutPte = &pt[EPT_PT_INDEX(Gpa)];
    return NptLookupDone;
}

// ----------------------------------------------------------------------------
//  Deadlock-safe NPT split: pool-pop outside lock, re-validate in phase 3.
// ----------------------------------------------------------------------------
static NTSTATUS SvmSplitAndGetPte(UINT64 Gpa, PEPT_ENTRY* OutPte)
{
    NPT_SPLIT_PLAN    plan = {};
    PEPT_ENTRY        pte  = NULL;
    NPT_LOOKUP_RESULT result;

    SpinAcquire(&g_Npt.Lock);
    result = NptLookupLocked(Gpa, &pte, &plan);
    SpinRelease(&g_Npt.Lock);

    if (result == NptLookupDone) {
        if (OutPte) *OutPte = pte;
        return STATUS_SUCCESS;
    }
    if (result != NptLookupNeedsSplit) return STATUS_UNSUCCESSFUL;

    PEPT_ENTRY newPt = (PEPT_ENTRY)HvPtPoolAlloc(NULL);
    if (!newPt) return STATUS_INSUFFICIENT_RESOURCES;

    for (UINT32 i = 0; i < 512; i++) {
        newPt[i].Value = 0;
        newPt[i].Fields.Read      = (plan.OriginalPerm & NPT_PERM_READ)    ? 1 : 0;
        newPt[i].Fields.Write     = (plan.OriginalPerm & NPT_PERM_WRITE)   ? 1 : 0;
        newPt[i].Fields.Execute   = (plan.OriginalPerm & NPT_PERM_EXECUTE) ? 1 : 0;
        newPt[i].Fields.MemType   = 6;   // WB
        newPt[i].Fields.PhysAddr  = (plan.OriginalHpa +
                                     (UINT64)i * PAGE_SIZE) >> 12;
    }

    SpinAcquire(&g_Npt.Lock);

    PEPT_ENTRY pml4e = &g_Npt.Pml4[EPT_PML4_INDEX(plan.PageGpa)];
    PEPT_ENTRY pdpt  = pml4e->Fields.Read
                     ? (PEPT_ENTRY)(pml4e->Fields.PhysAddr << 12) : NULL;
    PEPT_ENTRY pdpte = pdpt ? &pdpt[EPT_PDPT_INDEX(plan.PageGpa)] : NULL;
    PEPT_ENTRY pd    = (pdpte && pdpte->Fields.Read)
                     ? (PEPT_ENTRY)(pdpte->Fields.PhysAddr << 12) : NULL;
    PEPT_ENTRY pde   = pd ? &pd[plan.PdIndex] : NULL;

    if (!pde || !pde->Fields.Read) {
        HvPtPoolFree(newPt);
        SpinRelease(&g_Npt.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    if (!pde->Fields.LargePage) {
        PEPT_ENTRY existingPt  = (PEPT_ENTRY)(pde->Fields.PhysAddr << 12);
        PEPT_ENTRY existingPte = &existingPt[EPT_PT_INDEX(plan.PageGpa)];

        UINT64 existingHpa = (existingPte->Fields.PhysAddr << 12) & ~0xFFFULL;
        UINT64 expectedHpa = plan.OriginalHpa +
                             (UINT64)EPT_PT_INDEX(plan.PageGpa) * PAGE_SIZE;
        if (existingHpa != expectedHpa) {
            HvPtPoolFree(newPt);
            SpinRelease(&g_Npt.Lock);
            return STATUS_RETRY;
        }

        if (OutPte) *OutPte = existingPte;
        HvPtPoolFree(newPt);
        NptInvalidateAll();
        SpinRelease(&g_Npt.Lock);
        return STATUS_SUCCESS;
    }

    UINT64 currentHpa = (pde->Fields.PhysAddr << 12) & ~0x1FFFFFULL;
    if (currentHpa != plan.OriginalHpa) {
        HvPtPoolFree(newPt);
        SpinRelease(&g_Npt.Lock);
        return STATUS_RETRY;
    }

    pde->Value = 0;
    pde->Fields.Read      = 1;
    pde->Fields.Write     = 1;
    pde->Fields.Execute   = 1;
    pde->Fields.LargePage = 0;
    pde->Fields.PhysAddr  = NptPhysOf(newPt) >> 12;

    if (OutPte) *OutPte = &newPt[EPT_PT_INDEX(plan.PageGpa)];

    NptInvalidateAll();
    SpinRelease(&g_Npt.Lock);
    return STATUS_SUCCESS;
}

// ============================================================================
//  VMCB initialisation
// ============================================================================

// Build a VMCB_SEG from a standard descriptor. In long mode the guest
// selectors must be present and usable; AR attributes are stored in the
// VMCB "Attrib" field in the same 16-bit format as a segment descriptor
// (AMD APM Vol 2, App. B, "VMCB Layout, State Save Area").
static VOID SvmSetupSegment(
    VMCB_SEG* Seg, UINT16 Selector, UINT64 Base, UINT32 Limit, UINT16 Attrib)
{
    Seg->Selector = Selector;
    Seg->Attrib   = Attrib;
    Seg->Limit    = Limit;
    Seg->Base     = Base;
}

// Read the Task Register selector (same asm stub used by Intel).
extern "C" UINT16 VmxReadTr(VOID);

// Walk the GDT to find the TSS base. Identical logic to the Intel version.
static UINT64 SvmReadTssBase(VOID)
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

    UINT64 base = 0;
    base |= (UINT64)desc->Base15_0;
    base |= (UINT64)desc->Base23_16 << 16;
    base |= (UINT64)desc->Base31_24 << 24;
    base |= (UINT64)desc->Base63_32 << 32;
    return base;
}

// Initialise the VMCB for the current CPU.
static NTSTATUS SvmInitializeVmcb(PPER_CPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    RtlZeroMemory(vmcb, sizeof(VMCB));

    // ---- Control area: intercepts ----
    // CPUID — mandatory for an anti-cheat hypervisor.
    vmcb->Control.InterceptMisc1 |= SVM_INTERCEPT_CPUID;

    // VMMCALL — required so we can implement our teardown hypercall.
    vmcb->Control.InterceptMisc2 |= SVM_INTERCEPT_VMMCALL;

    // #DB — required for single-stepping (RFLAGS.TF).
    vmcb->Control.InterceptExceptions |= (1U << 1);   // bit 1 = #DB

    // Do NOT intercept #PF, CR0/CR3/CR4, or NPT-related events: with NPT
    // active, the hardware resolves guest page faults and CR updates
    // directly. Trapping them would destroy performance and cause the
    // "infinite trap loop" documented in issue #4.
    // (No bits set for SVM_EXIT_NPF, CR reads/writes, etc.)

    // ---- Control area: NPT ----
    vmcb->Control.NestedCtl = 1;                  // NP_ENABLE = 1
    vmcb->Control.NestedCr3 = g_Npt.Pml4Phys;     // NPT PML4 physical address

    // ---- Control area: MSR bitmap ----
    // Allocate a 2-page MSRPM at PASSIVE_LEVEL (during init only).
    // An all-zero MSRPM means no MSR intercepts.
    // (MSRPM_SIZE = 2 * PAGE_SIZE per KVM convention.)
    // The physical address must be 4 KB aligned.
    if (Cpu->MsrBitmapVa) {
        vmcb->Control.MsrpmBasePa =
            MmGetPhysicalAddress(Cpu->MsrBitmapVa).QuadPart & ~0xFFFULL;
    }

    // ---- Save area: control registers ----
    vmcb->Save.Cr0  = __readcr0();
    vmcb->Save.Cr3  = __readcr3();
    vmcb->Save.Cr4  = __readcr4() | X86_CR4_PAE;   // NPT requires PAE
    vmcb->Save.Efer = __readmsr(MSR_IA32_EFER) | X86_EFER_SVME;
    vmcb->Save.Dr7  = 0x400;

    // ---- Save area: segments ----
    DESCRIPTOR_TABLE_REGISTER64 gdtr = {};
    DESCRIPTOR_TABLE_REGISTER64 idtr = {};
    __sgdt(&gdtr);
    __sidt(&idtr);

    UINT64 trBase = SvmReadTssBase();
    if (trBase == 0) return STATUS_UNSUCCESSFUL;

    UINT64 fsBase = __readmsr(MSR_IA32_FS_BASE);
    UINT64 gsBase = __readmsr(MSR_IA32_GS_BASE);

    // Long-mode segment attributes:
    //   CS: 0x0A9B (L=1, D=0, P=1, S=1, Type=0xB, G=1)
    //   SS/DS/ES/FS/GS: 0x0C93 (D=1, P=1, S=1, Type=0x3, G=1)
    //   TR: 0x008B (P=1, S=0, Type=0xB)
    //   LDTR: 0x0082 (P=1, S=0, Type=0x2) — but unusable in long mode
    SvmSetupSegment(&vmcb->Save.Cs,  0x08, 0,          0xFFFFFFFF, 0x0A9B);
    SvmSetupSegment(&vmcb->Save.Ss,  0x10, 0,          0xFFFFFFFF, 0x0C93);
    SvmSetupSegment(&vmcb->Save.Ds,  0x18, 0,          0xFFFFFFFF, 0x0C93);
    SvmSetupSegment(&vmcb->Save.Es,  0x20, 0,          0xFFFFFFFF, 0x0C93);
    SvmSetupSegment(&vmcb->Save.Fs,  0x28, fsBase,     0xFFFFFFFF, 0x0C93);
    SvmSetupSegment(&vmcb->Save.Gs,  0x30, gsBase,     0xFFFFFFFF, 0x0C93);
    SvmSetupSegment(&vmcb->Save.Ldtr, 0,    0,          0,          0x0082);
    SvmSetupSegment(&vmcb->Save.Tr,  VmxReadTr(), trBase, 0x67,     0x008B);

    // GDTR / IDTR (selector field unused in long mode)
    SvmSetupSegment(&vmcb->Save.Gdtr, 0, gdtr.Base, gdtr.Limit, 0);
    SvmSetupSegment(&vmcb->Save.Idtr, 0, idtr.Base, idtr.Limit, 0);

    // ---- Save area: RFLAGS, RIP, RSP ----
    // RIP and RSP are overwritten by SvmLaunch() in assembly.
    vmcb->Save.Rflags = __readeflags();
    vmcb->Save.Rip    = 0;   // set at launch
    vmcb->Save.Rsp    = 0;   // set at launch

    return STATUS_SUCCESS;
}

// ============================================================================
//  Per-CPU bring-up
// ============================================================================
static NTSTATUS SvmSetupCurrentCpu(PVOID /*Context*/)
{
    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu) return STATUS_UNSUCCESSFUL;

    // Enable SVM by setting EFER.SVME.
    UINT64 efer = __readmsr(MSR_IA32_EFER);
    __writemsr(MSR_IA32_EFER, efer | X86_EFER_SVME);

    NTSTATUS st = SvmInitializeVmcb(cpu);
    if (!NT_SUCCESS(st)) return st;

    cpu->Launched = TRUE;
    return STATUS_SUCCESS;
}

// ============================================================================
//  Launch: VMRUN
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
//  Teardown
//
//  The only safe way to leave guest mode is VMMCALL. The exit handler
//  dispatches HV_HYPERCALL_TEARDOWN to SvmHandleTeardownVmcall(), which
//  executes CLGI, VMSAVE, clears EFER.SVME and returns to bare metal.
// ============================================================================
#define HV_HYPERCALL_TEARDOWN  0x48566D78ULL   // 'HVmx'

NTSTATUS SvmHandleTeardownVmcall(PPER_CPU_CONTEXT Cpu)
{
    if (!Cpu || !Cpu->Launched) return STATUS_SUCCESS;

    // 1. CLGI — disable global interrupts in guest context.
    __svm_clgi();

    // 2. VMSAVE — save the current guest state to the VMCB
    //    (AMD APM Vol 2, 15.20). The VMCB clean bits are cleared so the
    //    CPU will re-read the save area on the next VMRUN.
    __svm_vmsave(Cpu->VmcbPa);

    // 3. Clear EFER.SVME. After this instruction, SVM is disabled and
    //    VMRUN/VMLOAD/VMSAVE/VMMCALL generate #UD (AMD APM 15.5).
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

    // Execute VMMCALL. The exit handler runs SvmHandleTeardownVmcall
    // in host context and disables SVM on this CPU.
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

    // Free per-CPU resources with the exact matching deallocator.
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

    // Free NPT tables.
    if (g_Npt.Pml4) {
        for (UINT32 pml4i = 0; pml4i < 512; pml4i++) {
            PEPT_ENTRY pml4e = &g_Npt.Pml4[pml4i];
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
                        HvPtPoolFree((PVOID)(pde->Fields.PhysAddr << 12));
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
//  Remaining callbacks
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

    for (UINT64 p = Gpa; p < Gpa + Size; p += PAGE_SIZE) {
        PEPT_ENTRY pte = NULL;
        NTSTATUS st = SvmSplitAndGetPte(p, &pte);
        if (!NT_SUCCESS(st)) return st;
        if (!pte) return STATUS_UNSUCCESSFUL;

        SpinAcquire(&g_Npt.Lock);
        pte->Fields.Read    = (Perms & NPT_PERM_READ)    ? 1 : 0;
        pte->Fields.Write   = (Perms & NPT_PERM_WRITE)   ? 1 : 0;
        pte->Fields.Execute = (Perms & NPT_PERM_EXECUTE) ? 1 : 0;
        if (pte->Fields.Write) pte->Fields.Read = 1;
        NptInvalidateAll();
        SpinRelease(&g_Npt.Lock);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS SvmSaveAndGrant(UINT64 Gpa, UINT64 Perms, UINT64* OutOriginal)
{
    UINT64 pageGpa = Gpa & ~0xFFFULL;

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

// AMD single-step: set RFLAGS.TF in the VMCB save area and enable #DB
// intercepts. The next instruction completes, #DB is delivered, and the
// exit handler (which must recognise SVM_EXIT_EXCP_BASE + 1) will call
// SvmDisarmSingleStep().
static VOID SvmArmSingleStep(PPER_CPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb) return;

    vmcb->Save.Rflags |= X86_RFLAGS_TF;
    vmcb->Control.InterceptExceptions |= (1U << 1);   // #DB
}

static VOID SvmDisarmSingleStep(PPER_CPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb) return;

    vmcb->Save.Rflags &= ~X86_RFLAGS_TF;
    vmcb->Control.InterceptExceptions &= ~(1U << 1);  // #DB
}

// Inject a native exception into the guest via the VMCB EVENTINJ field.
// AMD encoding: bit 31 = valid, bits 10:8 = type (3 = exception),
// bits 7:0 = vector; bit 11 = error-code valid.
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
    if (Vector == 14) {                    // #PF has an error code
        eventInj |= (1ULL << 11);          // error-code valid
        vmcb->Control.ExitInfo1 = ErrorCode;  // error code goes in EXITINFO1
    }

    vmcb->Control.EventInj = eventInj;
}

static VOID SvmInvalidateTlbAll(VOID)
{
    NptInvalidateAll();
}
