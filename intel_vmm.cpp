// ============================================================================
//  intel_vmm.cpp — Intel VT-x / EPT vendor backend.
//
//  Everything that touches VMCS, EPT or Intel-specific VM-exit state lives
//  here. Self-contained apart from common.h and the page-table sheet pool in
//  ept_common.cpp.
//
//  Architectural mechanics implemented in this module:
//
//    EPT (Extended Page Tables, SDM Vol 3C ch. 28): a second, guest-invisible
//    translation stage. VMCS_EPTP roots a 4-level walk (walk length 3) that
//    translates guest-physical to host-physical addresses. Leaf descriptors
//    carry an explicit 3-bit MemType in bits 5:3 — Write-Back (6) is
//    mandatory for normal RAM; a zero encoding would present memory as UC
//    and collapse host caching performance. Permission bits R/W/X in [2:0]
//    are checked on every guest access; a failed check produces an
//    EPT-violation exit instead of a memory reference.
//
//    MTF single-stepping: CPU_BASED_MONITOR_TRAP_FLAG causes a VM exit after
//    exactly one guest instruction. The isolation engine flips an EPT leaf
//    open (RelaxPermissions), lets exactly one instruction complete, and the
//    MTF exit restores the journaled strict leaf (RestoreEntry). All journal
//    state lives in the owning core's PCPU_CONTEXT — no shared tracking slot
//    exists, so concurrent single-steps on different cores cannot collide.
//
//    Teardown: the only safe step-down path from guest mode is a VMCALL
//    exit. This module's teardown handler captures the guest resume state
//    while the VMCS is still current, then VMCLEAR -> INVVPID(all-context)
//    -> VMXOFF -> CR4.VMXE clear. It returns a distinct control status so
//    the assembly stub bypasses VMRESUME (whose VMCS is now inactive and
//    would fault fatally) and jumps back to the guest natively.
// ============================================================================
#include "common.h"
#include <intrin.h>

// ----------------------------------------------------------------------------
//  Forward declarations.
// ----------------------------------------------------------------------------
static NTSTATUS VmxInitialize(VOID);
static VOID     VmxTeardown(VOID);
static NTSTATUS VmxProtectRange(UINT64 Gpa, UINT64 Size, ULONG Perms);
static NTSTATUS VmxSaveEntry(PPCPU_CONTEXT Cpu, UINT64 Gpa);
static NTSTATUS VmxRelaxPermissions(PPCPU_CONTEXT Cpu, UINT64 Gpa, ULONG RelaxPerms);
static NTSTATUS VmxRestoreEntry(PPCPU_CONTEXT Cpu);
static VOID     VmxArmSingleStep(PPCPU_CONTEXT Cpu);
static VOID     VmxDisarmSingleStep(PPCPU_CONTEXT Cpu);
static NTSTATUS VmxInjectException(PPCPU_CONTEXT Cpu, UINT32 Vector,
                                   UINT32 ErrorCode, UINT64 FaultingGpa);
static VOID     VmxInvalidateTlbAll(PPCPU_CONTEXT Cpu);

static NTSTATUS VmxSplitAndGetPte(UINT64 Gpa, PEPT_ENTRY* OutPte);
static VOID     EptInveptSingle(VOID);

// ----------------------------------------------------------------------------
//  Dynamic physical->virtual resolver for pool-owned sheets
//  (implemented in ept_common.cpp). EPT descriptors store physical frame
//  numbers; every downward walk re-derives the kernel virtual alias through
//  this tracker. Never reinterpret a physical address as a virtual one.
// ----------------------------------------------------------------------------
PVOID HvPtPoolVaFromPa(UINT64 Phys);

// ----------------------------------------------------------------------------
//  The exported operations table. g_HvOps is bound to this by the init path
//  when the CPU vendor is GenuineIntel.
// ----------------------------------------------------------------------------
HV_OPERATIONS g_IntelOps = {
    HvVendorIntel,
    "Intel VT-x/EPT",
    VmxInitialize,
    VmxTeardown,
    VmxProtectRange,
    VmxSaveEntry,
    VmxRelaxPermissions,
    VmxRestoreEntry,
    VmxArmSingleStep,
    VmxDisarmSingleStep,
    VmxInjectException,
    VmxInvalidateTlbAll,
};

// ----------------------------------------------------------------------------
//  Local constants.
// ----------------------------------------------------------------------------

// 64-bit host-state VMCS fields (SDM Vol 3C App. B) not enumerated in
// common.h because only the Intel backend consumes them.
#define VMCS_HOST_IA32_PAT              0x2C00
#define VMCS_HOST_IA32_EFER             0x2C02

// 2MB large-page geometry for EPT leaves.
#define EPT_2MB_SIZE                    0x200000ULL
#define EPT_2MB_MASK                    0x1FFFFFULL

// Customer-range control status consumed by the assembly teardown wrapper.
// On any other return the stub performs a normal VMRESUME; on this value the
// stub must bypass VMRESUME entirely (the VMCS has been cleared and VMX is
// off), restore the guest GPR frame — including the resume RSP staged in the
// frame's RSP slot and the resume RIP in slot RegRip — and execute a plain
// long-mode jmp back into the guest.
#define HV_STATUS_TEARDOWN_BARE_METAL   ((NTSTATUS)0x20000001L)

// Guest register frame slot reserved for the staged teardown resume RIP.
// The assembly frame is 17 slots: RAX..R15 plus this resume-RIP slot.
#define REG_FRAME_RESUME_RIP            16

// Vectors that architecturally push an error code (SDM Vol 3A ch. 6):
// #DF(8) #TS(10) #NP(11) #SS(12) #GP(13) #PF(14) #AC(17) #CP(21) #VC(29) #SX(30).
#define EPT_ERRCODE_VECTOR_MASK \
    ((1U << 8)  | (1U << 10) | (1U << 11) | (1U << 12) | (1U << 13) | \
     (1U << 14) | (1U << 17) | (1U << 21) | (1U << 29) | (1U << 30))

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
//  EptPhysOf — page-aligned physical address of a pool sheet.
// ----------------------------------------------------------------------------
static UINT64 EptPhysOf(PVOID Va)
{
    return MmGetPhysicalAddress(Va).QuadPart & ~0xFFFULL;
}

// ============================================================================
//  INVEPT / cross-core flush machinery.
// ============================================================================

// ----------------------------------------------------------------------------
//  EptInveptSingle — single-context invalidation (type 1) scoped to the
//  active EPTP, on the executing processor only. Must be called while
//  g_Ept.Lock is held together with the mutation it validates.
// ----------------------------------------------------------------------------
static VOID EptInveptSingle(VOID)
{
    __declspec(align(16)) struct { UINT64 Eptp; UINT64 Reserved; } desc =
        { g_Ept.Eptp, 0 };
    _invept(1, &desc);
}

// ----------------------------------------------------------------------------
//  EptInveptLocalAll — all-context invalidation (type 2) on this processor.
// ----------------------------------------------------------------------------
static VOID EptInveptLocalAll(VOID)
{
    __declspec(align(16)) struct { UINT64 A; UINT64 B; } desc = { 0, 0 };
    _invept(2, &desc);
}

// ----------------------------------------------------------------------------
//  Cross-core EPT-TLB shootdown.
//
//  INVEPT retires cached guest-physical translations on the processor that
//  executes it and on no other. Any EPT permission change is only
//  architecturally visible to a remote core after that core has itself run
//  INVEPT. KeGenericCallDpc dispatches to every active logical processor
//  (bounded by the static boot-time g_CpuCount — hot-plugged cores were
//  never virtualized), each runs a local all-context INVEPT, all cores
//  synchronize, and the caller returns only after the last flush completes.
//
//  Locking: the caller MUST have released g_Ept.Lock before broadcasting —
//  the DPC touches no hypervisor lock, so it can never deadlock against a
//  mutator running on another CPU.
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

// ============================================================================
//  EPT walk primitives. Functions in this section require g_Ept.Lock held.
// ============================================================================

// ----------------------------------------------------------------------------
//  EptWalkPdeLocked — PML4 -> PDPT -> PD walk returning the PD descriptor
//  covering Gpa. Table references are resolved through the canonical
//  physical->virtual tracker; 1GB leaves are never created by this module,
//  so a PDPT descriptor with PS set is treated as a walk fault.
// ----------------------------------------------------------------------------
static PEPT_ENTRY EptWalkPdeLocked(UINT64 Gpa)
{
    if (!g_Ept.Pml4)
        return NULL;

    PEPT_ENTRY pml4e = &g_Ept.Pml4[EPT_PML4_INDEX(Gpa)];
    if (!pml4e->Fields.Read)
        return NULL;

    PEPT_ENTRY pdpt = (PEPT_ENTRY)HvPtPoolVaFromPa(pml4e->Fields.PhysAddr << 12);
    if (!pdpt)
        return NULL;

    PEPT_ENTRY pdpte = &pdpt[EPT_PDPT_INDEX(Gpa)];
    if (!pdpte->Fields.Read || pdpte->Fields.LargePage)
        return NULL;

    PEPT_ENTRY pd = (PEPT_ENTRY)HvPtPoolVaFromPa(pdpte->Fields.PhysAddr << 12);
    if (!pd)
        return NULL;

    return &pd[EPT_PD_INDEX(Gpa)];
}

// ----------------------------------------------------------------------------
//  Phase-1 lookup result / split plan.
// ----------------------------------------------------------------------------
typedef enum _EPT_LOOKUP_RESULT {
    EptLookupDone,
    EptLookupNeedsSplit,
    EptLookupNotMapped,
} EPT_LOOKUP_RESULT;

typedef struct _EPT_SPLIT_PLAN {
    UINT64 PageGpa;
    UINT64 OriginalHpa;      // 2MB-aligned host physical base of the leaf
    UINT64 OriginalPerm;
} EPT_SPLIT_PLAN;

// ----------------------------------------------------------------------------
//  EptLookupLocked — probe the walk for Gpa. If the covering PD descriptor
//  is a 2MB leaf (PS=1), the descriptor image is captured into the plan so
//  the commit phase can re-validate it after the lock has been dropped.
// ----------------------------------------------------------------------------
static EPT_LOOKUP_RESULT EptLookupLocked(
    UINT64 Gpa, PEPT_ENTRY* OutPte, EPT_SPLIT_PLAN* OutPlan)
{
    *OutPte = NULL;

    PEPT_ENTRY pde = EptWalkPdeLocked(Gpa);
    if (!pde)
        return EptLookupNotMapped;

    if (pde->Fields.LargePage) {
        OutPlan->PageGpa      = Gpa & ~0xFFFULL;
        OutPlan->OriginalHpa  = (pde->Fields.PhysAddr << 12) & ~EPT_2MB_MASK;
        OutPlan->OriginalPerm = pde->Value & (EPT_PERM_READ |
                                              EPT_PERM_WRITE |
                                              EPT_PERM_EXECUTE);
        return EptLookupNeedsSplit;
    }

    if (!pde->Fields.Read)
        return EptLookupNotMapped;

    PEPT_ENTRY pt = (PEPT_ENTRY)HvPtPoolVaFromPa(pde->Fields.PhysAddr << 12);
    if (!pt)
        return EptLookupNotMapped;

    *OutPte = &pt[EPT_PT_INDEX(Gpa)];
    return EptLookupDone;
}

// ----------------------------------------------------------------------------
//  EptEnsureDirectoriesLocked — create any missing directory levels on the
//  path to Gpa and return the PD descriptor. Non-leaf descriptors carry
//  R/W/X=1; the MemType bits are architecturally ignored above leaf level.
// ----------------------------------------------------------------------------
static NTSTATUS EptEnsureDirectoriesLocked(UINT64 Gpa, PEPT_ENTRY* OutPde)
{
    if (!g_Ept.Pml4)
        return STATUS_UNSUCCESSFUL;

    PEPT_ENTRY pml4e = &g_Ept.Pml4[EPT_PML4_INDEX(Gpa)];
    if (!pml4e->Fields.Read) {
        PVOID table = HvPtPoolAlloc(NULL);
        if (!table) return STATUS_INSUFFICIENT_RESOURCES;
        pml4e->Value = 0;
        pml4e->Fields.Read     = 1;
        pml4e->Fields.Write    = 1;
        pml4e->Fields.Execute  = 1;
        pml4e->Fields.PhysAddr = EptPhysOf(table) >> 12;
    }

    PEPT_ENTRY pdpt = (PEPT_ENTRY)HvPtPoolVaFromPa(pml4e->Fields.PhysAddr << 12);
    if (!pdpt) return STATUS_UNSUCCESSFUL;

    PEPT_ENTRY pdpte = &pdpt[EPT_PDPT_INDEX(Gpa)];
    if (!pdpte->Fields.Read) {
        PVOID table = HvPtPoolAlloc(NULL);
        if (!table) return STATUS_INSUFFICIENT_RESOURCES;
        pdpte->Value = 0;
        pdpte->Fields.Read     = 1;
        pdpte->Fields.Write    = 1;
        pdpte->Fields.Execute  = 1;
        pdpte->Fields.PhysAddr = EptPhysOf(table) >> 12;
    }

    PEPT_ENTRY pd = (PEPT_ENTRY)HvPtPoolVaFromPa(pdpte->Fields.PhysAddr << 12);
    if (!pd) return STATUS_UNSUCCESSFUL;

    *OutPde = &pd[EPT_PD_INDEX(Gpa)];
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  EptMap2MbLocked — install one 2MB leaf. PS=1, MemType=WB (6) is mandatory
//  for RAM. Re-running over an identical mapping is a no-op, which makes the
//  identity-map builder idempotent.
// ----------------------------------------------------------------------------
static NTSTATUS EptMap2MbLocked(UINT64 Gpa, UINT64 Hpa, ULONG Perms)
{
    if ((Gpa & EPT_2MB_MASK) || (Hpa & EPT_2MB_MASK))
        return STATUS_INVALID_PARAMETER;

    PEPT_ENTRY pde = NULL;
    NTSTATUS status = EptEnsureDirectoriesLocked(Gpa, &pde);
    if (!NT_SUCCESS(status))
        return status;

    EPT_ENTRY leaf;
    leaf.Value = 0;
    leaf.Fields.Read      = (Perms & EPT_PERM_READ)    ? 1 : 0;
    leaf.Fields.Write     = (Perms & EPT_PERM_WRITE)   ? 1 : 0;
    leaf.Fields.Execute   = (Perms & EPT_PERM_EXECUTE) ? 1 : 0;
    leaf.Fields.MemType   = 6;                          // Write-Back
    leaf.Fields.LargePage = 1;
    leaf.Fields.PhysAddr  = Hpa >> 12;                  // bits [51:21] consume

    if (pde->Fields.Read)
        return (pde->Value == leaf.Value) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    pde->Value = leaf.Value;
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  EptMap4KbLocked — install one 4KB leaf (MemType=WB). If the covering PD
//  descriptor is already a 2MB leaf identity-mapping this GPA, the request
//  is already satisfied. Existing identical leaves are accepted (idempotent
//  rebuilds); conflicting live entries are rejected.
// ----------------------------------------------------------------------------
static NTSTATUS EptMap4KbLocked(UINT64 Gpa, UINT64 Hpa, ULONG Perms)
{
    if ((Gpa & 0xFFF) || (Hpa & 0xFFF))
        return STATUS_INVALID_PARAMETER;

    PEPT_ENTRY pde = NULL;
    NTSTATUS status = EptEnsureDirectoriesLocked(Gpa, &pde);
    if (!NT_SUCCESS(status))
        return status;

    if (pde->Fields.LargePage) {
        // Already covered by a 2MB identity leaf.
        return ((pde->Fields.PhysAddr << 12) & ~EPT_2MB_MASK) ==
               (Gpa & ~EPT_2MB_MASK) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    if (!pde->Fields.Read) {
        PVOID table = HvPtPoolAlloc(NULL);
        if (!table) return STATUS_INSUFFICIENT_RESOURCES;
        pde->Value = 0;
        pde->Fields.Read     = 1;
        pde->Fields.Write    = 1;
        pde->Fields.Execute  = 1;
        pde->Fields.PhysAddr = EptPhysOf(table) >> 12;
    }

    PEPT_ENTRY pt = (PEPT_ENTRY)HvPtPoolVaFromPa(pde->Fields.PhysAddr << 12);
    if (!pt)
        return STATUS_UNSUCCESSFUL;

    PEPT_ENTRY pte = &pt[EPT_PT_INDEX(Gpa)];
    EPT_ENTRY leaf;
    leaf.Value = 0;
    leaf.Fields.Read     = (Perms & EPT_PERM_READ)    ? 1 : 0;
    leaf.Fields.Write    = (Perms & EPT_PERM_WRITE)   ? 1 : 0;
    leaf.Fields.Execute  = (Perms & EPT_PERM_EXECUTE) ? 1 : 0;
    leaf.Fields.MemType  = 6;                           // Write-Back
    leaf.Fields.PhysAddr = Hpa >> 12;

    if (pte->Fields.Read)
        return (pte->Value == leaf.Value) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    pte->Value = leaf.Value;
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  EptFractionateBlockLocked — map a partially-backed 2MB block as 4KB
//  leaves, restricted to pages actually covered by the flattened RAM list.
//  The uncovered holes (MMIO / reserved apertures) stay not-present, so no
//  EPT leaf ever presents MMIO with a WB MemType — that combination is an
//  EPT misconfiguration on hardware that honors MTRR/EPT consistency.
// ----------------------------------------------------------------------------
static NTSTATUS EptFractionateBlockLocked(
    UINT64 BlockGpa, const HV_IDENTITY_RANGE* Flat, ULONG Count)
{
    const UINT64 blockEnd = BlockGpa + EPT_2MB_SIZE;

    for (ULONG i = 0; i < Count; i++) {
        UINT64 start = Flat[i].Base;
        UINT64 end   = Flat[i].Base + Flat[i].Size;

        if (end <= BlockGpa || start >= blockEnd)
            continue;
        if (start < BlockGpa) start = BlockGpa;
        if (end > blockEnd)   end   = blockEnd;

        for (UINT64 gpa = start; gpa < end; gpa += PAGE_SIZE) {
            NTSTATUS status = EptMap4KbLocked(gpa, gpa, EPT_PERM_RWX);
            if (!NT_SUCCESS(status))
                return status;
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
//  Identity-map construction (boot time, PASSIVE_LEVEL).
// ============================================================================

// ----------------------------------------------------------------------------
//  EptFlattenRanges — sort and coalesce the physical allocation descriptors
//  into a canonical, strictly disjoint coverage model. The input may be
//  unsorted, duplicated or overlapping; all 64-bit arithmetic is checked.
// ----------------------------------------------------------------------------
static NTSTATUS EptFlattenRanges(
    const HV_IDENTITY_RANGE* Src, ULONG Count,
    HV_IDENTITY_RANGE** OutFlat, ULONG* OutFlatCount)
{
    *OutFlat = NULL;
    *OutFlatCount = 0;

    if (!Src) {
        Src   = g_IdentityRanges;
        Count = g_IdentityRangeCount;
    }
    if (!Src || Count == 0)
        return STATUS_INVALID_PARAMETER;

    if ((UINT64)Count > (MAXULONG64 / sizeof(HV_IDENTITY_RANGE)))
        return STATUS_INTEGER_OVERFLOW;

    HV_IDENTITY_RANGE* flat = (HV_IDENTITY_RANGE*)ExAllocatePoolWithTag(
        NonPagedPoolNx, (SIZE_T)Count * sizeof(HV_IDENTITY_RANGE), 'HvFl');
    if (!flat)
        return STATUS_INSUFFICIENT_RESOURCES;

    ULONG n = 0;
    for (ULONG i = 0; i < Count; i++) {
        UINT64 base = Src[i].Base;
        UINT64 size = Src[i].Size;
        if (size == 0)
            continue;

        UINT64 end = base + size;
        if (end < base)                 // wrapped descriptor
            continue;

        if (base & 0xFFF) {             // normalize to 4KB granularity
            UINT64 delta = PAGE_SIZE - (base & 0xFFF);
            if (size <= delta)
                continue;
            base += delta;
            size -= delta;
        }
        size &= ~0xFFFULL;
        if (size == 0)
            continue;

        flat[n].Base = base;
        flat[n].Size = size;
        n++;
    }

    if (n == 0) {
        ExFreePoolWithTag(flat, 'HvFl');
        return STATUS_INVALID_PARAMETER;
    }

    for (ULONG i = 1; i < n; i++) {     // insertion sort by base
        HV_IDENTITY_RANGE tmp = flat[i];
        ULONG j = i;
        while (j > 0 && flat[j - 1].Base > tmp.Base) {
            flat[j] = flat[j - 1];
            j--;
        }
        flat[j] = tmp;
    }

    ULONG m = 0;                        // coalesce overlapping/adjacent
    for (ULONG i = 0; i < n; i++) {
        if (m == 0) {
            flat[m++] = flat[i];
            continue;
        }
        HV_IDENTITY_RANGE* prev = &flat[m - 1];
        UINT64 prevEnd = prev->Base + prev->Size;
        if (prevEnd < prev->Base) prevEnd = MAXULONG64;
        UINT64 curEnd = flat[i].Base + flat[i].Size;
        if (curEnd < flat[i].Base) curEnd = MAXULONG64;

        if (flat[i].Base <= prevEnd) {
            if (curEnd > prevEnd)
                prev->Size = curEnd - prev->Base;
        } else {
            flat[m++] = flat[i];
        }
    }

    *OutFlat = flat;
    *OutFlatCount = m;
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  EptBuildIdentityMap — boot-time identity map over reported RAM.
//
//  Fully-covered 2MB blocks install one 2MB leaf; blocks that intersect MMIO
//  or reserved apertures are fractionated into 4KB leaves covering only the
//  RAM pages. Blocks shared by the tail of one range and the head of the
//  next are always fractionated, which covers their union and keeps the
//  builder exactly-once by construction (all map primitives are idempotent).
// ----------------------------------------------------------------------------
static NTSTATUS EptBuildIdentityMap(const HV_IDENTITY_RANGE* Ranges, ULONG Count)
{
    HV_IDENTITY_RANGE* flat = NULL;
    ULONG flatCount = 0;

    NTSTATUS status = EptFlattenRanges(Ranges, Count, &flat, &flatCount);
    if (!NT_SUCCESS(status))
        return status;

    if (!g_Ept.Pml4) {
        g_Ept.Pml4 = (PEPT_ENTRY)HvPtPoolAlloc(NULL);
        if (!g_Ept.Pml4) {
            ExFreePoolWithTag(flat, 'HvFl');
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(g_Ept.Pml4, PAGE_SIZE);
        g_Ept.Pml4Phys = EptPhysOf(g_Ept.Pml4);
        g_Ept.Lock = 0;
    }

    SpinAcquire(&g_Ept.Lock);

    NTSTATUS mapStatus = STATUS_SUCCESS;
    UINT64   prevLastBlock = MAXULONG64;

    for (ULONG i = 0; i < flatCount && NT_SUCCESS(mapStatus); i++) {
        const UINT64 firstBlock = flat[i].Base & ~EPT_2MB_MASK;
        const UINT64 lastBlock  = (flat[i].Base + flat[i].Size - 1) & ~EPT_2MB_MASK;
        const UINT64 rangeEnd   = flat[i].Base + flat[i].Size;

        for (UINT64 block = firstBlock; ; block += EPT_2MB_SIZE) {
            const BOOLEAN sharedWithPrevRange = (i > 0 && block == prevLastBlock);
            const BOOLEAN fullyCovered = (flat[i].Base <= block) &&
                                         (rangeEnd >= block + EPT_2MB_SIZE);

            if (sharedWithPrevRange || !fullyCovered) {
                mapStatus = EptFractionateBlockLocked(block, flat, flatCount);
            } else {
                mapStatus = EptMap2MbLocked(block, block, EPT_PERM_RWX);
            }

            if (!NT_SUCCESS(mapStatus))
                break;
            if (block >= lastBlock)
                break;
        }

        prevLastBlock = lastBlock;
    }

    SpinRelease(&g_Ept.Lock);
    ExFreePoolWithTag(flat, 'HvFl');

    if (!NT_SUCCESS(mapStatus))
        return mapStatus;

    // EPTP layout (SDM Vol 3C 28.2.2):
    //   bits 2:0    = 3   (4-level walk)
    //   bits 5:3    = 6   (Write-Back memtype)
    //   bit  6      = accessed/dirty enable, only when the CPU reports it
    //   bits 51:12  = PML4 physical address
    UINT64 eptCaps = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
    if (!(eptCaps & (1ULL << 14)))       // EPT Write-Back memtype support
        return STATUS_NOT_SUPPORTED;

    g_Ept.Eptp = (g_Ept.Pml4Phys & 0x000FFFFFFFFFF000ULL)
               | (3ULL << 0)
               | (6ULL << 3);
    if (eptCaps & (1ULL << 21))          // accessed/dirty bits supported
        g_Ept.Eptp |= (1ULL << 6);

    return STATUS_SUCCESS;
}

// ============================================================================
//  Two-phase 2MB -> 4KB split with bounded retries.
// ============================================================================

// ----------------------------------------------------------------------------
//  VmxSplitGetPteInternal — one attempt of the deadlock-safe split.
//
//  Phase 1 (g_Ept.Lock held)  : probe the walk. If the GPA resolves to a
//    4KB leaf already, return it. If it lands inside a 2MB leaf, capture
//    the descriptor image into the plan. The lock is then dropped.
//
//  Phase 2 (unlocked)         : pop a 4KB PT sheet from the pre-allocated
//    pool and populate 512 PTEs replicating the 2MB leaf. MemType=6 (WB) is
//    mandatory for RAM. If the pool is empty the split fails with
//    STATUS_INSUFFICIENT_RESOURCES — the exit dispatcher injects #PF; no
//    blocking allocator is ever reachable from this path.
//
//  Phase 3 (g_Ept.Lock reacquired) : re-verify the PD descriptor. A
//    concurrent core may have split or re-pointed it while the lock was
//    open. On a lost race the popped sheet is parked in a local tracker
//    pointer and returned to the pool strictly after the lock is released —
//    the pool's own spinlock is never taken while g_Ept.Lock is held. The
//    caller receives STATUS_RETRY and restarts phase 1.
// ----------------------------------------------------------------------------
static NTSTATUS VmxSplitGetPteInternal(UINT64 Gpa, PEPT_ENTRY* OutPte)
{
    EPT_SPLIT_PLAN    plan  = {};
    PEPT_ENTRY        pte   = NULL;
    NTSTATUS          status;
    PEPT_ENTRY        redundantSheet = NULL;
    EPT_LOOKUP_RESULT probe;

    // ---- Phase 1: probe under lock. ----
    SpinAcquire(&g_Ept.Lock);
    probe = EptLookupLocked(Gpa, &pte, &plan);
    SpinRelease(&g_Ept.Lock);

    if (probe == EptLookupDone) {
        if (OutPte) *OutPte = pte;
        return STATUS_SUCCESS;
    }
    if (probe != EptLookupNeedsSplit)
        return STATUS_UNSUCCESSFUL;

    // ---- Phase 2: allocate and populate the new PT sheet, unlocked. ----
    PEPT_ENTRY newPt = (PEPT_ENTRY)HvPtPoolAlloc(NULL);
    if (!newPt)
        return STATUS_INSUFFICIENT_RESOURCES;

    for (UINT32 i = 0; i < 512; i++) {
        newPt[i].Value = 0;
        newPt[i].Fields.Read     = (plan.OriginalPerm & EPT_PERM_READ)    ? 1 : 0;
        newPt[i].Fields.Write    = (plan.OriginalPerm & EPT_PERM_WRITE)   ? 1 : 0;
        newPt[i].Fields.Execute  = (plan.OriginalPerm & EPT_PERM_EXECUTE) ? 1 : 0;
        newPt[i].Fields.MemType  = 6;   // Write-Back — mandatory for RAM
        newPt[i].Fields.PhysAddr = (plan.OriginalHpa +
                                    (UINT64)i * PAGE_SIZE) >> 12;
    }

    // ---- Phase 3: re-validate and commit under lock. ----
    SpinAcquire(&g_Ept.Lock);

    PEPT_ENTRY pde = EptWalkPdeLocked(plan.PageGpa);
    if (!pde || !pde->Fields.Read) {
        status = STATUS_UNSUCCESSFUL;
        redundantSheet = newPt;
        goto Exit;
    }

    // Current 2MB host base of the covering descriptor (valid for both the
    // large-leaf and table-pointer shapes; only compared on the leaf path).
    const UINT64 currentHpa = (pde->Fields.PhysAddr << 12) & ~EPT_2MB_MASK;

    if (!pde->Fields.LargePage) {
        // Another core split this 2MB region while the lock was open. Route
        // the caller at the existing 4KB leaf when it matches the captured
        // plan; otherwise the mapping moved under us and the attempt must
        // restart. The freshly built sheet is redundant either way.
        PEPT_ENTRY pt = (PEPT_ENTRY)HvPtPoolVaFromPa(pde->Fields.PhysAddr << 12);
        if (!pt) {
            status = STATUS_UNSUCCESSFUL;
            redundantSheet = newPt;
            goto Exit;
        }

        PEPT_ENTRY existing = &pt[EPT_PT_INDEX(plan.PageGpa)];
        if (!existing->Fields.Read) {
            status = STATUS_UNSUCCESSFUL;
            redundantSheet = newPt;
            goto Exit;
        }

        const UINT64 existingHpa = existing->Fields.PhysAddr << 12;
        const UINT64 expectedHpa = plan.OriginalHpa +
                                   (UINT64)EPT_PT_INDEX(plan.PageGpa) * PAGE_SIZE;
        if (existingHpa != expectedHpa) {
            status = STATUS_RETRY;
            redundantSheet = newPt;
            goto Exit;
        }

        if (OutPte) *OutPte = existing;
        redundantSheet = newPt;
        EptInveptSingle();
        status = STATUS_SUCCESS;
        goto Exit;
    }

    // Still large — validate the HPA is what phase 1 observed.
    if (currentHpa != plan.OriginalHpa) {
        status = STATUS_RETRY;
        redundantSheet = newPt;
        goto Exit;
    }

    // Won the race: re-point the PD descriptor at the new table.
    pde->Value = 0;
    pde->Fields.Read     = 1;
    pde->Fields.Write    = 1;
    pde->Fields.Execute  = 1;
    pde->Fields.LargePage = 0;
    pde->Fields.PhysAddr = EptPhysOf(newPt) >> 12;

    if (OutPte) *OutPte = &newPt[EPT_PT_INDEX(plan.PageGpa)];

    EptInveptSingle();
    status = STATUS_SUCCESS;

Exit:
    SpinRelease(&g_Ept.Lock);

    // Pool return happens strictly outside g_Ept.Lock.
    if (redundantSheet)
        HvPtPoolFree(redundantSheet);

    return status;
}

// ----------------------------------------------------------------------------
//  VmxSplitAndGetPte — hard-bounded retry wrapper (exactly 5 attempts).
//  Multithreaded splits may race and produce STATUS_RETRY; the retry is
//  absorbed entirely inside the allocator so callers always receive a
//  definitive STATUS_SUCCESS or a hard failure — STATUS_RETRY never escapes.
// ----------------------------------------------------------------------------
static NTSTATUS VmxSplitAndGetPte(UINT64 Gpa, PEPT_ENTRY* OutPte)
{
    for (ULONG attempt = 0; attempt < 5; attempt++) {
        NTSTATUS status = VmxSplitGetPteInternal(Gpa, OutPte);
        if (status != STATUS_RETRY)
            return status;
    }
    return STATUS_UNSUCCESSFUL;
}

// ============================================================================
//  Operations-template: memory protection.
// ============================================================================

// ----------------------------------------------------------------------------
//  VmxProtectRange — set permissions on a 4KB-aligned GPA range. Every page
//  is coerced to 4KB granularity first (protection is only expressible at PT
//  level), rewritten under the EPT lock with a local INVEPT, and ONE
//  cross-core all-context INVEPT broadcast is issued after the whole batch.
// ----------------------------------------------------------------------------
static NTSTATUS VmxProtectRange(UINT64 Gpa, UINT64 Size, ULONG Perms)
{
    if ((Gpa & 0xFFF) || (Size & 0xFFF) || Size == 0)
        return STATUS_INVALID_PARAMETER;

    if ((Gpa > MAXULONG64 - Size))
        return STATUS_INVALID_PARAMETER;

    for (UINT64 p = Gpa; p < Gpa + Size; p += PAGE_SIZE) {
        PEPT_ENTRY pte = NULL;
        NTSTATUS status = VmxSplitAndGetPte(p, &pte);
        if (!NT_SUCCESS(status))
            return status;
        if (!pte)
            return STATUS_UNSUCCESSFUL;

        SpinAcquire(&g_Ept.Lock);
        pte->Fields.Read    = (Perms & EPT_PERM_READ)    ? 1 : 0;
        pte->Fields.Write   = (Perms & EPT_PERM_WRITE)   ? 1 : 0;
        pte->Fields.Execute = (Perms & EPT_PERM_EXECUTE) ? 1 : 0;
        if (pte->Fields.Write)
            pte->Fields.Read = 1;               // W implies R
        EptInveptSingle();
        SpinRelease(&g_Ept.Lock);
    }

    // Remote cores still hold pre-change translations in their TLBs; one
    // broadcast flushes every logical processor exactly once for the batch.
    EptInveptBroadcast();
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  VmxSaveEntry — journal the raw strict EPT leaf for the page the current
//  core is about to relax. The journal lives in the core's own PCPU_CONTEXT
//  (SavedPteValue + SingleStepPageGpa), never in a shared array: two cores
//  isolating different pages (or the same page independently) cannot
//  overwrite one another's saved descriptor.
// ----------------------------------------------------------------------------
static NTSTATUS VmxSaveEntry(PPCPU_CONTEXT Cpu, UINT64 Gpa)
{
    if (!Cpu)
        return STATUS_INVALID_PARAMETER;

    const UINT64 pageGpa = Gpa & ~0xFFFULL;

    PEPT_ENTRY pte = NULL;
    NTSTATUS status = VmxSplitAndGetPte(pageGpa, &pte);
    if (!NT_SUCCESS(status))
        return status;

    SpinAcquire(&g_Ept.Lock);

    // Re-walk under the lock: the split above may have raced with another
    // core and the committed leaf must be the one that is journaled.
    PEPT_ENTRY       live = NULL;
    EPT_SPLIT_PLAN   probe = {};
    if (EptLookupLocked(pageGpa, &live, &probe) != EptLookupDone || !live) {
        SpinRelease(&g_Ept.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    Cpu->SavedPteValue     = live->Value;
    Cpu->SingleStepPageGpa = pageGpa;

    SpinRelease(&g_Ept.Lock);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  VmxRelaxPermissions — re-open permission bits on one EPT leaf for the
//  re-execution window of a single step. Only a local INVEPT is required:
//  the relaxation must be visible first on the core that will re-execute;
//  remote cores keep their strict translations and will trap if they touch
//  the page independently.
// ----------------------------------------------------------------------------
static NTSTATUS VmxRelaxPermissions(PPCPU_CONTEXT Cpu, UINT64 Gpa, ULONG RelaxPerms)
{
    UNREFERENCED_PARAMETER(Cpu);

    const UINT64 pageGpa = Gpa & ~0xFFFULL;

    PEPT_ENTRY pte = NULL;
    NTSTATUS status = VmxSplitAndGetPte(pageGpa, &pte);
    if (!NT_SUCCESS(status))
        return status;

    SpinAcquire(&g_Ept.Lock);

    PEPT_ENTRY     live = NULL;
    EPT_SPLIT_PLAN probe = {};
    if (EptLookupLocked(pageGpa, &live, &probe) != EptLookupDone || !live) {
        SpinRelease(&g_Ept.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    if (RelaxPerms & EPT_PERM_READ)
        live->Fields.Read = 1;
    if (RelaxPerms & EPT_PERM_WRITE) {
        live->Fields.Write = 1;
        live->Fields.Read  = 1;             // W implies R
    }
    if (RelaxPerms & EPT_PERM_EXECUTE)
        live->Fields.Execute = 1;

    EptInveptSingle();
    SpinRelease(&g_Ept.Lock);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  VmxRestoreEntry — write the journaled strict descriptor image back over
//  the relaxed leaf, re-sealing the page. Consumes only the core's own
//  PCPU_CONTEXT journal. The caller follows with InvalidateTlbAll to
//  broadcast the re-seal across all cores.
// ----------------------------------------------------------------------------
static NTSTATUS VmxRestoreEntry(PPCPU_CONTEXT Cpu)
{
    if (!Cpu || !Cpu->SingleStepFlipped)
        return STATUS_UNSUCCESSFUL;

    const UINT64 pageGpa = Cpu->SingleStepPageGpa;
    if (pageGpa == 0)
        return STATUS_UNSUCCESSFUL;

    SpinAcquire(&g_Ept.Lock);

    PEPT_ENTRY     live = NULL;
    EPT_SPLIT_PLAN probe = {};
    if (EptLookupLocked(pageGpa, &live, &probe) != EptLookupDone || !live) {
        SpinRelease(&g_Ept.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    live->Value = Cpu->SavedPteValue;

    EptInveptSingle();
    SpinRelease(&g_Ept.Lock);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  VmxArmSingleStep / VmxDisarmSingleStep — toggle CPU_BASED_MTF on the
//  current VMCS. Both are only ever invoked on the core that owns Cpu (from
//  its own exit path), so the read-modify-write targets the active VMCS.
// ----------------------------------------------------------------------------
static VOID VmxArmSingleStep(PPCPU_CONTEXT Cpu)
{
    UNREFERENCED_PARAMETER(Cpu);
    UINT32 ctl = VmRead32(VMCS_PROC_BASED_CTLS);
    ctl |= CPU_BASED_MONITOR_TRAP_FLAG;
    VmWrite32(VMCS_PROC_BASED_CTLS, ctl);
}

static VOID VmxDisarmSingleStep(PPCPU_CONTEXT Cpu)
{
    UNREFERENCED_PARAMETER(Cpu);
    UINT32 ctl = VmRead32(VMCS_PROC_BASED_CTLS);
    ctl &= ~CPU_BASED_MONITOR_TRAP_FLAG;
    VmWrite32(VMCS_PROC_BASED_CTLS, ctl);
}

// ============================================================================
//  Exception injection.
// ============================================================================

// ----------------------------------------------------------------------------
//  VmxInjectException — program the VM-entry interruption-information field
//  (SDM Vol 3C 26.2.1):
//    bit 31    = valid
//    bit 11    = deliver error code
//    bits 10:8 = interruption type (3 = hardware exception)
//    bits 7:0  = vector
//
//  Vectors that architecturally push an error code are resolved through the
//  rigid EPT_ERRCODE_VECTOR_MASK lookup; setting bit 11 for any other vector
//  — or omitting it for these — fails VM-entry consistency checks. The field
//  is rejected outright if a previous event is still pending: two valid
//  events cannot be queued and overwriting one corrupts guest delivery.
//
//  #PF: CR2 is architecturally NOT a VMCS-managed field (SDM Vol 3C 24.4 —
//  the guest-state area enumerates CR0/CR3/CR4/DR7 but excludes CR2), so a
//  fabricated CR2 encoding would fail the field-validity check. The
//  architectural register is shared with the host (VM-exit does not modify
//  CR2), so it is loaded directly before VMRESUME to deliver the guest-
//  visible fault address.
// ----------------------------------------------------------------------------
static NTSTATUS VmxInjectException(
    PPCPU_CONTEXT Cpu, UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa)
{
    if (!Cpu)
        return STATUS_INVALID_PARAMETER;
    if (Vector > 31)
        return STATUS_INVALID_PARAMETER;

    // Reject if an event is already pending for delivery on next entry.
    const UINT32 current = VmRead32(VMCS_ENTRY_INTR_INFO);
    if (current & (1U << 31))
        return STATUS_UNSUCCESSFUL;

    const BOOLEAN hasErrorCode = (EPT_ERRCODE_VECTOR_MASK & (1U << Vector)) != 0;

    UINT32 info = (1U << 31) | (3U << 8) | (Vector & 0xFF);

    if (hasErrorCode) {
        info |= (1U << 11);                       // deliver error code
        VmWrite32(VMCS_ENTRY_EXCEPTION_ERR, ErrorCode);

        if (Vector == 14)
            __writecr2(FaultingGpa);              // CR2: not VMCS-managed
    } else {
        VmWrite32(VMCS_ENTRY_EXCEPTION_ERR, 0);
    }

    VmWrite32(VMCS_ENTRY_INTR_INFO, info);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  VmxInvalidateTlbAll — local all-context INVEPT on the core that owns the
//  exit, followed by a KeGenericCallDpc broadcast that drives a synchronized
//  all-context INVEPT on every active logical processor (bounded by the
//  static boot-time g_CpuCount). This is the only mechanism that makes an
//  EPT permission change architecturally visible SMP-wide: each remote core
//  must execute its own INVEPT.
// ----------------------------------------------------------------------------
static VOID VmxInvalidateTlbAll(PPCPU_CONTEXT Cpu)
{
    UNREFERENCED_PARAMETER(Cpu);

    EptInveptLocalAll();
    EptInveptBroadcast();
}

// ============================================================================
//  Segment and descriptor-table helpers.
// ============================================================================

// SGDT/SIDT store a 16-bit limit immediately followed by the 64-bit base
// with no alignment padding; capture the hardware image into this packed
// alias before reading it through the aligned descriptor-table struct.
#pragma pack(push, 1)
typedef struct _VMX_DTR_RAW {
    UINT16 Limit;
    UINT64 Base;
} VMX_DTR_RAW;
#pragma pack(pop)

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
// the selector returned by STR: 16-byte long-mode system descriptors extend
// the base through bytes 8-11. Bounds-check against GDTR.Limit so a selector
// at the table edge can never read past the last valid byte. Returns 0 on
// any decoding failure.
static UINT64 ReadTssBase(VOID)
{
    VMX_DTR_RAW gdtr = {};
    __sgdt((unsigned char*)&gdtr);

    UINT16 trSelector = VmxReadTr();
    if (trSelector & 0x4)
        return 0;                               // LDT-based, unsupported

    const UINT64 offset = trSelector & ~0x7U;
    if (offset + sizeof(SEGMENT_DESCRIPTOR64) > (UINT64)gdtr.Limit + 1)
        return 0;

    const SEGMENT_DESCRIPTOR64* desc =
        (const SEGMENT_DESCRIPTOR64*)(gdtr.Base + offset);
    return SegmentDescriptorBase64(desc);
}

// Build the VMCS Access Rights (AR) value from decoded descriptor fields:
// Type[3:0] S[4] DPL[6:5] P[7] AVL[12] L[13] DB[14] G[15]; bit 16 marks an
// unusable segment.
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
//  VmxInitializeVmcs — full VMCS programming for one logical processor.
//  The VMCS must be current (VMPTRLD completed) before any field write.
// ============================================================================
static NTSTATUS VmxInitializeVmcs(PPCPU_CONTEXT Cpu)
{
    // ---- 1. Stamp Revision ID onto both regions before VMCLEAR/VMPTRLD ----
    // SDM Vol 3C 24.11.5: the 31-bit revision identifier from
    // IA32_VMX_BASIC[30:0] must be present in the first dword of the VMXON
    // region and the VMCS region. The CPU never writes this field.
    UINT64 vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    UINT32 revisionId = (UINT32)(vmxBasic & 0x7FFFFFFF);

    *(UINT32*)Cpu->VmxonVa = revisionId;
    *(UINT32*)Cpu->VmcsVa  = revisionId;

    if (__vmx_vmclear(&Cpu->VmcsPa) != 0) return STATUS_UNSUCCESSFUL;
    if (__vmx_vmptrld(&Cpu->VmcsPa) != 0) return STATUS_UNSUCCESSFUL;

    // ---- 2. MSR bitmap: 4KB all-zero page (no MSR intercepts) ----
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
    // MSR bitmap + secondary activation only. CR3/DR/HLT/MWAIT are not
    // trapped: trapping without emulation produces an infinite exit loop.
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
    // Host IA32_PAT and IA32_EFER are reloaded from their VMCS fields on
    // every #VMEXIT. Without the load controls, a guest PAT/EFER change
    // leaks into host state at the exit boundary and corrupts host paging
    // or SYSCALL configuration.
    UINT32 exitCtl = VM_EXIT_HOST_ADDR_SPACE_SIZE
                   | VM_EXIT_ACK_INTR_ON_EXIT
                   | VM_EXIT_LOAD_IA32_PAT
                   | VM_EXIT_LOAD_IA32_EFER;
    VmxAdjustControls(&exitCtl, MSR_IA32_VMX_EXIT_CTLS);
    if (!(exitCtl & VM_EXIT_LOAD_IA32_PAT) || !(exitCtl & VM_EXIT_LOAD_IA32_EFER))
        return STATUS_NOT_SUPPORTED;
    VmWrite32(VMCS_EXIT_CTLS, exitCtl);

    // ---- 7. Entry controls ----
    // Symmetrically, guest IA32_PAT/IA32_EFER are loaded from their VMCS
    // fields on every VM entry, guaranteeing register isolation in both
    // directions.
    UINT32 entryCtl = VM_ENTRY_IA32E_MODE
                    | VM_ENTRY_LOAD_IA32_PAT
                    | VM_ENTRY_LOAD_IA32_EFER;
    VmxAdjustControls(&entryCtl, MSR_IA32_VMX_ENTRY_CTLS);
    if (!(entryCtl & VM_ENTRY_LOAD_IA32_PAT) || !(entryCtl & VM_ENTRY_LOAD_IA32_EFER))
        return STATUS_NOT_SUPPORTED;
    VmWrite32(VMCS_ENTRY_CTLS, entryCtl);

    // ---- 8. VMCS link pointer: invalid (no VMCS shadowing) ----
    VmWrite64(VMCS_VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFULL);

    // ---- 9. EPTP ----
    VmWrite64(VMCS_EPTP, g_Ept.Eptp);

    // ---- 10. Guest CR0 / CR4 with Intel fixed-bit masks ----
    UINT64 cr0Fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    UINT64 cr0Fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    UINT64 cr0 = __readcr0();
    cr0 |=  cr0Fixed0;                          // mandatory 1 bits
    cr0 &=  cr0Fixed1;                          // mandatory 0 bits
    VmWrite64(VMCS_GUEST_CR0, cr0);

    UINT64 cr4Fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
    UINT64 cr4Fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);
    UINT64 cr4 = __readcr4() | X86_CR4_VMXE;
    cr4 |=  cr4Fixed0;
    cr4 &=  cr4Fixed1;
    VmWrite64(VMCS_GUEST_CR4, cr4);

    VmWrite64(VMCS_GUEST_CR3, __readcr3());

    // Guest DR7 mirrors the live debug-control register (__readdr(7)).
    // Debuggers and fuzzers may run with non-default DR7 settings; syncing
    // avoids any post-launch DR-access inconsistency.
    VmWrite64(VMCS_GUEST_DR7, __readdr(7));

    // ---- 11. Guest IA32_EFER / IA32_PAT — synchronized host MSR images ----
    const UINT64 efer = __readmsr(MSR_IA32_EFER);
    const UINT64 pat  = __readmsr(MSR_IA32_PAT);
    VmWrite64(VMCS_GUEST_IA32_EFER, efer);
    VmWrite64(VMCS_GUEST_IA32_PAT, pat);

    // ---- 12. Guest segment state ----
    VMX_DTR_RAW gdtrRaw = {};
    VMX_DTR_RAW idtrRaw = {};
    __sgdt((unsigned char*)&gdtrRaw);
    __sidt((unsigned char*)&idtrRaw);

    const UINT64 trBase = ReadTssBase();
    if (trBase == 0) return STATUS_UNSUCCESSFUL;

    // Long-mode flat segments: bases 0, limits 0xFFFFFFFF.
    // CS: L=1, D=0, P=1, DPL=0, S=1, Type=0xB (execute/read, accessed)
    // SS/DS/ES: D=1, P=1, DPL=0, S=1, Type=0x3 (data read/write, accessed)
    const UINT32 csAr = BuildAccessRights(0xB, 1, 0, 1, 0, 1, 0, 1);
    const UINT32 dsAr = BuildAccessRights(0x3, 1, 0, 1, 0, 0, 1, 1);

    VmxSetupGuestSegment(VMCS_GUEST_CS_SEL, VMCS_GUEST_CS_BASE,
                         VMCS_GUEST_CS_LIMIT, VMCS_GUEST_CS_AR,
                         0x08, 0, 0xFFFFFFFF, csAr);
    VmxSetupGuestSegment(VMCS_GUEST_SS_SEL, VMCS_GUEST_SS_BASE,
                         VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_AR,
                         0x10, 0, 0xFFFFFFFF, dsAr);
    VmxSetupGuestSegment(VMCS_GUEST_DS_SEL, VMCS_GUEST_DS_BASE,
                         VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_AR,
                         0x18, 0, 0xFFFFFFFF, dsAr);
    VmxSetupGuestSegment(VMCS_GUEST_ES_SEL, VMCS_GUEST_ES_BASE,
                         VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_AR,
                         0x20, 0, 0xFFFFFFFF, dsAr);

    // FS/GS bases live in MSRs in long mode; the GDT image is stale.
    const UINT64 fsBase = __readmsr(MSR_IA32_FS_BASE);
    const UINT64 gsBase = __readmsr(MSR_IA32_GS_BASE);
    VmxSetupGuestSegment(VMCS_GUEST_FS_SEL, VMCS_GUEST_FS_BASE,
                         VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_AR,
                         0x28, fsBase, 0xFFFFFFFF, dsAr);
    VmxSetupGuestSegment(VMCS_GUEST_GS_SEL, VMCS_GUEST_GS_BASE,
                         VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_AR,
                         0x30, gsBase, 0xFFFFFFFF, dsAr);

    // LDTR: unusable in long mode (AR bit 16), selector/base/limit 0.
    VmWrite16(VMCS_GUEST_LDTR_SEL, 0);
    VmWrite64(VMCS_GUEST_LDTR_BASE, 0);
    VmWrite32(VMCS_GUEST_LDTR_LIMIT, 0);
    VmWrite32(VMCS_GUEST_LDTR_AR, 0x10000);     // unusable

    // TR: base from the GDT walk (16-byte system descriptor); limit 0x67
    // (64-bit TSS), AR 0x8B (busy 64-bit TSS, P=1, DPL=0).
    VmWrite16(VMCS_GUEST_TR_SEL, VmxReadTr());
    VmWrite64(VMCS_GUEST_TR_BASE, trBase);
    VmWrite32(VMCS_GUEST_TR_LIMIT, 0x67);
    VmWrite32(VMCS_GUEST_TR_AR, BuildAccessRights(0xB, 0, 0, 1, 0, 0, 0, 0));

    // GDTR / IDTR: mirror the live host tables.
    VmWrite64(VMCS_GUEST_GDTR_BASE, gdtrRaw.Base);
    VmWrite32(VMCS_GUEST_GDTR_LIMIT, gdtrRaw.Limit);
    VmWrite64(VMCS_GUEST_IDTR_BASE, idtrRaw.Base);
    VmWrite32(VMCS_GUEST_IDTR_LIMIT, idtrRaw.Limit);

    // SYSENTER state: CS from the live MSR (VM-entry consistency field);
    // ESP/EIP explicitly zeroed — a 64-bit guest uses SYSCALL, and stale
    // nonzero values would redirect a legacy sysenter into the host.
    VmWrite32(VMCS_GUEST_SYSENTER_CS, (UINT32)__readmsr(MSR_IA32_SYSENTER_CS));
    VmWrite64(VMCS_GUEST_SYSENTER_ESP, 0);
    VmWrite64(VMCS_GUEST_SYSENTER_EIP, 0);

    // RFLAGS: mask reserved bits (3, 5, 15, 22..63) and force bit 1, which
    // reads as 1 architecturally and is validated by VM-entry checks.
    UINT64 rflags = __readeflags() & 0x3F7FD5ULL;
    rflags |= 0x2ULL;
    VmWrite64(VMCS_GUEST_RFLAGS, rflags);

    // ---- 13. Host state ----
    VmWrite64(VMCS_HOST_CR0, __readcr0());
    VmWrite64(VMCS_HOST_CR3, __readcr3());
    VmWrite64(VMCS_HOST_CR4, __readcr4() | X86_CR4_VMXE);

    // Host PAT/EFER images loaded on every #VMEXIT (exit controls above).
    VmWrite64(VMCS_HOST_IA32_PAT, pat);
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
    VmWrite64(VMCS_HOST_GDTR_BASE, gdtrRaw.Base);
    VmWrite64(VMCS_HOST_IDTR_BASE, idtrRaw.Base);

    // Host SYSENTER state: fully initialized — stale zeroes can trip
    // VM-entry checks on some microarchitectures.
    VmWrite32(VMCS_HOST_SYSENTER_CS, (UINT32)__readmsr(MSR_IA32_SYSENTER_CS));
    VmWrite64(VMCS_HOST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    VmWrite64(VMCS_HOST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    VmWrite64(VMCS_HOST_RSP, Cpu->HostStackTop);
    VmWrite64(VMCS_HOST_RIP, (UINT64)VmxVmExitEntry);

    // CR masks: guest may change benign bits without exiting.
    VmWrite64(VMCS_CR0_GUEST_HOST_MASK, X86_CR0_PE | X86_CR0_NE | X86_CR0_PG);
    VmWrite64(VMCS_CR4_GUEST_HOST_MASK, X86_CR4_PAE);

    return STATUS_SUCCESS;
}

// ============================================================================
//  Per-CPU bring-up.
// ============================================================================

// ----------------------------------------------------------------------------
//  VmxSetupCurrentCpu — runs pinned to one logical processor: enable
//  CR4.VMXE, stamp and activate the VMXON region, program the VMCS.
//  Launched is deliberately NOT set here: a core with VMXON + VMCS ready is
//  not yet executing guest code, and the flag gates VMCALL-based teardown
//  (a VMCALL from root mode would fault). It is raised only after the
//  launch primitive returns successfully.
// ----------------------------------------------------------------------------
static NTSTATUS VmxSetupCurrentCpu(PVOID /*Context*/)
{
    PPCPU_CONTEXT cpu = GetCurrentCpuContext();
    if (!cpu || !cpu->VmxonVa || !cpu->VmcsVa || !cpu->HostStack)
        return STATUS_UNSUCCESSFUL;

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

// ----------------------------------------------------------------------------
//  VmxLaunchCurrentCpu — enter the guest through the assembly primitive.
//  On VMLAUNCH failure the core falls back to bare metal cleanly (VMCLEAR,
//  VMXOFF, CR4.VMXE clear) so a partial multi-CPU launch leaves no core in
//  an undefined root state. Launched is raised only after the primitive
//  reports a successful transition into guest context.
// ----------------------------------------------------------------------------
static NTSTATUS VmxLaunchCurrentCpu(VOID)
{
    PPCPU_CONTEXT cpu = GetCurrentCpuContext();
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
        cpu->Launched = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    cpu->Launched = TRUE;
    return STATUS_SUCCESS;
}

// ============================================================================
//  Teardown.
//
//  VMCALL is the only safe step-down path from guest mode. The exit
//  dispatcher (vmexit.cpp) routes HV_HYPERCALL_TEARDOWN here; the handler
//  below performs the full root-mode step-down and hands control back to
//  the assembly wrapper with HV_STATUS_TEARDOWN_BARE_METAL so VMRESUME —
//  which would now target a cleared VMCS and fault fatally — is bypassed.
// ============================================================================

// ----------------------------------------------------------------------------
//  IntelHandleTeardownVmcall — runs in root mode inside the VMCALL exit.
//
//  Sequence (order is load-bearing):
//    1. Capture VMCS_GUEST_RIP / VMCS_GUEST_RSP into stack storage while the
//       VMCS is still current — after VMXOFF no VMCS field is accessible.
//    2. Launched = FALSE: the core is no longer a live guest from this
//       instant, so nested teardown re-entry is a no-op.
//    3. VMCLEAR: flushes VMCS state to memory and marks the VMCS inactive
//       (VMRESUME against it would fail from this point on).
//    4. INVVPID all-context: retire every cached VPID-tagged translation.
//    5. VMXOFF: leave VMX root operation entirely.
//    6. CR4.VMXE clear: bare metal. VMX instructions now #UD, which is the
//       fence that proves no later code path can touch VMCS state.
//    7. Stage the captured resume state into the guest register frame — RSP
//       into the frame's RSP slot, RIP into the reserved resume slot — and
//       return the distinct control status that makes the assembly wrapper
//       skip VMRESUME, restore the GPRs, and jmp natively back to the guest.
// ----------------------------------------------------------------------------
NTSTATUS IntelHandleTeardownVmcall(UINT64* GuestRegs, PPCPU_CONTEXT Cpu)
{
    if (!GuestRegs || !Cpu)
        return STATUS_INVALID_PARAMETER;
    if (!Cpu->Launched)
        return STATUS_SUCCESS;

    // 1. Safe stack capture while the VMCS is current.
    const UINT64 guestRip = VmRead64(VMCS_GUEST_RIP);
    const UINT64 guestRsp = VmRead64(VMCS_GUEST_RSP);

    // 2. Latch the core as stepped down.
    Cpu->Launched = FALSE;

    // 3. VMCLEAR — VMCS state flushed to memory; VMRESUME now impossible.
    __vmx_vmclear(&Cpu->VmcsPa);

    // 4. INVVPID, all-context (SDM Vol 3C 30.4): flush cached VPID
    //    translations before leaving VMX operation.
    __declspec(align(16)) struct { UINT64 A; UINT64 B; } invvpidDesc = { 0, 0 };
    _invvpid(2, &invvpidDesc);

    // 5. VMXOFF — exit VMX root operation.
    __vmx_vmxoff();

    // 6. Bare metal: clear CR4.VMXE.
    __writecr4(__readcr4() & ~X86_CR4_VMXE);

    // 7. Stage resume state for the assembly jmp-back primitive.
    GuestRegs[RegRsp]              = guestRsp;
    GuestRegs[REG_FRAME_RESUME_RIP] = guestRip;

    return HV_STATUS_TEARDOWN_BARE_METAL;
}

// ----------------------------------------------------------------------------
//  VmxTeardownDpc — executes the teardown VMCALL on one pinned core. The
//  exit dispatcher runs the handler above in root mode; the assembly layer
//  observes the bare-metal status and never returns here.
// ----------------------------------------------------------------------------
static VOID VmxTeardownDpc(
    PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PPCPU_CONTEXT cpu = GetCurrentCpuContext();
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

    // Iterate strictly over the static boot-time CPU count. Runtime
    // hot-plug processors are intentionally not touched: they were never
    // brought up under this hypervisor and own no per-CPU context here.
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

    // Free per-CPU resources with the exact matching deallocator for each
    // allocation API. MsrBitmap is allocated by VmxInitializeVmcs.
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

    // Release the EPT tree before draining the shared sheet pool. Table
    // references are resolved through the canonical physical->virtual
    // tracker; PD descriptors with PS=1 are leaves and own no sheet.
    if (g_Ept.Pml4) {
        for (UINT32 pml4i = 0; pml4i < 512; pml4i++) {
            PEPT_ENTRY pml4e = &g_Ept.Pml4[pml4i];
            if (!pml4e->Fields.Read) continue;

            PEPT_ENTRY pdpt = (PEPT_ENTRY)HvPtPoolVaFromPa(pml4e->Fields.PhysAddr << 12);
            if (!pdpt) continue;

            for (UINT32 pdpti = 0; pdpti < 512; pdpti++) {
                PEPT_ENTRY pdpte = &pdpt[pdpti];
                if (!pdpte->Fields.Read) continue;

                PEPT_ENTRY pd = (PEPT_ENTRY)HvPtPoolVaFromPa(pdpte->Fields.PhysAddr << 12);
                if (!pd) continue;

                for (UINT32 pdi = 0; pdi < 512; pdi++) {
                    PEPT_ENTRY pde = &pd[pdi];
                    if (!pde->Fields.Read) continue;
                    if (!pde->Fields.LargePage) {
                        PEPT_ENTRY pt = (PEPT_ENTRY)HvPtPoolVaFromPa(pde->Fields.PhysAddr << 12);
                        if (pt) HvPtPoolFree(pt);
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
//  Initialization vector.
// ============================================================================

// ----------------------------------------------------------------------------
//  VmxInitialize — ordered phases: sheet pool, boot-time EPT identity map
//  (PASSIVE_LEVEL, g_IdentityRanges already populated), per-core VMXON +
//  VMCS programming under group affinity, then per-core guest launch.
// ----------------------------------------------------------------------------
static NTSTATUS VmxInitialize(VOID)
{
    NTSTATUS status = HvPtPoolInit();
    if (!NT_SUCCESS(status) && status != STATUS_ALREADY_REGISTERED)
        return status;

    status = EptBuildIdentityMap(g_IdentityRanges, g_IdentityRangeCount);
    if (!NT_SUCCESS(status))
        return status;
    if (!g_Ept.Eptp)
        return STATUS_UNSUCCESSFUL;

    ULONG count = g_CpuCount;

    for (ULONG i = 0; i < count; i++) {
        PROCESSOR_NUMBER pn;
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) continue;

        GROUP_AFFINITY aff = {};
        aff.Group = pn.Group;
        aff.Mask  = 1ULL << pn.Number;
        GROUP_AFFINITY old = {};
        KeSetSystemGroupAffinityThread(&aff, &old);
        status = VmxSetupCurrentCpu(NULL);
        KeRevertToUserGroupAffinityThread(&old);
        if (!NT_SUCCESS(status)) return status;
    }

    for (ULONG i = 0; i < count; i++) {
        PROCESSOR_NUMBER pn;
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) continue;

        GROUP_AFFINITY aff = {};
        aff.Group = pn.Group;
        aff.Mask  = 1ULL << pn.Number;
        GROUP_AFFINITY old = {};
        KeSetSystemGroupAffinityThread(&aff, &old);
        status = VmxLaunchCurrentCpu();
        KeRevertToUserGroupAffinityThread(&old);
        if (!NT_SUCCESS(status)) return status;
    }

    InterlockedExchange(&g_HypervisorActive, 1);
    return STATUS_SUCCESS;
}
