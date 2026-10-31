// ============================================================================
//  amd_npt.cpp — AMD-V (SVM) Nested Page Table (NPT) module.
//
//  Architectural reference: AMD64 Architecture Programmer's Manual,
//  Volume 2, Chapter 5 (nested paging) and Appendix B (VMCB layout).
//
//  Module contract (consumed by the vendor dispatch layer):
//    * SvmBuildIdentityMap / SvmProtectRange / SvmSaveAndGrant /
//      SvmRestoreEntry / SvmSplitAndGetPte / SvmInvalidateTlbAll bind
//      directly into the vendor-agnostic operations template in common.h.
//    * NptGetPml4Phys() supplies the VMCB n_cr3 field (offset 0x0B0) and
//      NptFreeAll() releases the tree before the shared 4KB sheet pool is
//      destroyed.
//
//  NPT descriptor format implemented here (APM Vol 2, Figures 5-12..5-16):
//    bit  0     P      Present — gates every translated access
//    bit  1     R/W    Write permission (read of a P=1 page is always allowed)
//    bit  2     U/S    User/Supervisor — forced to 1 at every level so CPL=3
//                      fetches and data accesses never raise an unresolvable
//                      nested page fault
//    bit  3     PWT    Page-level write-through — must stay 0
//    bit  4     PCD    Page-level cache disable  — must stay 0
//    bit  7     PAT    4KB leaf: page-attribute-table index (must stay 0)
//                      PD level: PS (page size) — 1 selects a 2MB leaf
//    bit 12            2MB leaf: PAT index (must stay 0)
//    bits 51:12/13     Physical frame number (4KB / 2MB leaf respectively)
//    bit 63     NX     No-execute — the native AMD execution-protection bit;
//                      recognized in nested translations whenever NPT is
//                      enabled (no EFER.NXE dependency for NPT walks)
//
//  Memory-type mechanics: unlike Intel EPT, NPT descriptors carry no explicit
//  MemType encoding. The PWT/PCD/PAT bits index the host PAT/MTRR state the
//  same way ordinary paging does. PWT=PCD=PAT=0 selects PAT entry 0, which is
//  Write-Back on every Windows-programmed PAT — leaving those bits clear is
//  what preserves native caching speeds. Setting them "like EPT MemType=6"
//  would assert PCD/PWT and force RAM uncached.
// ============================================================================
#include "common.h"
#include <intrin.h>

// ----------------------------------------------------------------------------
//  NPT_PTE — AMD nested page-table descriptor.
//
//  common.h is expected to host this union; until it does, the declaration is
//  emitted here under an integration guard so the module compiles against the
//  current header. Define NPT_PTE_DECLARED in common.h (and delete this
//  block) once the union moves there.
// ----------------------------------------------------------------------------
#ifndef NPT_PTE_DECLARED
#define NPT_PTE_DECLARED
#pragma pack(push, 1)
typedef union _NPT_PTE {
    UINT64 Value;
    struct {
        UINT64 Present  : 1;    // [0]      P
        UINT64 Write    : 1;    // [1]      R/W
        UINT64 User     : 1;    // [2]      U/S — always 1 in this module
        UINT64 Pwt      : 1;    // [3]      must stay 0 (WB)
        UINT64 Pcd      : 1;    // [4]      must stay 0 (WB)
        UINT64 Accessed : 1;    // [5]
        UINT64 Dirty    : 1;    // [6]
        UINT64 Pat      : 1;    // [7]      PAT on 4KB leaf / PS on PD entry
        UINT64 Avl1     : 4;    // [11:8]   ignored
        UINT64 PhysAddr : 40;   // [51:12]  frame number (4KB granularity;
                                //           for a 2MB leaf bits [51:13] are the
                                //           frame and bit 12 is the PAT index)
        UINT64 Avl2     : 11;   // [62:52]  ignored
        UINT64 Nx       : 1;    // [63]     no-execute
    } Fields;
} NPT_PTE, *PNPT_PTE;
#pragma pack(pop)
#endif

C_ASSERT(sizeof(NPT_PTE) == sizeof(UINT64));

// ----------------------------------------------------------------------------
//  NPT descriptor bit masks (raw-value construction paths).
// ----------------------------------------------------------------------------
#define NPT_PTE_PRESENT             (1ULL <<  0)
#define NPT_PTE_WRITE               (1ULL <<  1)
#define NPT_PTE_USER                (1ULL <<  2)
#define NPT_PTE_PWT                 (1ULL <<  3)
#define NPT_PTE_PCD                 (1ULL <<  4)
#define NPT_PTE_ACCESSED            (1ULL <<  5)
#define NPT_PTE_DIRTY               (1ULL <<  6)
#define NPT_PTE_PAT                 (1ULL <<  7)   // 4KB leaf PAT index
#define NPT_PTE_PS                  (1ULL <<  7)   // PD entry page-size flag
#define NPT_PTE_NX                  (1ULL << 63)

#define NPT_PAGE_SIZE               0x1000ULL
#define NPT_PAGE_MASK               0xFFFULL
#define NPT_2MB_SIZE                0x200000ULL
#define NPT_2MB_MASK                0x1FFFFFULL

#define NPT_PA_4K_MASK              0x000FFFFFFFFFF000ULL   // frame bits [51:12]
#define NPT_PA_2M_MASK              0x000FFFFFFFFFFE0000ULL // frame bits [51:13]

//  Four-level walk indices. NPT uses the canonical x86-64 4KB/2MB/1GB
//  geometry: 9 bits of index per level, 512 descriptors per table.
#define NPT_PML4_INDEX(gpa)         (((gpa) >> 39) & 0x1FFULL)
#define NPT_PDPT_INDEX(gpa)         (((gpa) >> 30) & 0x1FFULL)
#define NPT_PD_INDEX(gpa)           (((gpa) >> 21) & 0x1FFULL)
#define NPT_PT_INDEX(gpa)           (((gpa) >> 12) & 0x1FFULL)

//  Non-leaf descriptor template: P=1, R/W=1, U/S=1; PWT=PCD=0 (WB), PS=0
//  (table pointer), NX=0 — bit 63 is only consumed on leaf descriptors, so
//  execution policy is never expressed on directory entries.
#define NPT_DIR_FLAGS               (NPT_PTE_PRESENT | NPT_PTE_WRITE | NPT_PTE_USER)

// ----------------------------------------------------------------------------
//  VMCB TLB maintenance (APM Vol 2, Appendix B). TLB_CONTROL is a byte at
//  control-area offset 0x05C. Encoding 01b orders the processor to flush its
//  entire TLB (all ASIDs, non-global) automatically on the next VMRUN — the
//  architectural control for nested-translation invalidation.
// ----------------------------------------------------------------------------
#define NPT_VMCB_OFF_TLB_CTL        0x05C
#define NPT_TLBCTL_FLUSH_ALL        0x01

// ----------------------------------------------------------------------------
//  Forward declarations.
// ----------------------------------------------------------------------------
extern "C" NTSTATUS SvmSplitAndGetPte(UINT64 Gpa, PEPT_ENTRY* OutPte);
extern "C" VOID     NptFreeAll(VOID);

static VOID NptSignalTlbFlushAll(VOID);

// ============================================================================
//  NPT global state.
// ============================================================================
typedef struct _AMD_NPT_CONTEXT {
    PNPT_PTE     Pml4;          // PML4 table virtual alias (512 descriptors)
    UINT64       Pml4Phys;      // PML4 physical base — loads into n_cr3
    volatile LONG Lock;         // global NPT mutation lock (SpinAcquire)
    volatile LONG FlushEpoch;   // monotonically increases per flush broadcast
} AMD_NPT_CONTEXT;

static AMD_NPT_CONTEXT g_Npt = {};

// ----------------------------------------------------------------------------
//  Split plan — state captured in phase 1 while g_Npt.Lock is held, consumed
//  in phase 3 after the lock has been dropped and reacquired.
// ----------------------------------------------------------------------------
typedef struct _NPT_SPLIT_PLAN {
    UINT64 PageGpa;             // 4KB-aligned GPA being split out
    UINT64 OriginalPde;         // raw 2MB PD descriptor captured at probe time
} NPT_SPLIT_PLAN, *PNPT_SPLIT_PLAN;

typedef enum _NPT_LOOKUP_RESULT {
    NptLookupDone,              // 4KB leaf reached; OutPte is valid
    NptLookupNeedsSplit,        // 2MB leaf covers the GPA; plan captured
    NptLookupNotMapped,         // path not present below the PD level
} NPT_LOOKUP_RESULT;

// ----------------------------------------------------------------------------
//  Block index — distinct, non-overlapping 2MB-aligned segments built from
//  the flattened physical allocation list before any mapping is created.
// ----------------------------------------------------------------------------
typedef struct _NPT_BLOCK_DESC {
    UINT64  BaseGpa;            // 2MB-aligned guest-physical base
    BOOLEAN FullyCovered;       // every byte backed by reported RAM
} NPT_BLOCK_DESC, *PNPT_BLOCK_DESC;

typedef struct _NPT_BLOCK_INDEX {
    PNPT_BLOCK_DESC Desc;
    ULONG           Count;
} NPT_BLOCK_INDEX, *PNPT_BLOCK_INDEX;

// ============================================================================
//  Physical / virtual plumbing.
// ============================================================================

// ----------------------------------------------------------------------------
//  HvPtPoolVaFromPa — canonical address tracker for pool-owned sheets.
//
//  NPT descriptors store physical frame numbers ("allocation links"); every
//  downward walk re-derives the kernel virtual alias from the link.
//  MmGetVirtualForPhysical is valid for any RAM-backed page already mapped in
//  the host page tables, which every sheet popped from the shared pool is.
//  The frame portion is masked to 4KB granularity first: a 2MB leaf carries
//  its PAT index inside what would be bit 12 of a 4KB frame, and feeding a
//  large-leaf value through here would corrupt the alias lookup.
// ----------------------------------------------------------------------------
static PNPT_PTE HvPtPoolVaFromPa(UINT64 Phys)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = Phys & ~NPT_PAGE_MASK;
    return (PNPT_PTE)MmGetVirtualForPhysical(pa);
}

static UINT64 NptPhysOf(PVOID Va)
{
    return MmGetPhysicalAddress(Va).QuadPart & ~NPT_PAGE_MASK;
}

// ----------------------------------------------------------------------------
//  NptAllocSheet — pop a pre-zeroed 4KB sheet from the shared pool.
//
//  An empty NPT table must read as all zeros: P=0 on every descriptor is the
//  architectural encoding of "unmapped at this level", and the walker treats
//  it as a not-present fault rather than dereferencing a bogus frame link.
// ----------------------------------------------------------------------------
static PVOID NptAllocSheet(VOID)
{
    PVOID sheet = HvPtPoolAlloc(NULL);
    if (sheet) RtlZeroMemory(sheet, PAGE_SIZE);
    return sheet;
}

// ============================================================================
//  Descriptor construction.
// ============================================================================

// ----------------------------------------------------------------------------
//  Leaf bit template. P=1 grants read access (AMD NPT has no separate
//  read-suppression encoding); R/W follows policy; U/S=1 unconditionally so
//  CPL=3 activity never faults on user/supervisor checks; PWT, PCD and PAT
//  stay 0, selecting PAT entry 0 (Write-Back) and keeping RAM fully cached;
//  NX is set iff execution is not granted.
// ----------------------------------------------------------------------------
static UINT64 NptLeafBits(UINT64 Perms)
{
    UINT64 bits = NPT_PTE_PRESENT | NPT_PTE_USER;

    if (Perms & NPT_PERM_WRITE)
        bits |= NPT_PTE_WRITE;

    if (!(Perms & NPT_PERM_EXECUTE))
        bits |= NPT_PTE_NX;

    return bits;    // PWT=0, PCD=0, PAT=0  ->  MemType = WB
}

// ----------------------------------------------------------------------------
//  Exact-permission application for SvmProtectRange. AMD NPT cannot express
//  execute-only (there is no read-disable bit and no mode-based execution
//  mask), so requesting any permission keeps the page translated; Perms==0
//  clears P entirely, architecturally hiding the page from the guest.
// ----------------------------------------------------------------------------
static UINT64 NptApplyPermsExact(UINT64 Current, UINT64 Perms)
{
    UINT64 value = Current & ~(NPT_PTE_PRESENT | NPT_PTE_WRITE | NPT_PTE_NX);

    if (Perms & (NPT_PERM_READ | NPT_PERM_WRITE | NPT_PERM_EXECUTE))
        value |= NPT_PTE_PRESENT;
    if (Perms & NPT_PERM_WRITE)
        value |= NPT_PTE_WRITE;
    if (!(Perms & NPT_PERM_EXECUTE))
        value |= NPT_PTE_NX;

    return value;
}

// ============================================================================
//  Locked walk primitives. All functions in this section require g_Npt.Lock.
// ============================================================================

// ----------------------------------------------------------------------------
//  Walk PML4 -> PDPT -> PD and return a pointer to the PD descriptor covering
//  Gpa. 1GB leaves are never created by this module, so a PDPT descriptor
//  with PS=1 is treated as a walk fault rather than misread as a frame link.
// ----------------------------------------------------------------------------
static PNPT_PTE NptWalkPdeLocked(UINT64 Gpa)
{
    if (!g_Npt.Pml4)
        return NULL;

    PNPT_PTE pml4e = &g_Npt.Pml4[NPT_PML4_INDEX(Gpa)];
    if (!pml4e->Fields.Present)
        return NULL;

    PNPT_PTE pdpt = HvPtPoolVaFromPa(pml4e->Fields.PhysAddr << 12);
    if (!pdpt)
        return NULL;

    PNPT_PTE pdpte = &pdpt[NPT_PDPT_INDEX(Gpa)];
    if (!pdpte->Fields.Present || pdpte->Fields.Pat)
        return NULL;

    PNPT_PTE pd = HvPtPoolVaFromPa(pdpte->Fields.PhysAddr << 12);
    if (!pd)
        return NULL;

    return &pd[NPT_PD_INDEX(Gpa)];
}

// ----------------------------------------------------------------------------
//  Create any missing directory levels on the path to Gpa and return the PD
//  descriptor. New directory entries always install NPT_DIR_FLAGS: present,
//  writable, U/S=1, PWT/PCD=0, PS=0, NX=0.
// ----------------------------------------------------------------------------
static NTSTATUS NptEnsureDirectoriesLocked(UINT64 Gpa, PNPT_PTE* OutPde)
{
    if (!g_Npt.Pml4)
        return STATUS_UNSUCCESSFUL;

    PNPT_PTE pml4e = &g_Npt.Pml4[NPT_PML4_INDEX(Gpa)];
    if (!pml4e->Fields.Present) {
        PVOID table = NptAllocSheet();
        if (!table) return STATUS_INSUFFICIENT_RESOURCES;
        pml4e->Value = NPT_DIR_FLAGS | (NptPhysOf(table) & NPT_PA_4K_MASK);
    }

    PNPT_PTE pdpt = HvPtPoolVaFromPa(pml4e->Fields.PhysAddr << 12);
    if (!pdpt) return STATUS_UNSUCCESSFUL;

    PNPT_PTE pdpte = &pdpt[NPT_PDPT_INDEX(Gpa)];
    if (!pdpte->Fields.Present) {
        PVOID table = NptAllocSheet();
        if (!table) return STATUS_INSUFFICIENT_RESOURCES;
        pdpte->Value = NPT_DIR_FLAGS | (NptPhysOf(table) & NPT_PA_4K_MASK);
    }

    PNPT_PTE pd = HvPtPoolVaFromPa(pdpte->Fields.PhysAddr << 12);
    if (!pd) return STATUS_UNSUCCESSFUL;

    *OutPde = &pd[NPT_PD_INDEX(Gpa)];
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  Install one 2MB leaf. Bit 7 of the PD descriptor carries PS=1; the frame
//  number occupies bits [51:13] and bit 12 (the 2MB PAT index) must remain 0
//  for Write-Back. Re-running over an identical mapping is a no-op, which is
//  what makes the identity-map builder idempotent.
// ----------------------------------------------------------------------------
static NTSTATUS NptMapLarge2MbLocked(UINT64 Gpa, UINT64 Hpa, UINT64 Perms)
{
    if ((Gpa & NPT_2MB_MASK) || (Hpa & NPT_2MB_MASK))
        return STATUS_INVALID_PARAMETER;

    PNPT_PTE pde = NULL;
    NTSTATUS status = NptEnsureDirectoriesLocked(Gpa, &pde);
    if (!NT_SUCCESS(status))
        return status;

    UINT64 leaf = NptLeafBits(Perms) | NPT_PTE_PS | (Hpa & NPT_PA_2M_MASK);

    if (pde->Fields.Present)
        return (pde->Value == leaf) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    pde->Value = leaf;
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  Install one 4KB leaf. Bit 7 is the PAT index and must stay 0 (WB); the
//  frame occupies bits [51:12]. A PD descriptor with PS=1 covering the GPA is
//  a structural conflict — the caller is expected to have split it first.
// ----------------------------------------------------------------------------
static NTSTATUS NptMap4KbLocked(UINT64 Gpa, UINT64 Hpa, UINT64 Perms)
{
    if ((Gpa & NPT_PAGE_MASK) || (Hpa & NPT_PAGE_MASK))
        return STATUS_INVALID_PARAMETER;

    PNPT_PTE pde = NULL;
    NTSTATUS status = NptEnsureDirectoriesLocked(Gpa, &pde);
    if (!NT_SUCCESS(status))
        return status;

    if (pde->Fields.Pat)
        return STATUS_UNSUCCESSFUL;

    if (!pde->Fields.Present) {
        PVOID table = NptAllocSheet();
        if (!table) return STATUS_INSUFFICIENT_RESOURCES;
        pde->Value = NPT_DIR_FLAGS | (NptPhysOf(table) & NPT_PA_4K_MASK);
    }

    PNPT_PTE pt = HvPtPoolVaFromPa(pde->Fields.PhysAddr << 12);
    if (!pt)
        return STATUS_UNSUCCESSFUL;

    PNPT_PTE pte = &pt[NPT_PT_INDEX(Gpa)];
    UINT64 leaf = NptLeafBits(Perms) | (Hpa & NPT_PA_4K_MASK);

    if (pte->Fields.Present)
        return (pte->Value == leaf) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    pte->Value = leaf;
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  Fractionate a partially-backed 2MB block into 4KB leaves. Only pages
//  actually covered by the flattened RAM list are mapped; the gaps (MMIO
//  apertures, reserved firmware ranges) stay P=0, so the guest can never
//  establish a translation to hardware with an illegal caching state.
// ----------------------------------------------------------------------------
static NTSTATUS NptFractionateBlockLocked(
    UINT64 BlockGpa, const HV_IDENTITY_RANGE* Flat, ULONG Count)
{
    UINT64 blockEnd = BlockGpa + NPT_2MB_SIZE;

    for (ULONG i = 0; i < Count; i++) {
        UINT64 start = Flat[i].Base;
        UINT64 end   = Flat[i].Base + Flat[i].Size;

        if (end <= BlockGpa || start >= blockEnd)
            continue;
        if (start < BlockGpa) start = BlockGpa;
        if (end > blockEnd)   end   = blockEnd;

        for (UINT64 gpa = start; gpa < end; gpa += NPT_PAGE_SIZE) {
            NTSTATUS status = NptMap4KbLocked(gpa, gpa, NPT_PERM_RWX);
            if (!NT_SUCCESS(status))
                return status;
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
//  Range flattening and block-index construction (boot time, PASSIVE_LEVEL).
// ============================================================================

// ----------------------------------------------------------------------------
//  NptFlattenRanges — sort and coalesce the physical allocation descriptors.
//
//  The input list may be unsorted, duplicated, overlapping or adjacent. Two
//  descriptors that overlap or touch one another are merged so the block
//  index below sees a canonical, strictly disjoint coverage model.
// ----------------------------------------------------------------------------
static NTSTATUS NptFlattenRanges(
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
        if (end < base)             // wrapped descriptor
            continue;

        if (base & NPT_PAGE_MASK) { // normalize to 4KB granularity
            UINT64 delta = NPT_PAGE_SIZE - (base & NPT_PAGE_MASK);
            if (size <= delta)
                continue;
            base += delta;
            size -= delta;
        }
        size &= ~NPT_PAGE_MASK;
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

    // Insertion sort by base — the descriptor count is small.
    for (ULONG i = 1; i < n; i++) {
        HV_IDENTITY_RANGE tmp = flat[i];
        ULONG j = i;
        while (j > 0 && flat[j - 1].Base > tmp.Base) {
            flat[j] = flat[j - 1];
            j--;
        }
        flat[j] = tmp;
    }

    // Coalesce overlapping / adjacent descriptors in place.
    ULONG m = 0;
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
//  NptBuildBlockIndex — enumerate distinct 2MB-aligned segments.
//
//  Each flattened range is decomposed into the 2MB blocks it touches. Blocks
//  are visited in ascending order, so a block shared by the tail of one range
//  and the head of the next (two allocations falling into or crossing the
//  same 2MB window) is detected by comparing against the last emitted record
//  and merged instead of appended — the allocator maps it exactly once.
//
//  Coverage: after coalescing, disjoint ranges can never jointly fill a block
//  (a zero-width gap would have been merged), so a block is FullyCovered iff
//  a single range spans the entire 2MB window. Partially backed blocks
//  intersect MMIO or reserved apertures and are fractionated at map time.
// ----------------------------------------------------------------------------
static NTSTATUS NptBuildBlockIndex(
    const HV_IDENTITY_RANGE* Flat, ULONG Count, PNPT_BLOCK_INDEX OutIndex)
{
    RtlZeroMemory(OutIndex, sizeof(*OutIndex));

    // Exact worst-case capacity: one record per block touched by each range,
    // before deduplication. Computed once so no growth path exists.
    UINT64 capacity = 0;
    for (ULONG i = 0; i < Count; i++) {
        UINT64 first = Flat[i].Base & ~NPT_2MB_MASK;
        UINT64 last  = (Flat[i].Base + Flat[i].Size - 1) & ~NPT_2MB_MASK;
        capacity += ((last - first) >> 21) + 1;
    }
    if (capacity == 0 || capacity > MAXULONG)
        return STATUS_INTEGER_OVERFLOW;

    PNPT_BLOCK_DESC desc = (PNPT_BLOCK_DESC)ExAllocatePoolWithTag(
        NonPagedPoolNx, (SIZE_T)capacity * sizeof(NPT_BLOCK_DESC), 'HvBl');
    if (!desc)
        return STATUS_INSUFFICIENT_RESOURCES;

    ULONG count = 0;
    for (ULONG i = 0; i < Count; i++) {
        UINT64 first    = Flat[i].Base & ~NPT_2MB_MASK;
        UINT64 last     = (Flat[i].Base + Flat[i].Size - 1) & ~NPT_2MB_MASK;
        UINT64 rangeEnd = Flat[i].Base + Flat[i].Size;

        for (UINT64 block = first; ; block += NPT_2MB_SIZE) {
            BOOLEAN full = (Flat[i].Base <= block) &&
                           (rangeEnd >= block + NPT_2MB_SIZE);

            if (count > 0 && desc[count - 1].BaseGpa == block) {
                // Shared block: record the union of coverage. With coalesced
                // input this can only ever stay partial.
                desc[count - 1].FullyCovered =
                    (BOOLEAN)(desc[count - 1].FullyCovered && full);
            } else {
                desc[count].BaseGpa     = block;
                desc[count].FullyCovered = full;
                count++;
            }

            if (block >= last)
                break;
        }
    }

    OutIndex->Desc  = desc;
    OutIndex->Count = count;
    return STATUS_SUCCESS;
}

// ============================================================================
//  Identity-map construction.
// ============================================================================

// ----------------------------------------------------------------------------
//  SvmBuildIdentityMap — idempotent, overlap-safe identity mapping.
//
//  Sequence: flatten the physical allocation list, build the 2MB block index,
//  then map. Fully-covered blocks install one 2MB leaf (PS=1); partially
//  backed blocks are fractionated into 4KB leaves so the uncovered holes —
//  MMIO and reserved firmware space — remain architecturally not-present.
//  Every leaf carries PWT=PCD=PAT=0 (Write-Back) and U/S=1.
// ----------------------------------------------------------------------------
extern "C" NTSTATUS SvmBuildIdentityMap(const HV_IDENTITY_RANGE* Ranges, ULONG Count)
{
    HV_IDENTITY_RANGE* flat = NULL;
    ULONG              flatCount = 0;
    NTSTATUS           status;

    status = NptFlattenRanges(Ranges, Count, &flat, &flatCount);
    if (!NT_SUCCESS(status))
        return status;

    NPT_BLOCK_INDEX index;
    status = NptBuildBlockIndex(flat, flatCount, &index);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(flat, 'HvFl');
        return status;
    }

    if (!g_Npt.Pml4) {
        PNPT_PTE pml4 = (PNPT_PTE)NptAllocSheet();
        if (!pml4) {
            ExFreePoolWithTag(index.Desc, 'HvBl');
            ExFreePoolWithTag(flat, 'HvFl');
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        g_Npt.Pml4     = pml4;
        g_Npt.Pml4Phys = NptPhysOf(pml4);
        g_Npt.Lock     = 0;
    }

    SpinAcquire(&g_Npt.Lock);

    NTSTATUS  mapStatus = STATUS_SUCCESS;
    ULONG     fullBlocks = 0;
    ULONG     partialBlocks = 0;

    for (ULONG i = 0; i < index.Count; i++) {
        if (index.Desc[i].FullyCovered) {
            mapStatus = NptMapLarge2MbLocked(
                index.Desc[i].BaseGpa, index.Desc[i].BaseGpa, NPT_PERM_RWX);
            if (NT_SUCCESS(mapStatus)) fullBlocks++;
        } else {
            mapStatus = NptFractionateBlockLocked(
                index.Desc[i].BaseGpa, flat, flatCount);
            if (NT_SUCCESS(mapStatus)) partialBlocks++;
        }

        if (!NT_SUCCESS(mapStatus))
            break;
    }

    SpinRelease(&g_Npt.Lock);

    ExFreePoolWithTag(index.Desc, 'HvBl');
    ExFreePoolWithTag(flat, 'HvFl');

    if (!NT_SUCCESS(mapStatus)) {
        NptFreeAll();
        return mapStatus;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[HV] NPT identity map: %u 2MB blocks, %u fractionated blocks, "
        "n_cr3=%p\n",
        fullBlocks, partialBlocks, (PVOID)(ULONG_PTR)g_Npt.Pml4Phys);

    return STATUS_SUCCESS;
}

// ============================================================================
//  NPT lookup and two-phase 2MB->4KB splitting.
// ============================================================================

// ----------------------------------------------------------------------------
//  NptLookupLocked — probe the walk for Gpa. If the covering PD descriptor is
//  a 2MB leaf (PS=1 at bit 7), the raw descriptor is captured into the plan
//  so phase 3 can re-validate it without holding the lock across the walk.
// ----------------------------------------------------------------------------
static NPT_LOOKUP_RESULT NptLookupLocked(
    UINT64 Gpa, PNPT_PTE* OutPte, PNPT_SPLIT_PLAN OutPlan)
{
    *OutPte = NULL;

    PNPT_PTE pde = NptWalkPdeLocked(Gpa);
    if (!pde)
        return NptLookupNotMapped;

    if (pde->Fields.Pat) {              // bit 7 = PS at the PD level
        OutPlan->PageGpa     = Gpa & ~NPT_PAGE_MASK;
        OutPlan->OriginalPde = pde->Value;
        return NptLookupNeedsSplit;
    }

    if (!pde->Fields.Present)
        return NptLookupNotMapped;

    PNPT_PTE pt = HvPtPoolVaFromPa(pde->Fields.PhysAddr << 12);
    if (!pt)
        return NptLookupNotMapped;

    *OutPte = &pt[NPT_PT_INDEX(Gpa)];
    return NptLookupDone;
}

// ----------------------------------------------------------------------------
//  NptSplitLeafPte — deadlock-safe three-phase 2MB split.
//
//  Phase 1 (g_Npt.Lock held): probe the walk. If the GPA resolves to a 4KB
//    leaf already, return it. If it lands inside a 2MB leaf, capture the raw
//    PD descriptor into the split plan. The lock is then dropped.
//
//  Phase 2 (unlocked): pop a pre-allocated 4KB sheet from the shared pool and
//    populate its 512 descriptors from the captured 2MB leaf: each child
//    inherits the leaf's R/W and NX policy, gains P=1 and U/S=1, and carries
//    PWT=PCD=PAT=0. If the pool is empty the split fails immediately with
//    STATUS_INSUFFICIENT_RESOURCES — the exit dispatcher translates that
//    into a valid guest #PF via the SVM_EXIT_NPF path; nothing is ever
//    allocated at high IRQL on the hot path.
//
//  Phase 3 (g_Npt.Lock reacquired): re-verify the PD descriptor. A concurrent
//    core may have split, unmapped or re-pointed it while the lock was open.
//    On a lost race the popped sheet is parked in a local tracking pointer
//    and returned to the pool strictly after the lock has been released, so
//    the pool's own spinlock is never taken while g_Npt.Lock is held (lock-
//    order inversion would deadlock the exit path). On a won race the PD
//    descriptor is re-pointed at the new table: P=1, R/W=1, U/S=1, PS=0,
//    NX=0 — bit 7 returns to table-pointer duty and bit 12 becomes don't-care.
// ----------------------------------------------------------------------------
static NTSTATUS NptSplitLeafPte(UINT64 PageGpa, PNPT_PTE* OutPte)
{
    PageGpa &= ~NPT_PAGE_MASK;

    NPT_SPLIT_PLAN    plan  = {};
    PNPT_PTE          pte   = NULL;
    NTSTATUS          status;
    PVOID             redundantSheet = NULL;
    NPT_LOOKUP_RESULT probe;

    // ---- Phase 1: probe under the lock. ----
    SpinAcquire(&g_Npt.Lock);
    probe = NptLookupLocked(PageGpa, &pte, &plan);
    SpinRelease(&g_Npt.Lock);

    if (probe == NptLookupDone) {
        if (OutPte) *OutPte = pte;
        return STATUS_SUCCESS;
    }
    if (probe != NptLookupNeedsSplit)
        return STATUS_UNSUCCESSFUL;

    // ---- Phase 2: allocate and populate the new PT sheet, unlocked. ----
    PVOID sheet = NptAllocSheet();
    if (!sheet)
        return STATUS_INSUFFICIENT_RESOURCES;

    PNPT_PTE newPt = (PNPT_PTE)sheet;
    UINT64   largeBase = plan.OriginalPde & NPT_PA_2M_MASK;
    UINT64   leafBits  = NPT_PTE_PRESENT | NPT_PTE_USER;

    if (plan.OriginalPde & NPT_PTE_WRITE)
        leafBits |= NPT_PTE_WRITE;
    if (plan.OriginalPde & NPT_PTE_NX)
        leafBits |= NPT_PTE_NX;

    for (UINT32 i = 0; i < 512; i++) {
        newPt[i].Value = leafBits |
                         ((largeBase + (UINT64)i * NPT_PAGE_SIZE) & NPT_PA_4K_MASK);
    }

    // ---- Phase 3: re-validate and commit under the lock. ----
    SpinAcquire(&g_Npt.Lock);

    PNPT_PTE pde = NptWalkPdeLocked(plan.PageGpa);
    if (!pde || !pde->Fields.Present) {
        status = STATUS_UNSUCCESSFUL;
        redundantSheet = sheet;
        goto Exit;
    }

    if (!pde->Fields.Pat) {
        // The descriptor was split by a concurrent core while the lock was
        // open. Route the caller at the existing 4KB leaf when it is live;
        // otherwise the mapping vanished mid-flight and the access must
        // re-fault. The freshly built sheet is redundant either way.
        PNPT_PTE pt = HvPtPoolVaFromPa(pde->Fields.PhysAddr << 12);
        if (!pt) {
            status = STATUS_UNSUCCESSFUL;
            redundantSheet = sheet;
            goto Exit;
        }

        PNPT_PTE existing = &pt[NPT_PT_INDEX(plan.PageGpa)];
        if (!existing->Fields.Present) {
            status = STATUS_UNSUCCESSFUL;
            redundantSheet = sheet;
            goto Exit;
        }

        if (OutPte) *OutPte = existing;
        status = STATUS_SUCCESS;
        redundantSheet = sheet;
        goto Exit;
    }

    if ((pde->Value & NPT_PA_2M_MASK) != largeBase) {
        // The 2MB leaf was re-pointed concurrently — the captured plan is
        // stale. Force the caller to restart the operation.
        status = STATUS_RETRY;
        redundantSheet = sheet;
        goto Exit;
    }

    // Won the race: install the table pointer.
    pde->Value = NPT_DIR_FLAGS | (NptPhysOf(sheet) & NPT_PA_4K_MASK);

    if (OutPte) *OutPte = &newPt[NPT_PT_INDEX(plan.PageGpa)];

    // Combined translations cached under the old 2MB leaf must be dropped on
    // every core before the finer mapping is observed.
    NptSignalTlbFlushAll();
    status = STATUS_SUCCESS;

Exit:
    SpinRelease(&g_Npt.Lock);

    // Pool return happens strictly outside g_Npt.Lock.
    if (redundantSheet)
        HvPtPoolFree(redundantSheet);

    return status;
}

// ----------------------------------------------------------------------------
//  SvmSplitAndGetPte — operations-template entry point. The template types
//  the leaf handle with common.h's vendor-neutral descriptor union; both
//  formats are single-UINT64 storage, so the handle reinterprets losslessly
//  into NPT_PTE. All internal mechanics are NPT-native.
// ----------------------------------------------------------------------------
extern "C" NTSTATUS SvmSplitAndGetPte(UINT64 Gpa, PEPT_ENTRY* OutPte)
{
    PNPT_PTE pte = NULL;
    NTSTATUS status = NptSplitLeafPte(Gpa, &pte);

    if (NT_SUCCESS(status) && OutPte)
        *OutPte = (PEPT_ENTRY)pte;

    return status;
}

// ============================================================================
//  TLB maintenance.
// ============================================================================

// ----------------------------------------------------------------------------
//  NptSignalTlbFlushAll — broadcast a flush order to every core.
//
//  INVLPGA is deliberately not used for NPT maintenance: it retires cached
//  translations for one guest *virtual* page on the *current* core and
//  current ASID only, while NPT modifications change guest-physical ->
//  host-physical state that is cached in combined translations across all
//  cores. There is no per-page invalidation operand for nested layers.
//  Instead, TLB_CONTROL (VMCB offset 0x05C) is written to 01b in every CPU's
//  control area, forcing the processor to flush its entire TLB (all ASIDs,
//  non-global) automatically on its next VMRUN. The VMCB is host memory and
//  TLB_CONTROL is host-written only, so the store is safe while the owning
//  core is executing the guest.
// ----------------------------------------------------------------------------
static VOID NptSignalTlbFlushAll(VOID)
{
    if (g_PerCpu) {
        for (ULONG i = 0; i < g_CpuCount; i++) {
            PPER_CPU_CONTEXT cpu = &g_PerCpu[i];
            if (!cpu->VmcbVa)
                continue;

            *(volatile UINT8*)((volatile UINT8*)cpu->VmcbVa +
                               NPT_VMCB_OFF_TLB_CTL) = NPT_TLBCTL_FLUSH_ALL;
        }
    }

    InterlockedIncrement(&g_Npt.FlushEpoch);
}

// ----------------------------------------------------------------------------
//  Operations-template TLB callback.
// ----------------------------------------------------------------------------
extern "C" VOID SvmInvalidateTlbAll(VOID)
{
    NptSignalTlbFlushAll();
}

// ============================================================================
//  Range protection callbacks.
// ============================================================================

// ----------------------------------------------------------------------------
//  SvmProtectRange — apply exact permissions across a GPA span.
//
//  Every page in the span is first coerced to a 4KB leaf (protection can only
//  be expressed precisely at PT granularity), then rewritten under the lock.
//  Original raw descriptors are journaled so a mid-span failure rolls the
//  whole operation back. One synchronized flush covers the entire batch.
// ----------------------------------------------------------------------------
extern "C" NTSTATUS SvmProtectRange(UINT64 Gpa, UINT64 Size, UINT64 Perms)
{
    if ((Gpa & NPT_PAGE_MASK) || (Size & NPT_PAGE_MASK) || Size == 0)
        return STATUS_INVALID_PARAMETER;

    SIZE_T pageCount = (SIZE_T)(Size / NPT_PAGE_SIZE);
    if (pageCount == 0 || pageCount > (((SIZE_T)-1) / sizeof(UINT64)))
        return STATUS_INVALID_PARAMETER;

    PUINT64 originals = (PUINT64)ExAllocatePoolWithTag(
        NonPagedPoolNx, pageCount * sizeof(UINT64), 'HvRB');
    if (!originals)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T   committed = 0;

    for (SIZE_T i = 0; i < pageCount; i++) {
        UINT64 pageGpa = Gpa + (UINT64)i * NPT_PAGE_SIZE;

        status = SvmSplitAndGetPte(pageGpa, NULL);
        if (!NT_SUCCESS(status))
            break;

        SpinAcquire(&g_Npt.Lock);

        PNPT_PTE       live  = NULL;
        NPT_SPLIT_PLAN probe = {};
        if (NptLookupLocked(pageGpa, &live, &probe) != NptLookupDone || !live) {
            SpinRelease(&g_Npt.Lock);
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        originals[committed] = live->Value;
        live->Value = NptApplyPermsExact(live->Value, Perms);
        committed++;

        SpinRelease(&g_Npt.Lock);
    }

    if (!NT_SUCCESS(status)) {
        for (SIZE_T j = 0; j < committed; j++) {
            UINT64 pageGpa = Gpa + (UINT64)j * NPT_PAGE_SIZE;

            SpinAcquire(&g_Npt.Lock);

            PNPT_PTE       live  = NULL;
            NPT_SPLIT_PLAN probe = {};
            if (NptLookupLocked(pageGpa, &live, &probe) == NptLookupDone && live)
                live->Value = originals[j];

            SpinRelease(&g_Npt.Lock);
        }
    }

    NptSignalTlbFlushAll();

    ExFreePoolWithTag(originals, 'HvRB');
    return status;
}

// ----------------------------------------------------------------------------
//  SvmSaveAndGrant — journal the raw descriptor and add permissions only.
//  Granting read/write raises P/R/W; granting execution clears NX (bit 63).
//  PWT/PCD/PAT positions are untouched, so the WB policy is preserved.
// ----------------------------------------------------------------------------
extern "C" NTSTATUS SvmSaveAndGrant(UINT64 Gpa, UINT64 Perms, UINT64* OutOriginal)
{
    UINT64 pageGpa = Gpa & ~NPT_PAGE_MASK;

    NTSTATUS status = SvmSplitAndGetPte(pageGpa, NULL);
    if (!NT_SUCCESS(status))
        return status;

    SpinAcquire(&g_Npt.Lock);

    PNPT_PTE       live  = NULL;
    NPT_SPLIT_PLAN probe = {};
    if (NptLookupLocked(pageGpa, &live, &probe) != NptLookupDone || !live) {
        SpinRelease(&g_Npt.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    if (OutOriginal)
        *OutOriginal = live->Value;

    if (Perms & NPT_PERM_READ)
        live->Fields.Present = 1;
    if (Perms & NPT_PERM_WRITE) {
        live->Fields.Present = 1;
        live->Fields.Write   = 1;
    }
    if (Perms & NPT_PERM_EXECUTE)
        live->Fields.Nx = 0;

    NptSignalTlbFlushAll();

    SpinRelease(&g_Npt.Lock);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  SvmRestoreEntry — write a journaled raw descriptor back verbatim. The
//  saved value is a complete NPT descriptor image, so PWT/PCD/PAT and the
//  U/S policy travel with it; no field-level reconstruction is needed.
// ----------------------------------------------------------------------------
extern "C" NTSTATUS SvmRestoreEntry(UINT64 Gpa, UINT64 OriginalValue)
{
    UINT64 pageGpa = Gpa & ~NPT_PAGE_MASK;

    SpinAcquire(&g_Npt.Lock);

    PNPT_PTE       live  = NULL;
    NPT_SPLIT_PLAN probe = {};
    if (NptLookupLocked(pageGpa, &live, &probe) != NptLookupDone || !live) {
        SpinRelease(&g_Npt.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    live->Value = OriginalValue;

    NptSignalTlbFlushAll();

    SpinRelease(&g_Npt.Lock);
    return STATUS_SUCCESS;
}

// ============================================================================
//  Teardown and accessors.
// ============================================================================

// ----------------------------------------------------------------------------
//  NptFreeAll — release every table back to the shared 4KB pool.
//
//  The PML4 base is unpublished first, so no new walk can reach the tree
//  while it is being dismantled; callers must have stopped guest execution on
//  all cores (SVME cleared) before invoking this. Every sheet in the tree was
//  carved from the pool, so each release routes through HvPtPoolFree — the
//  pool must outlive this call and is destroyed by its owner afterwards.
//  PD descriptors with PS=1 are leaves and own no table sheet.
// ----------------------------------------------------------------------------
extern "C" VOID NptFreeAll(VOID)
{
    SpinAcquire(&g_Npt.Lock);

    PNPT_PTE pml4 = g_Npt.Pml4;
    g_Npt.Pml4     = NULL;
    g_Npt.Pml4Phys = 0;

    SpinRelease(&g_Npt.Lock);

    if (!pml4)
        return;

    for (ULONG i = 0; i < 512; i++) {
        PNPT_PTE pml4e = &pml4[i];
        if (!pml4e->Fields.Present)
            continue;

        PNPT_PTE pdpt = HvPtPoolVaFromPa(pml4e->Fields.PhysAddr << 12);
        if (!pdpt)
            continue;

        for (ULONG j = 0; j < 512; j++) {
            PNPT_PTE pdpte = &pdpt[j];
            if (!pdpte->Fields.Present)
                continue;

            PNPT_PTE pd = HvPtPoolVaFromPa(pdpte->Fields.PhysAddr << 12);
            if (!pd)
                continue;

            for (ULONG k = 0; k < 512; k++) {
                PNPT_PTE pde = &pd[k];
                if (!pde->Fields.Present)
                    continue;

                if (!pde->Fields.Pat) {         // PS=0 -> PT sheet backs this range
                    PNPT_PTE pt = HvPtPoolVaFromPa(pde->Fields.PhysAddr << 12);
                    if (pt)
                        HvPtPoolFree(pt);
                }
            }

            HvPtPoolFree(pd);
        }

        HvPtPoolFree(pdpt);
    }

    HvPtPoolFree(pml4);
}

// ----------------------------------------------------------------------------
//  NptGetPml4Phys — physical PML4 base for the VMCB n_cr3 field (offset
//  0x0B0), loaded together with nested-paging enable in the NP_ENABLE control
//  (offset 0x090, bit 0). Returns 0 before SvmBuildIdentityMap succeeds.
// ----------------------------------------------------------------------------
extern "C" UINT64 NptGetPml4Phys(VOID)
{
    return g_Npt.Pml4Phys;
}

extern "C" BOOLEAN NptIsReady(VOID)
{
    return g_Npt.Pml4 != NULL;
}
