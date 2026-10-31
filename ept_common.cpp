// ============================================================================
//  ept_common.cpp — vendor-agnostic page-table infrastructure.
//
//  Contents:
//    * HvPtPoolInit / HvPtPoolAlloc / HvPtPoolFree / HvPtPoolDestroy
//    * HvCollectPhysicalRanges / HvFreePhysicalRanges
//    * HvInjectGuestPageFault
//
//  This TU never references Intel- or AMD-specific VMCS/VMCB layouts; it
//  dispatches all exceptions through g_HvOps.
// ============================================================================
#include "common.h"

// ----------------------------------------------------------------------------
//  Global pool. A single pool per hypervisor, shared by all CPUs. The
//  spinlock protects the array; all mutation is a simple push/pop.
// ----------------------------------------------------------------------------
HV_PT_POOL g_PtPool = {};

// ============================================================================
//  Page-table pool
// ============================================================================

// ----------------------------------------------------------------------------
//  HvPtPoolInit — allocate HV_PT_POOL_MAX_PAGES 4KB sheets.
//  Called at PASSIVE_LEVEL from DriverEntry.
//
//  Uses MmAllocateContiguousMemorySpecifyCacheNode(PAGE_SIZE, ...) which is
//  guaranteed to return 4KB-aligned, physically-contiguous memory. This is
//  the same allocator that the EPT split fast-path must not call, so we
//  pre-populate here while it is still legal to block.
//
//  On partial failure we free whatever we already allocated and return
//  STATUS_INSUFFICIENT_RESOURCES. The caller must treat this as fatal —
//  a hypervisor without a PT pool cannot split large pages and therefore
//  cannot protect memory.
// ----------------------------------------------------------------------------
NTSTATUS HvPtPoolInit(VOID)
{
    if (g_PtPool.Initialized) return STATUS_ALREADY_REGISTERED;

    RtlZeroMemory(g_PtPool.Pages, sizeof(g_PtPool.Pages));
    RtlZeroMemory(g_PtPool.Phys,  sizeof(g_PtPool.Phys));
    g_PtPool.Top  = 0;
    g_PtPool.Lock = 0;

    for (ULONG i = 0; i < HV_PT_POOL_MAX_PAGES; i++) {
        PVOID p = MmAllocateContiguousMemorySpecifyCacheNode(
            PAGE_SIZE,
            (PHYSICAL_ADDRESS) { 0 },
            (PHYSICAL_ADDRESS) { MAXULONG64 },
            (PHYSICAL_ADDRESS) { 0 },
            MmCached,
            MM_ANY_NODE_OK);

        if (!p) {
            // Roll back — free everything we have so far.
            for (ULONG j = 0; j < i; j++) {
                if (g_PtPool.Pages[j]) {
                    MmFreeContiguousMemory(g_PtPool.Pages[j]);
                    g_PtPool.Pages[j] = NULL;
                    g_PtPool.Phys[j]  = 0;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(p, PAGE_SIZE);
        g_PtPool.Pages[i] = p;
        g_PtPool.Phys[i]  = MmGetPhysicalAddress(p).QuadPart & ~0xFFFULL;
    }

    g_PtPool.Top = HV_PT_POOL_MAX_PAGES;
    g_PtPool.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[HV] PT pool initialized: %u pages, %u KB\n",
        HV_PT_POOL_MAX_PAGES, (HV_PT_POOL_MAX_PAGES * PAGE_SIZE) / 1024);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  HvPtPoolAlloc — pop a page. Safe to call from any IRQL.
//  Returns NULL if the pool is exhausted; caller MUST inject #PF and NOT
//  fall back to MmAllocateContiguousMemory.
// ----------------------------------------------------------------------------
PVOID HvPtPoolAlloc(UINT64* OutPhys)
{
    PVOID result = NULL;

    if (OutPhys) *OutPhys = 0;
    if (!g_PtPool.Initialized) return NULL;

    SpinAcquire(&g_PtPool.Lock);
    if (g_PtPool.Top > 0) {
        g_PtPool.Top--;
        result = g_PtPool.Pages[g_PtPool.Top];
        if (OutPhys) *OutPhys = g_PtPool.Phys[g_PtPool.Top];
        g_PtPool.Pages[g_PtPool.Top] = NULL;
        g_PtPool.Phys[g_PtPool.Top]  = 0;
    }
    SpinRelease(&g_PtPool.Lock);

    return result;
}

// ----------------------------------------------------------------------------
//  HvPtPoolFree — return a page that was popped but never committed.
//  Used by the EPT split's phase-3 rollback when a concurrent split loses
//  the race. Never call this on a page that is referenced by a PDE/PTE.
// ----------------------------------------------------------------------------
VOID HvPtPoolFree(PVOID Page)
{
    if (!Page || !g_PtPool.Initialized) return;

    SpinAcquire(&g_PtPool.Lock);
    if (g_PtPool.Top < HV_PT_POOL_MAX_PAGES) {
        UINT32 idx = (UINT32)g_PtPool.Top;
        g_PtPool.Pages[idx] = Page;
        g_PtPool.Phys[idx]  = MmGetPhysicalAddress(Page).QuadPart & ~0xFFFULL;
        g_PtPool.Top++;
    } else {
        // Should never happen — the pool grew beyond its capacity.
        // Free to the system to avoid a leak.
        MmFreeContiguousMemory(Page);
    }
    SpinRelease(&g_PtPool.Lock);
}

// ----------------------------------------------------------------------------
//  HvPtPoolDestroy — release everything still in the pool.
//  Call at teardown, AFTER every CPU has executed VMXOFF / SVMDISABLE,
//  and AFTER EptFreeAll / NptFreeAll have released committed PTs.
// ----------------------------------------------------------------------------
VOID HvPtPoolDestroy(VOID)
{
    if (!g_PtPool.Initialized) return;

    SpinAcquire(&g_PtPool.Lock);
    while (g_PtPool.Top > 0) {
        g_PtPool.Top--;
        if (g_PtPool.Pages[g_PtPool.Top]) {
            MmFreeContiguousMemory(g_PtPool.Pages[g_PtPool.Top]);
            g_PtPool.Pages[g_PtPool.Top] = NULL;
            g_PtPool.Phys[g_PtPool.Top]  = 0;
        }
    }
    SpinRelease(&g_PtPool.Lock);

    g_PtPool.Initialized = FALSE;
}

// ============================================================================
//  Identity-map range collection
// ============================================================================

// ----------------------------------------------------------------------------
//  HvCollectPhysicalRanges — query the OS for physical RAM layout.
//
//  MmGetPhysicalMemoryRanges() returns a NULL-terminated array of
//  PHYSICAL_MEMORY_RANGE, sorted by BaseAddress. We copy the ranges into
//  our own HV_IDENTITY_RANGE format and coalesce adjacent/overlapping
//  entries so that EptBuildIdentityMap / NptBuildIdentityMap only iterate
//  the minimum number of segments.
//
//  This replaces the hardcoded 1 GB limit: the returned array covers the
//  machine's actual RAM, whether that is 512 MB or 2 TB. The caller must
//  free the result with HvFreePhysicalRanges().
//
//  NOTE: MmGetPhysicalMemoryRanges reports RAM only. MMIO ranges and
//  reserved firmware areas are not included. If the guest touches a GPA
//  outside the returned ranges, we do NOT want to identity-map it — that
//  would silently expose the physical bus. Instead, the EPT/NPT builder
//  leaves the corresponding EPT entry non-present, so the access triggers
//  an EPT/NPT violation and the exit handler injects a real #PF into the
//  guest. This is the correct behavior for a defensive hypervisor.
// ----------------------------------------------------------------------------
NTSTATUS HvCollectPhysicalRanges(PHV_IDENTITY_RANGE* OutRanges, PULONG OutCount)
{
    if (!OutRanges || !OutCount) return STATUS_INVALID_PARAMETER;
    *OutRanges = NULL;
    *OutCount  = 0;

    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return STATUS_INSUFFICIENT_RESOURCES;

    // First pass: count non-empty entries.
    ULONG rawCount = 0;
    for (ULONG i = 0; ranges[i].NumberOfBytes.QuadPart != 0; i++) rawCount++;
    if (rawCount == 0) {
        ExFreePool(ranges);
        return STATUS_NOT_FOUND;
    }

    HV_IDENTITY_RANGE* copy = (HV_IDENTITY_RANGE*)ExAllocatePoolWithTag(
        NonPagedPoolNx, rawCount * sizeof(HV_IDENTITY_RANGE), 'HvId');
    if (!copy) {
        ExFreePool(ranges);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Second pass: copy and coalesce.
    ULONG outIdx = 0;
    for (ULONG i = 0; i < rawCount; i++) {
        UINT64 base = ranges[i].BaseAddress.QuadPart;
        UINT64 size = ranges[i].NumberOfBytes.QuadPart;
        if (size == 0) continue;

        // Sanity: 4 KB alignment. The API guarantees this, but be defensive.
        if (base & 0xFFF) {
            UINT64 delta = base & 0xFFF;
            base = (base + 0xFFF) & ~0xFFFULL;
            size = (size >= delta) ? (size - delta) : 0;
            if (size == 0) continue;
        }
        size &= ~0xFFFULL;
        if (size == 0) continue;

        if (outIdx > 0) {
            HV_IDENTITY_RANGE* prev = &copy[outIdx - 1];
            UINT64 prevEnd = prev->Base + prev->Size;
            if (base <= prevEnd) {
                // Overlap or adjacency — merge.
                UINT64 newEnd = base + size;
                if (newEnd > prevEnd) prev->Size = newEnd - prev->Base;
                continue;
            }
        }

        copy[outIdx].Base = base;
        copy[outIdx].Size = size;
        outIdx++;
    }

    ExFreePool(ranges);

    if (outIdx == 0) {
        ExFreePool(copy);
        return STATUS_NOT_FOUND;
    }

    *OutRanges = copy;
    *OutCount  = outIdx;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[HV] collected %u physical ranges (raw=%u)\n", outIdx, rawCount);
    return STATUS_SUCCESS;
}

VOID HvFreePhysicalRanges(HV_IDENTITY_RANGE* Ranges)
{
    if (Ranges) ExFreePool(Ranges);
}

// ============================================================================
//  Exception injection (safe degradation when PT pool is exhausted)
// ============================================================================

// ----------------------------------------------------------------------------
//  HvInjectGuestPageFault — inject a native #PF into the guest.
//
//  Called when the PT pool is depleted during EptSplit2MBTwoPhase /
//  NptSplit2MBTwoPhase. We must NOT allocate in the exit handler, so the
//  only safe action is to deny the access with the correct architectural
//  exception. The guest OS will deliver it to the faulting process, which
//  is exactly what a hardware page fault does — no defensive degradation.
//
//  Error-code bits (Intel SDM Vol 3A 4.7 / AMD APM Vol 2 8.4):
//     bit 0   P   0 = not-present, 1 = protection violation
//     bit 1   W/R 0 = read, 1 = write
//     bit 2   U/S 0 = supervisor, 1 = user
//     bit 3   RSVD (reserved bit violation)
//     bit 4   I/D 0 = data, 1 = instruction fetch
//
//  For an EPT/NPT permission failure the entry is present but disallows
//  the requested access, so P = 1. W and X are set from the failing access.
//  U/S is unknown here (vendor handler resolves it); we default to
//  supervisor (U/S = 0), which is the safe assumption for kernel-mode
//  reads/writes on protected pages.
// ----------------------------------------------------------------------------
VOID HvInjectGuestPageFault(UINT64 Gpa, BOOLEAN Write, BOOLEAN Execute)
{
    if (!g_HvOps || !g_HvOps->InjectException) {
        // Vendor not initialized — this must never happen. Bugcheck rather
        // than silently corrupting guest state.
        KeBugCheckEx(0xE0000002, Gpa, Write, Execute, 0);
    }

    UINT32 errorCode = 0x01;                 // P = 1 (present)
    if (Write)   errorCode |= 0x02;          // W = 1
    if (Execute) errorCode |= 0x10;          // I = 1

    g_HvOps->InjectException(14 /* #PF */, errorCode, Gpa);
}
