// ============================================================================
//  ept_common.cpp — vendor-agnostic page-table infrastructure.
//
//  Contents:
//    * HvPtPoolInit / HvPtPoolAlloc / HvPtPoolFree / HvPtPoolDestroy
//    * HvCollectPhysicalRanges / HvFreePhysicalRanges
//    * HvInjectGuestPageFault
//
//  This TU never references Intel- or AMD-specific VMCS/VMCB layouts; it
//  dispatches all exceptions through g_HvOps. The vendor backend is
//  responsible for translating the linear fault address supplied here into
//  the guest architectural state (Intel VMCS_GUEST_CR2 / AMD CR2 save area
//  surfaced through VMCB_CTRL_EXIT_INFO1) before VMRESUME/VMRUN.
// ============================================================================
#include "common.h"
#include <intrin.h>

// ----------------------------------------------------------------------------
//  Global pool. A single pool per hypervisor, shared by all CPUs. The
//  spinlock protects the array; all mutation is a simple push/pop.
// ----------------------------------------------------------------------------
HV_PT_POOL g_PtPool = {};

// ----------------------------------------------------------------------------
//  Canonical page tracking.
//
//  Populated once at HvPtPoolInit before Initialized becomes TRUE; cleared
//  at HvPtPoolDestroy after Initialized becomes FALSE. During steady-state
//  operation the array is immutable, so HvPtPoolFree may query membership
//  and the cached physical address outside g_PtPool.Lock without racing.
//
//  This table gives us two independent safety properties:
//    (a) A foreign / corrupted pointer can never enter the pool, which
//        would otherwise let an attacker launder arbitrary kernel memory
//        into the EPT/NPT construction path.
//    (b) A "returned then returned again" double-free can be detected
//        inside the lock by scanning the live Pages[] array.
// ----------------------------------------------------------------------------
static PVOID   s_PoolCanon[HV_PT_POOL_MAX_PAGES];
static UINT64  s_PoolCanonPhys[HV_PT_POOL_MAX_PAGES];
static ULONG   s_PoolCanonCount = 0;

// ----------------------------------------------------------------------------
//  Outstanding accounting. Incremented on every successful pop, decremented
//  on every successful push. A non-zero value at HvPtPoolDestroy time
//  indicates the EPT/NPT teardown did not reclaim every committed split
//  table before the pool was destroyed (caller ordering bug).
// ----------------------------------------------------------------------------
static volatile LONG s_PoolOutstanding = 0;

// ----------------------------------------------------------------------------
//  MAXPHYADDR retrieval.
//
//  CPUID.80000008H.EAX[7:0] carries the number of physical-address bits
//  supported by the package on both Intel and AMD. If the leaf is not
//  advertised (very old CPU) fall back to the 36-bit legacy maximum.
// ----------------------------------------------------------------------------
static UINT32 HvGetMaxPhyAddrBits(VOID)
{
    int regs[4] = { 0, 0, 0, 0 };
    __cpuid(regs, 0x80000000);
    if ((UINT32)regs[0] < 0x80000008u) return 36;
    __cpuid(regs, 0x80000008);
    UINT32 bits = (UINT32)regs[0] & 0xFFu;
    // Some firmware advertises 0; clamp to the architectural window.
    return (bits >= 32 && bits <= 52) ? bits : 36;
}

// ============================================================================
//  Page-table pool
// ============================================================================

// ----------------------------------------------------------------------------
//  HvPtPoolInit — allocate HV_PT_POOL_MAX_PAGES 4KB sheets.
//
//  Runs at PASSIVE_LEVEL from DriverEntry. Uses the contiguous allocator,
//  which returns 4KB-aligned physically-contiguous pages. This is exactly
//  the allocator the EPT/NPT split fast-path must NOT call from the exit
//  handler, so pre-populating here avoids any IRQL-incompatible allocation
//  later on the hot path.
//
//  On partial failure we free whatever we already allocated and return
//  STATUS_INSUFFICIENT_RESOURCES. The caller must treat this as fatal — a
//  hypervisor without a PT pool cannot split large pages and therefore
//  cannot protect memory.
// ----------------------------------------------------------------------------
NTSTATUS HvPtPoolInit(VOID)
{
    if (g_PtPool.Initialized) return STATUS_ALREADY_REGISTERED;

    RtlZeroMemory(g_PtPool.Pages, sizeof(g_PtPool.Pages));
    RtlZeroMemory(g_PtPool.Phys,  sizeof(g_PtPool.Phys));
    RtlZeroMemory(s_PoolCanon,     sizeof(s_PoolCanon));
    RtlZeroMemory(s_PoolCanonPhys, sizeof(s_PoolCanonPhys));
    g_PtPool.Top         = 0;
    g_PtPool.Lock        = 0;
    s_PoolCanonCount     = 0;
    s_PoolOutstanding    = 0;

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
                    g_PtPool.Pages[j]     = NULL;
                    g_PtPool.Phys[j]      = 0;
                    s_PoolCanon[j]        = NULL;
                    s_PoolCanonPhys[j]    = 0;
                }
            }
            s_PoolCanonCount = 0;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(p, PAGE_SIZE);
        UINT64 phys = MmGetPhysicalAddress(p).QuadPart & ~0xFFFULL;
        g_PtPool.Pages[i]     = p;
        g_PtPool.Phys[i]      = phys;
        s_PoolCanon[i]        = p;
        s_PoolCanonPhys[i]    = phys;
    }

    s_PoolCanonCount     = HV_PT_POOL_MAX_PAGES;
    g_PtPool.Top         = HV_PT_POOL_MAX_PAGES;
    g_PtPool.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[HV] PT pool initialized: %u pages, %u KB\n",
        HV_PT_POOL_MAX_PAGES, (HV_PT_POOL_MAX_PAGES * PAGE_SIZE) / 1024);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  HvPtPoolAlloc — pop a page. Safe to call from any IRQL.
//
//  The Initialized flag is verified strictly under the acquired lock so
//  teardown cannot race past the check and mutate a half-torn-down array.
//  The page is explicitly zeroed before it is handed to the caller so that
//  no stale EPT/NPT entry from a previous split (or a prior owner) can leak
//  through into the guest's address translation.
// ----------------------------------------------------------------------------
PVOID HvPtPoolAlloc(UINT64* OutPhys)
{
    PVOID result = NULL;

    if (OutPhys) *OutPhys = 0;

    SpinAcquire(&g_PtPool.Lock);
    if (!g_PtPool.Initialized || g_PtPool.Top == 0) {
        SpinRelease(&g_PtPool.Lock);
        return NULL;
    }

    g_PtPool.Top--;
    result = g_PtPool.Pages[g_PtPool.Top];
    if (OutPhys) *OutPhys = g_PtPool.Phys[g_PtPool.Top];
    g_PtPool.Pages[g_PtPool.Top] = NULL;
    g_PtPool.Phys[g_PtPool.Top]  = 0;
    InterlockedIncrement(&s_PoolOutstanding);
    SpinRelease(&g_PtPool.Lock);

    // Hard zeroed contract: every allocation is cold on delivery.
    if (result) RtlZeroMemory(result, PAGE_SIZE);

    return result;
}

// ----------------------------------------------------------------------------
//  HvPtPoolFree — return a page that was popped but never committed.
//
//  Called from the EPT/NPT split's phase-3 rollback path when a concurrent
//  split loses the race, or by explicit teardown paths. Never call this on
//  a page that is reachable from a live PDE/PTE.
//
//  Fix requirements enforced here:
//    * Membership and physical-address resolution are performed BEFORE the
//      lock so no prolonged tracking runs under the global spinlock.
//    * A pointer not owned by this pool is rejected without ever entering
//      Pages[] (foreign-pointer / pool-pollution defense).
//    * A pointer already present in Pages[] is rejected (double-free guard).
//    * The only path that frees to the allocator never holds the lock.
// ----------------------------------------------------------------------------
VOID HvPtPoolFree(PVOID Page)
{
    if (!Page) return;

    // Resolve membership and cached physical without touching the lock.
    // s_PoolCanon is immutable while Initialized == TRUE.
    BOOLEAN isOurs     = FALSE;
    UINT64  cachedPhys = 0;
    for (ULONG i = 0; i < s_PoolCanonCount; i++) {
        if (s_PoolCanon[i] == Page) {
            isOurs     = TRUE;
            cachedPhys = s_PoolCanonPhys[i];
            break;
        }
    }
    if (!isOurs) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[HV] HvPtPoolFree: rejected foreign pointer %p\n", Page);
        return;
    }

    BOOLEAN freeToSystem = FALSE;

    SpinAcquire(&g_PtPool.Lock);

    // Re-validate under the lock: Initialized may have flipped between the
    // fast membership read above and this acquisition.
    if (!g_PtPool.Initialized) {
        SpinRelease(&g_PtPool.Lock);
        return;
    }

    // Double-free guard: the page must not already be resident in the pool.
    BOOLEAN inPool = FALSE;
    for (ULONG i = 0; i < g_PtPool.Top; i++) {
        if (g_PtPool.Pages[i] == Page) { inPool = TRUE; break; }
    }
    if (inPool) {
        SpinRelease(&g_PtPool.Lock);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[HV] HvPtPoolFree: rejected double-free of %p\n", Page);
        return;
    }

    if (g_PtPool.Top < HV_PT_POOL_MAX_PAGES) {
        UINT32 idx = (UINT32)g_PtPool.Top;
        g_PtPool.Pages[idx] = Page;
        g_PtPool.Phys[idx]  = cachedPhys;
        g_PtPool.Top++;
        InterlockedDecrement(&s_PoolOutstanding);
    } else {
        // Structural invariant broken — pool full but page is ours and
        // absent from the pool. Defer the free outside the spinlock.
        freeToSystem = TRUE;
        InterlockedDecrement(&s_PoolOutstanding);
    }

    SpinRelease(&g_PtPool.Lock);

    if (freeToSystem) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[HV] HvPtPoolFree: pool overflow, freeing %p to system\n", Page);
        MmFreeContiguousMemory(Page);
    }
}

// ----------------------------------------------------------------------------
//  HvPtPoolDestroy — release everything still in the pool.
//
//  Call at teardown AFTER every CPU has executed VMXOFF / SVMDISABLE and
//  AFTER EptFreeAll / NptFreeAll have released every committed PT.
//
//  Correctness requirements enforced here:
//    * Initialized transitions to FALSE inside the lock so concurrent
//      HvPtPoolAlloc / HvPtPoolFree callers observe the state change under
//      the same lock and bail out before mutating the array.
//    * Pages are extracted into a local staging array while holding the
//      lock; MmFreeContiguousMemory is invoked strictly outside the lock,
//      preventing lock-order inversion with the memory manager.
//    * Outstanding count is snapshotted under the lock and reported after
//      the lock is dropped, so a caller-ordering bug that leaked committed
//      split pages is logged rather than silently masked.
// ----------------------------------------------------------------------------
VOID HvPtPoolDestroy(VOID)
{
    PVOID localPages[HV_PT_POOL_MAX_PAGES];
    ULONG localCount = 0;
    LONG  outstandingSnapshot = 0;

    SpinAcquire(&g_PtPool.Lock);
    if (!g_PtPool.Initialized) {
        SpinRelease(&g_PtPool.Lock);
        return;
    }

    // Atomically transition to a torn-down state. Any concurrent Alloc/Free
    // that is about to acquire the lock will observe Initialized == FALSE
    // and return without touching the array.
    g_PtPool.Initialized = FALSE;

    while (g_PtPool.Top > 0) {
        g_PtPool.Top--;
        if (g_PtPool.Pages[g_PtPool.Top]) {
            localPages[localCount++]     = g_PtPool.Pages[g_PtPool.Top];
            g_PtPool.Pages[g_PtPool.Top] = NULL;
            g_PtPool.Phys[g_PtPool.Top]  = 0;
        }
    }
    outstandingSnapshot = s_PoolOutstanding;
    s_PoolOutstanding   = 0;
    SpinRelease(&g_PtPool.Lock);

    // Free outside the spinlock to avoid high-IRQL lock-chain issues.
    for (ULONG i = 0; i < localCount; i++) {
        MmFreeContiguousMemory(localPages[i]);
    }

    // The canonical table is now stale by definition; wipe it so a later
    // HvPtPoolInit sees a clean slate.
    RtlZeroMemory(s_PoolCanon,     sizeof(s_PoolCanon));
    RtlZeroMemory(s_PoolCanonPhys, sizeof(s_PoolCanonPhys));
    s_PoolCanonCount = 0;

    if (outstandingSnapshot != 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[HV] PT pool destroyed with %ld pages outstanding "
            "(committed EPT/NPT tables not reclaimed?)\n",
            outstandingSnapshot);
    }
}

// ============================================================================
//  Identity-map range collection
// ============================================================================

// ----------------------------------------------------------------------------
//  HvCollectPhysicalRanges — query the OS for physical RAM layout.
//
//  MmGetPhysicalMemoryRanges() returns a NULL-terminated array of
//  PHYSICAL_MEMORY_RANGE. The current documentation claims the array is
//  sorted by base address, but nothing in the API contract guarantees
//  that — so we sort defensively before coalescing. Duplicated or
//  overlapping descriptors that slipped through would cause the EPT/NPT
//  builder to double-install the same identity mapping and waste PDE/PTE
//  leaves or, worse, reopen a mapping after a split race.
//
//  All arithmetic on (base + size) is checked for 64-bit wrap. Ranges
//  whose base exceeds the CPU's MAXPHYADDR are dropped; ranges that
//  straddle the limit are clamped. Allocation size is guarded against
//  SIZE_T overflow so a malformed boot-parameter table cannot force an
//  undersized allocation followed by an overflow write.
//
//  NOTE: MmGetPhysicalMemoryRanges reports RAM only. MMIO and reserved
//  firmware apertures are not included. If the guest touches a GPA outside
//  the returned ranges, the EPT/NPT builder leaves the entry non-present
//  and the exit handler injects a real #PF — the guest never silently
//  reaches the physical bus.
// ----------------------------------------------------------------------------
NTSTATUS HvCollectPhysicalRanges(PHV_IDENTITY_RANGE* OutRanges, PULONG OutCount)
{
    if (!OutRanges || !OutCount) return STATUS_INVALID_PARAMETER;
    *OutRanges = NULL;
    *OutCount  = 0;

    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return STATUS_INSUFFICIENT_RESOURCES;

    // First pass: count non-empty entries. Cap at MAXULONG to guard against
    // a runaway loop if the terminator is missing.
    ULONG rawCount = 0;
    for (;;) {
        if (ranges[rawCount].NumberOfBytes.QuadPart == 0) break;
        rawCount++;
        if (rawCount == MAXULONG) {
            ExFreePool(ranges);
            return STATUS_INTEGER_OVERFLOW;
        }
    }
    if (rawCount == 0) {
        ExFreePool(ranges);
        return STATUS_NOT_FOUND;
    }

    // Checked allocation-size computation.
    SIZE_T oneSize = sizeof(HV_IDENTITY_RANGE);
    if ((SIZE_T)rawCount > (((SIZE_T)~(SIZE_T)0) / oneSize)) {
        ExFreePool(ranges);
        return STATUS_INTEGER_OVERFLOW;
    }
    SIZE_T allocSize = (SIZE_T)rawCount * oneSize;

    HV_IDENTITY_RANGE* copy = (HV_IDENTITY_RANGE*)ExAllocatePoolWithTag(
        NonPagedPoolNx, allocSize, 'HvId');
    if (!copy) {
        ExFreePool(ranges);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Resolve MAXPHYADDR once; every range must respect it.
    UINT32 maxPhyAddrBits = HvGetMaxPhyAddrBits();
    UINT64 maxPhyMask     = (maxPhyAddrBits >= 64)
                          ? MAXULONG64
                          : (((UINT64)1 << maxPhyAddrBits) - 1);
    UINT64 maxPhyLimit    = (maxPhyAddrBits >= 64)
                          ? MAXULONG64
                          : (((UINT64)1 << maxPhyAddrBits));

    // Second pass: normalize and copy.
    ULONG outIdx = 0;
    for (ULONG i = 0; i < rawCount; i++) {
        UINT64 base = ranges[i].BaseAddress.QuadPart;
        UINT64 size = ranges[i].NumberOfBytes.QuadPart;
        if (size == 0) continue;

        // Checked end computation; drop wrapped entries outright.
        UINT64 rawEnd = base + size;
        if (rawEnd < base) continue;

        // MAXPHYADDR gate.
        if ((base & ~maxPhyMask) != 0) continue;
        if (base >= maxPhyLimit) continue;
        if (size > (maxPhyLimit - base)) size = maxPhyLimit - base;

        // 4KB alignment normalization (defensive; API guarantees this).
        if (base & 0xFFF) {
            UINT64 delta = base & 0xFFFULL;
            base = (base + 0xFFFULL) & ~0xFFFULL;
            if (size >= delta) size -= delta;
            else               size = 0;
            if (size == 0) continue;
        }
        size &= ~0xFFFULL;
        if (size == 0) continue;

        copy[outIdx].Base = base;
        copy[outIdx].Size = size;
        outIdx++;
    }
    ExFreePool(ranges);

    if (outIdx == 0) {
        ExFreePool(copy);
        return STATUS_NOT_FOUND;
    }

    // Sort defensively by BaseAddress. The input is expected to be sorted,
    // but we never trust that. Insertion sort is well suited here because
    // the descriptor count is small (single-digit or low double-digit).
    for (ULONG i = 1; i < outIdx; i++) {
        HV_IDENTITY_RANGE tmp = copy[i];
        ULONG j = i;
        while (j > 0 && copy[j - 1].Base > tmp.Base) {
            copy[j] = copy[j - 1];
            j--;
        }
        copy[j] = tmp;
    }

    // Coalesce adjacent or overlapping descriptors in-place.
    ULONG coalesced = 0;
    for (ULONG i = 0; i < outIdx; i++) {
        if (coalesced == 0) {
            copy[coalesced++] = copy[i];
            continue;
        }
        HV_IDENTITY_RANGE* prev = &copy[coalesced - 1];
        UINT64 prevEnd = prev->Base + prev->Size;
        if (prevEnd < prev->Base) prevEnd = MAXULONG64;  // saturate on wrap

        if (copy[i].Base <= prevEnd) {
            UINT64 newEnd = copy[i].Base + copy[i].Size;
            if (newEnd < copy[i].Base) newEnd = MAXULONG64;
            if (newEnd > prevEnd) prev->Size = newEnd - prev->Base;
        } else {
            copy[coalesced++] = copy[i];
        }
    }

    *OutRanges = copy;
    *OutCount  = coalesced;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[HV] collected %u physical ranges (raw=%u, maxphy=%u)\n",
        coalesced, rawCount, maxPhyAddrBits);
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
//  The fault address supplied to the guest architectural state must be the
//  LINEAR (virtual) address that triggered the fault, never the GPA that
//  the EPT/NPT walker produced. The vendor backend maps GuestLinearAddress
//  into Intel's VMCS_GUEST_CR2 / AMD's CR2 save area before the next
//  VMRESUME/VMRUN. Passing a GPA here would corrupt every user-mode
//  diagnostic that inspects CR2 on the faulting thread.
//
//  Error-code bits (Intel SDM Vol 3A 4.7 / AMD APM Vol 2 8.4):
//     bit 0   P    0 = not-present, 1 = protection violation
//     bit 1   W/R  0 = read,        1 = write
//     bit 2   U/S  0 = supervisor,  1 = user
//     bit 3   RSVD reserved-bit violation (unused for EPT/NPT denials)
//     bit 4   I/D  0 = data,        1 = instruction fetch
//
//  A single #PF cannot be both a data write and an instruction fetch. If
//  the caller supplies that impossible combination (vendor-exit decoding
//  bug), we sanitize by dropping the instruction-fetch bit so the guest
//  never receives an architecturally impossible error code.
// ----------------------------------------------------------------------------
VOID HvInjectGuestPageFault(UINT64  GuestLinearAddress,
                            BOOLEAN Present,
                            BOOLEAN Write,
                            BOOLEAN Execute,
                            BOOLEAN UserMode)
{
    if (!g_HvOps || !g_HvOps->InjectException) {
        // Vendor backend not initialized — this must never happen. Bugcheck
        // rather than silently corrupt guest architectural state.
        KeBugCheckEx(0xE0000002, GuestLinearAddress, Present, Write, Execute);
    }

    if (Write && Execute) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[HV] HvInjectGuestPageFault: sanitizing impossible W&&X "
            "combination for LA=%p\n", (PVOID)GuestLinearAddress);
        Execute = FALSE;
    }

    UINT32 errorCode = 0;
    if (Present)  errorCode |= 0x01;   // P
    if (Write)    errorCode |= 0x02;   // W/R
    if (UserMode) errorCode |= 0x04;   // U/S
    if (Execute)  errorCode |= 0x10;   // I/D

    g_HvOps->InjectException(14 /* #PF */, errorCode, GuestLinearAddress);
}
