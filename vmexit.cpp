// vmexit.cpp — Master VM-exit dispatcher (Intel VMX + AMD SVM).
// Unified dual-vendor exit routing, instruction emulation, EPT/NPF resolution,
// single-step guarded memory-violation recovery, and authenticated teardown
// hypercall handling.

#include <ntddk.h>
#include <intrin.h>
#include "common.h"

// -----------------------------------------------------------------------------
// Backend-provided externals (implemented in intel_vmm.cpp / amd_npt.cpp).
// These are the per-vendor entry points used only after policy has been
// validated by this module.
// -----------------------------------------------------------------------------
extern "C" {
    VOID IntelHandleTeardownVmcall(_Inout_ UINT64* GuestRegs, _Inout_ PCPU_CONTEXT Cpu);
    VOID SvmHandleTeardownVmcall  (_Inout_ UINT64* GuestRegs, _Inout_ PCPU_CONTEXT Cpu);

    // Permanently grant read access to a protected page for the guest. The
    // backend is responsible for updating the EPT/NPT entry and invalidating
    // the current core's TLB for that page.
    BOOLEAN IntelGrantPageRead(_Inout_ PCPU_CONTEXT Cpu, _In_ UINT64 GuestPhysicalPage);
    BOOLEAN AmdGrantPageRead  (_Inout_ PCPU_CONTEXT Cpu, _In_ UINT64 GuestPhysicalPage);
}

// -----------------------------------------------------------------------------
// Guest register frame index layout. Matches the layout pushed by the assembly
// stubs before they C-call into this module.
// -----------------------------------------------------------------------------
enum : UINT32 {
    RegRax = 0, RegRcx = 1, RegRdx = 2, RegRbx = 3,
    RegRsp = 4, RegRbp = 5, RegRsi = 6, RegRdi = 7,
    RegR8  = 8, RegR9  = 9, RegR10 = 10, RegR11 = 11,
    RegR12 = 12, RegR13 = 13, RegR14 = 14, RegR15 = 15
};

// -----------------------------------------------------------------------------
// Local constants and structures.
// -----------------------------------------------------------------------------
static const UINT64 kPage4kMask        = 0xFFFFFFFFFFFFF000ULL;
static const UINT32 kExceptionDb       = 1;     // #DB architectural vector.

union EPT_EXIT_QUALIFICATION {
    UINT64 Value;
    struct {
        UINT64 Read               : 1;   // bit 0
        UINT64 Write              : 1;   // bit 1
        UINT64 Execute            : 1;   // bit 2
        UINT64 InstFetch          : 1;   // bit 3 (valid when Execute=1)
        UINT64 Reserved0          : 8;   // bits 4-11
        UINT64 GuestLinearValid   : 1;   // bit 12
        UINT64 Reserved1          : 51;
    };
};

union NPF_EXITINFO1 {
    UINT64 Value;
    struct {
        UINT64 Present            : 1;   // bit 0: 1=protection, 0=not-present
        UINT64 Write              : 1;   // bit 1
        UINT64 Read               : 1;   // bit 2
        UINT64 Execute            : 1;   // bit 3
        UINT64 Reserved           : 60;
    };
};

// -----------------------------------------------------------------------------
// VMCS accessors. Wrappers keep the handler body free of intrinsic noise and
// allow future switch to a cached VMCS mapping without touching call sites.
// -----------------------------------------------------------------------------
static __forceinline UINT64
ReadVmcsField(_In_ UINT32 Field)
{
    UINT64 value = 0;
    (VOID)__vmx_vmread(Field, &value);
    return value;
}

static __forceinline VOID
WriteVmcsField(_In_ UINT32 Field, _In_ UINT64 Value)
{
    (VOID)__vmx_vmwrite(Field, Value);
}

// =============================================================================
// CPUID emulation.
//
// CPUID is a fixed-width, side-effect-free instruction. The guest selects the
// leaf in EAX and the sub-leaf in ECX. The host executes the native CPUID with
// the guest-selected selectors and writes back the four 32-bit outputs. Each
// destination register is zero-extended: architectural CPUID outputs are 32-bit
// and the upper 32 bits of RAX/RBX/RCX/RDX must be cleared on write-back, or
// subsequent guest 64-bit reads observe stale garbage in the high halves.
// =============================================================================
static VOID
HandleCpuidExit(_Inout_ UINT64* GuestRegs)
{
    int regs[4] = { 0, 0, 0, 0 };

    const UINT32 leaf    = (UINT32)(GuestRegs[RegRax] & 0xFFFFFFFFULL);
    const UINT32 subleaf = (UINT32)(GuestRegs[RegRcx] & 0xFFFFFFFFULL);

    __cpuidex(regs, (int)leaf, (int)subleaf);

    // `(UINT64)(UINT32)value` is the explicit 64-bit zero-extension required by
    // CPUID semantics; it is equivalent to masking with 0x00000000FFFFFFFF.
    GuestRegs[RegRax] = (UINT64)(UINT32)regs[0];
    GuestRegs[RegRbx] = (UINT64)(UINT32)regs[1];
    GuestRegs[RegRcx] = (UINT64)(UINT32)regs[2];
    GuestRegs[RegRdx] = (UINT64)(UINT32)regs[3];
}

// =============================================================================
// Unified memory-violation resolver.
//
// Called for Intel EPT violations and AMD nested page faults. The caller has
// already decoded read / write / execute intent from the vendor-specific
// qualification word; this routine only deals with the shared policy engine.
//
// Resolution policy:
//   * Unprotected page            -> no action (backend fault would not occur).
//   * Read-only attempt           -> permanently grant read on the page.
//   * Write or execute attempt    -> single-step isolation:
//        1. Atomically save the original strict PTE state onto the Cpu context.
//        2. Relax permissions for the current core only.
//        3. Arm the single-step framework and flag the Cpu.
//       Adjacent cores that wish to single-step the same page spin on a pause
//       loop to serialize access to the shared PTE slot — otherwise concurrent
//       relaxations of the same table page can stack and defeat protection.
// =============================================================================
static BOOLEAN
HandleMemoryViolation(
    _Inout_ PCPU_CONTEXT Cpu,
    _In_    UINT64       GuestPhysicalPage,
    _In_    BOOLEAN      IsRead,
    _In_    BOOLEAN      IsWrite,
    _In_    BOOLEAN      IsExecute
    )
{
    const UINT64 pageAddr = GuestPhysicalPage & kPage4kMask;

    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&g_RangesLock);

    PROTECTED_RANGE range = { 0 };
    BOOLEAN found = FALSE;

    for (;;) {
        // Serialize against other cores currently single-stepping this page.
        // The check is performed while the ranges lock is held, but the spin
        // itself runs lock-free so that the owner can complete its single-step
        // and re-enter this handler to clear the tracking slot.
        if (g_ActiveSingleStepPage == pageAddr) {
            KeReleaseSpinLock(&g_RangesLock, irql);
            while (g_ActiveSingleStepPage == pageAddr) {
                _mm_pause();
            }
            irql = KeAcquireSpinLockRaiseToDpc(&g_RangesLock);
            continue;
        }

        found = PolicyLookup(pageAddr, &range);
        break;
    }

    if (!found) {
        KeReleaseSpinLock(&g_RangesLock, irql);
        return FALSE;
    }

    // Read-only attempt: permanently grant read on this page. The backend
    // updates the EPT/NPT entry and invalidates the current-core TLB.
    if (IsRead && !IsWrite && !IsExecute) {
        KeReleaseSpinLock(&g_RangesLock, irql);

        if (IntelGrantPageRead != NULL) {
            // The backend module registers the correct grant primitive based
            // on its vendor at runtime; calling it unconditionally is safe
            // because the wrong-vendor grant returns FALSE without side effect.
            (VOID)IntelGrantPageRead(Cpu, pageAddr);
            (VOID)AmdGrantPageRead(Cpu, pageAddr);
        }
        return TRUE;
    }

    // Write / execute attempt: enter single-step isolation.
    if (Cpu->SingleStepPending) {
        // A previous single-step is still outstanding on this core. The Cpu
        // must have drained it before we can arm another; reaching this point
        // indicates a lost completion exit. Bail out and let the outer loop
        // re-enter, which will surface the fault to the diagnostic path.
        KeReleaseSpinLock(&g_RangesLock, irql);
        return FALSE;
    }

    // Save the exact original PTE mapping onto the Cpu context. The backend
    // captures both the EPT/NPT slot value and any auxiliary permission bits.
    g_HvOps->SaveEntry(Cpu, pageAddr, &Cpu->SavedProtection);

    // Relax permissions for the current core only. Other cores keep their TLB
    // entries pointing at the original strict PTE, so the relaxation is
    // invisible outside this core.
    g_HvOps->RelaxPermissions(Cpu, pageAddr);

    // Arm the single-step framework (Intel: MTF; AMD: TF/RF + #DB intercept).
    g_HvOps->ArmSingleStep(Cpu);

    Cpu->SingleStepPage    = pageAddr;
    Cpu->SingleStepPending = TRUE;

    // Publish the tracked page for adjacent-core serialization.
    InterlockedExchange64((volatile LONG64*)&g_ActiveSingleStepPage,
                          (LONG64)pageAddr);

    KeReleaseSpinLock(&g_RangesLock, irql);
    return TRUE;
}

// =============================================================================
// Single-step completion handler.
//
// Intel: MONITOR_TRAP_FLAG exit. AMD: SVM_EXIT_EXCP_BASE + 1 (#DB intercept).
//
// If Cpu->SingleStepPending is set, this completion belongs to us: restore the
// original strict protection, disarm single-step, broadcast a TLB shootdown so
// every core observes the restored mapping, and clear the execution flags.
//
// If Cpu->SingleStepPending is clear on AMD, this #DB was guest-native
// (debugger or hardware breakpoint). We must not swallow it — reinject #DB
// through the intercept path so the guest debugger keeps working.
// =============================================================================
static VOID
HandleSingleStepCompletion(
    _Inout_ PCPU_CONTEXT Cpu,
    _In_    BOOLEAN      IsIntel
    )
{
    if (!Cpu->SingleStepPending) {
        if (!IsIntel) {
            // Guest-native #DB. Reinject into the guest context.
            g_HvOps->InjectException(Cpu, kExceptionDb, 0, 0);
        }
        return;
    }

    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&g_RangesLock);

    g_HvOps->RestoreEntry(Cpu);
    g_HvOps->DisarmSingleStep(Cpu);
    g_HvOps->InvalidateTlbAll(Cpu);

    Cpu->SingleStepPending = FALSE;
    Cpu->SingleStepPage    = 0;

    InterlockedExchange64((volatile LONG64*)&g_ActiveSingleStepPage, 0);

    KeReleaseSpinLock(&g_RangesLock, irql);
}

// =============================================================================
// Hypercall handler.
//
// Only a single authenticated hypercall is recognized: HV_HYPERCALL_TEARDOWN.
// Because an arbitrary untrusted Ring 0 driver could otherwise disable memory
// security defenses, the teardown hypercall requires a pre-shared cryptographic
// verification secret. Nonce and signature are supplied in guest registers by
// the caller and validated by the HV operations layer.
// =============================================================================
static VOID
HandleHypercall(
    _Inout_ UINT64*      GuestRegs,
    _Inout_ PCPU_CONTEXT Cpu,
    _In_    BOOLEAN      IsIntel
    )
{
    const UINT64 hypercallId = GuestRegs[RegRax];

    if (hypercallId != (UINT64)HV_HYPERCALL_TEARDOWN) {
        // Unknown hypercall — ignore and advance past the instruction.
        return;
    }

    // Cryptographic verification: nonce in RBX, HMAC-style signature in RCX.
    // Any failure is a silent reject; we must not surface a distinguishable
    // status to the caller or an attacker gains an oracle.
    const UINT64 nonce     = GuestRegs[RegRbx];
    const UINT64 signature = GuestRegs[RegRcx];

    if (!g_HvOps->VerifyHypercallAuth(nonce, signature)) {
        return;
    }

    if (IsIntel) {
        IntelHandleTeardownVmcall(GuestRegs, Cpu);
    } else {
        SvmHandleTeardownVmcall(GuestRegs, Cpu);
    }
}

// =============================================================================
// Fatal-exit diagnostic + safe host recovery loop.
//
// Reached for VMEXIT_INVALID and for any exit code the master dispatcher does
// not recognize. Execution context is logged once, the shutdown flag is
// latched, and the current core is parked in a low-power recovery loop while
// the rest of the system observes the teardown request.
// =============================================================================
static VOID
FatalHostRecovery(
    _In_ UINT32  ExitReason,
    _In_ UINT64  Qualification,
    _In_ UINT64  GuestRip,
    _In_ UINT64* GuestRegs
    )
{
    DbgPrint("[vmexit] FATAL exit=0x%08X qual=0x%016llX rip=0x%016llX "
             "rax=0x%016llX rbx=0x%016llX rcx=0x%016llX rdx=0x%016llX\n",
             ExitReason,
             Qualification,
             GuestRip,
             GuestRegs[RegRax],
             GuestRegs[RegRbx],
             GuestRegs[RegRcx],
             GuestRegs[RegRdx]);

    InterlockedExchange(&g_ShuttingDown, 1);

    for (;;) {
        KeStallExecutionProcessor(100);
        YieldProcessor();
    }
}

// =============================================================================
// Intel VMX master exit dispatcher.
// =============================================================================
extern "C"
VOID
VmxVmExitHandlerC(
    _Inout_ UINT64* GuestRegs
    )
{
    PCPU_CONTEXT Cpu = GetCurrentCpuContext();

    const UINT64 rawReason     = ReadVmcsField(VMCS_EXIT_REASON);
    const UINT64 qualification = ReadVmcsField(VMCS_EXIT_QUALIFICATION);
    const UINT64 guestRip      = ReadVmcsField(VMCS_GUEST_RIP);
    const UINT64 instrLength   = ReadVmcsField(VMCS_EXIT_INSTRUCTION_LENGTH);
    const UINT32 exitReason    = (UINT32)(rawReason & 0xFFFF);

    // Fast shutdown path: skip all policy, only advance RIP for instructions
    // we would normally consume. This prevents teardown from deadlocking on
    // a CPUID / hypercall loop while the rest of the system winds down.
    if (InterlockedCompareExchange(&g_ShuttingDown, 0, 0) != 0) {
        if (exitReason == EXIT_REASON_CPUID) {
            HandleCpuidExit(GuestRegs);
            WriteVmcsField(VMCS_GUEST_RIP, guestRip + instrLength);
        } else if (exitReason == EXIT_REASON_VMCALL) {
            WriteVmcsField(VMCS_GUEST_RIP, guestRip + instrLength);
        } else if (exitReason == EXIT_REASON_MONITOR_TRAP_FLAG) {
            if (Cpu->SingleStepPending) {
                HandleSingleStepCompletion(Cpu, TRUE);
            }
        }
        return;
    }

    // VMX uses 0xFFFF as the "invalid exit reason" sentinel. Handle it before
    // the switch so a signed comparison never masks it as a valid reason.
    if ((rawReason & 0xFFFF) == 0xFFFF) {
        FatalHostRecovery(0xFFFF, qualification, guestRip, GuestRegs);
        return;
    }

    switch (exitReason) {

    case EXIT_REASON_CPUID: {
        HandleCpuidExit(GuestRegs);
        // VMX does not auto-advance GUEST_RIP; the hardware-provided
        // instruction length is the only architecturally correct step.
        WriteVmcsField(VMCS_GUEST_RIP, guestRip + instrLength);
        break;
    }

    case EXIT_REASON_VMCALL: {
        HandleHypercall(GuestRegs, Cpu, TRUE);
        WriteVmcsField(VMCS_GUEST_RIP, guestRip + instrLength);
        break;
    }

    case EXIT_REASON_EPT_VIOLATION: {
        EPT_EXIT_QUALIFICATION eq;
        eq.Value = qualification;

        const UINT64 gpa = ReadVmcsField(VMCS_GUEST_PHYSICAL_ADDRESS);

        (VOID)HandleMemoryViolation(
            Cpu,
            gpa,
            (BOOLEAN)eq.Read,
            (BOOLEAN)eq.Write,
            (BOOLEAN)eq.Execute);

        // No RIP advance: the instruction must be re-executed after the PTE
        // has been relaxed or read access has been granted.
        break;
    }

    case EXIT_REASON_MONITOR_TRAP_FLAG: {
        HandleSingleStepCompletion(Cpu, TRUE);
        break;
    }

    default: {
        FatalHostRecovery(exitReason, qualification, guestRip, GuestRegs);
        break;
    }
    }
}

// =============================================================================
// AMD SVM master exit dispatcher.
// =============================================================================
extern "C"
VOID
SvmVmExitHandlerC(
    _Inout_ UINT64* GuestRegs
    )
{
    PCPU_CONTEXT Cpu = GetCurrentCpuContext();

    const UINT64 exitCode     = Cpu->Vmcb->Control.ExitCode;
    const UINT64 qualification = Cpu->Vmcb->Control.ExitInfo1;
    const UINT64 guestRip     = Cpu->Vmcb->StateSave.Rip;
    const UINT32 exitReason   = (UINT32)(exitCode & 0xFFFFFFFFULL);

    // Fast shutdown path: identical semantics to the Intel dispatcher. On AMD
    // the hardware has already populated Control.Nrip, so advancing RIP is a
    // single state-save update.
    if (InterlockedCompareExchange(&g_ShuttingDown, 0, 0) != 0) {
        if (exitReason == SVM_EXIT_CPUID) {
            HandleCpuidExit(GuestRegs);
            Cpu->Vmcb->StateSave.Rip = Cpu->Vmcb->Control.Nrip;
        } else if (exitReason == SVM_EXIT_VMMCALL) {
            Cpu->Vmcb->StateSave.Rip = Cpu->Vmcb->Control.Nrip;
        } else if (exitReason == (SVM_EXIT_EXCP_BASE + 1)) {
            if (Cpu->SingleStepPending) {
                HandleSingleStepCompletion(Cpu, FALSE);
            }
        }
        return;
    }

    switch (exitReason) {

    case SVM_EXIT_CPUID: {
        HandleCpuidExit(GuestRegs);
        // AMD hardware has already advanced Control.Nrip past CPUID; propagate
        // that architecturally-correct value into the state-save RIP so VMRUN
        // resumes at the next instruction.
        Cpu->Vmcb->StateSave.Rip = Cpu->Vmcb->Control.Nrip;
        break;
    }

    case SVM_EXIT_VMMCALL: {
        HandleHypercall(GuestRegs, Cpu, FALSE);
        Cpu->Vmcb->StateSave.Rip = Cpu->Vmcb->Control.Nrip;
        break;
    }

    case SVM_EXIT_NPF: {
        NPF_EXITINFO1 info;
        info.Value = qualification;

        const UINT64 gpa = Cpu->Vmcb->Control.ExitInfo2;

        (VOID)HandleMemoryViolation(
            Cpu,
            gpa,
            (BOOLEAN)info.Read,
            (BOOLEAN)info.Write,
            (BOOLEAN)info.Execute);

        // No RIP advance: re-execute the faulting instruction after the
        // permission fix has taken effect.
        break;
    }

    case (SVM_EXIT_EXCP_BASE + 1): {
        // #DB. Either our single-step completion or a guest-native debugger
        // breakpoint; HandleSingleStepCompletion discriminates and reinjects
        // guest-native #DB when appropriate.
        HandleSingleStepCompletion(Cpu, FALSE);
        break;
    }

    default: {
        FatalHostRecovery(exitReason, qualification, guestRip, GuestRegs);
        break;
    }
    }
}
