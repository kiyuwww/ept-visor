// ============================================================================
//  vmexit.cpp — master VM-exit dispatcher (Intel VMX + AMD SVM).
//
//  Both assembly entry stubs (VmxVmExitEntry / SvmVmExitEntry) push the live
//  GPR frame and call into this module. The dispatcher owns exit routing,
//  CPUID emulation, EPT/NPF resolution, single-step guarded recovery, and
//  authenticated teardown hypercalls.
//
//  Register-file contract (the core asymmetry between the two vendors):
//
//    Intel VMX does not swap GPRs on #VMEXIT at all — every guest register
//    is still live in the CPU when the stub pushes it, so the full frame in
//    GuestRegs is the guest state and VMCS_GUEST_RIP is advanced explicitly
//    by the instruction-length field.
//
//    AMD #VMEXIT microcodes RAX, RSP and RIP into the VMCB save area and
//    reloads host RAX/RSP/RIP from the pre-VMRUN context. The remaining
//    GPRs are not swapped, so GuestRegs holds guest RBX..R15 but the HOST
//    RAX. Any AMD path that touches guest RAX must therefore go through
//    Vmcb->Save.Rax, and any RIP advance must use Vmcb->Control.Nrip
//    (NextRip, populated by hardware when CPUID Fn8000_000A EDX.NRIPS is
//    set). Writing GuestRegs[RegRax] on AMD would corrupt host state and
//    silently discard the CPUID result.
//
//  Shutdown contract: g_ShuttingDown never disables exit interception. The
//  shutdown fast path runs after exit-reason decode and routes a teardown
//  hypercall straight to its handler; every other exit is stepped past so a
//  winding-down core always makes forward progress instead of spinning on
//  the same guest instruction.
// ============================================================================

#include <ntddk.h>
#include <intrin.h>
#include "common.h"

// -----------------------------------------------------------------------------
//  Vendor teardown primitives (implemented in intel_vmm.cpp / amd_svm.cpp).
//  They perform the vendor-specific step-down (VMXOFF path / EFER.SVME clear)
//  and are invoked only after cryptographic authorization has passed.
// -----------------------------------------------------------------------------
NTSTATUS IntelHandleTeardownVmcall(PPCPU_CONTEXT Cpu);
NTSTATUS SvmHandleTeardownVmcall(PPCPU_CONTEXT Cpu);

// -----------------------------------------------------------------------------
//  Guest register frame index layout. Matches the layout pushed by the
//  assembly stubs before they C-call into this module. On AMD, slot RegRax
//  carries the host RAX and must never be read as guest state.
// -----------------------------------------------------------------------------
enum : UINT32 {
    RegRax = 0, RegRcx = 1, RegRdx = 2, RegRbx = 3,
    RegRsp = 4, RegRbp = 5, RegRsi = 6, RegRdi = 7,
    RegR8  = 8, RegR9  = 9, RegR10 = 10, RegR11 = 11,
    RegR12 = 12, RegR13 = 13, RegR14 = 14, RegR15 = 15
};

static const UINT64 kPage4kMask   = 0xFFFFFFFFFFFFF000ULL;
static const UINT32 kExceptionDb  = 1;    // #DB architectural vector
static const UINT32 kExceptionPf  = 14;   // #PF architectural vector

// #PF error-code bits (Intel SDM Vol 3A 4.7 / AMD APM Vol 2 8.4)
#define PF_EC_PRESENT                   0x01
#define PF_EC_WRITE                     0x02
#define PF_EC_USER                      0x04
#define PF_EC_FETCH                     0x10

// -----------------------------------------------------------------------------
//  Exit qualification decoders.
//
//  Intel EPT violation (SDM Vol 3C, Table 28-7):
//    bit 0  data read, bit 1 data write, bit 2 instruction fetch
//    bit 3  EPT read permission for the GPA (1 = reads were permitted)
//    bit 4  EPT write permission, bit 5 EPT execute permission
//    bit 6  guest linear address validity — GUEST_LINEAR_ADDRESS is only
//           architecturally defined for this exit when this bit is set;
//           bit 7 is reserved
//    bit 12 guest physical address validity
//
//  AMD NPF (APM Vol 2, 15.21): Control.ExitInfo1 mirrors the native #PF
//  error code (P[0] W[1] U/S[2] R[3] I/D[4]) and Control.ExitInfo2 carries
//  the faulting guest physical address.
// -----------------------------------------------------------------------------
union EPT_EXIT_QUALIFICATION {
    UINT64 Value;
    struct {
        UINT64 Read          : 1;   // bit 0
        UINT64 Write         : 1;   // bit 1
        UINT64 Execute       : 1;   // bit 2
        UINT64 EptReadPerm   : 1;   // bit 3
        UINT64 EptWritePerm  : 1;   // bit 4
        UINT64 EptExecPerm   : 1;   // bit 5
        UINT64 GlaValid      : 1;   // bit 6 — GLA defined only when set
        UINT64 Reserved0     : 5;   // bits 11:7
        UINT64 GpaValid      : 1;   // bit 12
        UINT64 Reserved1     : 51;
    };
};

union NPF_EXITINFO1 {
    UINT64 Value;
    struct {
        UINT64 Present       : 1;   // bit 0: 1 = protection violation, 0 = not-present
        UINT64 Write         : 1;   // bit 1
        UINT64 User          : 1;   // bit 2: U/S
        UINT64 Read          : 1;   // bit 3: R — read access
        UINT64 Execute       : 1;   // bit 4: I/D — instruction fetch
        UINT64 Reserved      : 59;
    };
};

// =============================================================================
//  CPUID emulation — Intel form.
//
//  CPUID is fixed-width and side-effect-free. The guest selects the leaf in
//  EAX and the sub-leaf in ECX; the host executes the native CPUID with
//  those selectors and writes the four 32-bit outputs back, each explicitly
//  zero-extended: architectural CPUID outputs are 32-bit and the upper
//  halves of RAX/RBX/RCX/RDX must be cleared or subsequent guest 64-bit
//  reads observe stale garbage. The full guest GPR set is live in the stub
//  frame, so all four destinations are GuestRegs slots.
// =============================================================================
static VOID HandleCpuidExitIntel(_Inout_ UINT64* GuestRegs)
{
    int regs[4] = { 0, 0, 0, 0 };

    const UINT32 leaf    = (UINT32)(GuestRegs[RegRax] & 0xFFFFFFFFULL);
    const UINT32 subleaf = (UINT32)(GuestRegs[RegRcx] & 0xFFFFFFFFULL);

    __cpuidex(regs, (int)leaf, (int)subleaf);

    GuestRegs[RegRax] = (UINT64)(UINT32)regs[0];
    GuestRegs[RegRbx] = (UINT64)(UINT32)regs[1];
    GuestRegs[RegRcx] = (UINT64)(UINT32)regs[2];
    GuestRegs[RegRdx] = (UINT64)(UINT32)regs[3];
}

// =============================================================================
//  CPUID emulation — AMD form.
//
//  Identical semantics, different register file: the leaf selector lives in
//  Vmcb->Save.Rax (hardware-saved guest RAX), the sub-leaf arrives in the
//  stub frame (guest RCX is not swapped by #VMEXIT), and only the RAX
//  result is written back through the VMCB save area. RBX/RCX/RDX results
//  go back through the stub frame, which still aliases the guest GPRs.
// =============================================================================
static VOID HandleCpuidExitAmd(_Inout_ PVMCB Vmcb, _Inout_ UINT64* GuestRegs)
{
    int regs[4] = { 0, 0, 0, 0 };

    const UINT32 leaf    = (UINT32)(Vmcb->Save.Rax & 0xFFFFFFFFULL);
    const UINT32 subleaf = (UINT32)(GuestRegs[RegRcx] & 0xFFFFFFFFULL);

    __cpuidex(regs, (int)leaf, (int)subleaf);

    Vmcb->Save.Rax    = (UINT64)(UINT32)regs[0];
    GuestRegs[RegRbx] = (UINT64)(UINT32)regs[1];
    GuestRegs[RegRcx] = (UINT64)(UINT32)regs[2];
    GuestRegs[RegRdx] = (UINT64)(UINT32)regs[3];
}

// =============================================================================
//  RIP advancement.
// =============================================================================

// Intel: VMX never auto-advances GUEST_RIP; the hardware-supplied
// VMCS_EXIT_INSTRUCTION_LENGTH is the only architecturally correct step.
static __forceinline VOID VmxAdvanceRip(_In_ UINT64 GuestRip, _In_ UINT64 InstrLength)
{
    VmWrite64(VMCS_GUEST_RIP, GuestRip + InstrLength);
}

// AMD: Control.Nrip holds RIP+len of the exiting instruction for every exit
// this dispatcher advances (NRIPS is verified during the capability audit).
// A zero Nrip means the facility is unavailable on this core — fall back to
// the fixed encoding length of the exiting instruction.
static __forceinline VOID SvmAdvanceRip(_Inout_ PVMCB Vmcb, _In_ UINT64 FallbackLength)
{
    const UINT64 nrip = Vmcb->Control.Nrip;
    Vmcb->Save.Rip = (nrip != 0) ? nrip : (Vmcb->Save.Rip + FallbackLength);
}

// =============================================================================
//  Architectural denial — guest #PF synthesis.
//
//  When a fault cannot be resolved by policy (page outside every protected
//  range, or an outstanding single-step on this core), the access is denied
//  by injecting a not-present #PF into the guest architectural state. The
//  vendor backend routes the fault address into CR2 (VMCS_GUEST_CR2 / the
//  VMCB CR2 save field) before the next VMRESUME/VMRUN, so the guest OS
//  delivers it to the faulting thread exactly as hardware would. The fault
//  address must be the guest LINEAR address; the GPA produced by the EPT/NPT
//  walk is used only as a last resort when no valid GLA is available.
// =============================================================================
static VOID InjectDenialPageFault(
    _In_ PPCPU_CONTEXT Cpu,
    _In_ UINT64        FaultAddress,
    _In_ BOOLEAN       IsWrite,
    _In_ BOOLEAN       IsExecute,
    _In_ BOOLEAN       UserMode
    )
{
    UINT32 errorCode = 0;                       // P = 0: not-present denial
    if (IsWrite)   errorCode |= PF_EC_WRITE;
    if (UserMode)  errorCode |= PF_EC_USER;
    if (IsExecute) errorCode |= PF_EC_FETCH;

    (VOID)g_HvOps->InjectException(Cpu, kExceptionPf, errorCode, FaultAddress);
}

// =============================================================================
//  Unified memory-violation resolver.
//
//  Called for Intel EPT violations and AMD nested page faults. The caller
//  has already decoded the access intent from the vendor qualification word;
//  this routine owns the policy engine and the single-step trap-flip.
//
//  Resolution policy:
//    * Page outside every protected range -> architectural #PF denial.
//    * Access fully allowed by policy     -> stale/edge fault (TLB lag after
//      a restore); grant the attempted access and let it re-execute.
//    * Read-only probe                    -> granted once, permanently: the
//      protection model hides pages from bulk scans until a legitimate
//      reader touches them, then the read permission stays open.
//    * Write or execute attempt           -> single-step isolation:
//        1. SaveEntry journals the raw strict leaf into Cpu->SavedPteValue
//           and the page into Cpu->SingleStepPageGpa (per-core state — no
//           cross-core tracking slot exists, so two cores can isolate
//           different pages concurrently without collision).
//        2. RelaxPermissions re-opens only the attempted access for this
//           core; other cores keep their strict TLB state.
//        3. ArmSingleStep arms MTF (Intel) / RFLAGS.TF+#DB (AMD).
//      The very next guest instruction triggers the completion exit, which
//      restores the journaled leaf and re-seals the page.
//
//  Locking discipline: only SpinAcquire(&g_RangesLock) — a bare CMPXCHG lock
//  with no IRQL manipulation. Blocking primitives such as
//  KeAcquireSpinLockRaiseToDpc are forbidden in root context: raising IRQL
//  here would deadlock against the lock-order inversion between the range
//  lock and any paged code path the guest interrupted.
// =============================================================================
static BOOLEAN
HandleMemoryViolation(
    _In_ PPCPU_CONTEXT Cpu,
    _In_ UINT64        GuestPhysicalAddress,
    _In_ BOOLEAN       IsRead,
    _In_ BOOLEAN       IsWrite,
    _In_ BOOLEAN       IsExecute,
    _In_ UINT64        GuestLinearAddress,
    _In_ BOOLEAN       GuestLinearValid,
    _In_ BOOLEAN       GuestUserMode
    )
{
    const UINT64 page = GuestPhysicalAddress & kPage4kMask;

    // ---- Phase 1: policy interrogation under a short lock zone. ----
    ULONG ownerPid     = 0;
    ULONG allowedPerms = 0;
    BOOLEAN isProtected;

    SpinAcquire(&g_RangesLock);
    isProtected = PolicyLookup(page, &ownerPid, &allowedPerms);
    SpinRelease(&g_RangesLock);

    if (!isProtected) {
        // Not ours to adjudicate: deny the access architecturally. Prefer
        // the guest linear address for CR2 precision when hardware supplied
        // one; otherwise the GPA is the only addressable witness.
        const UINT64 faultAddress = (GuestLinearValid && GuestLinearAddress != 0)
                                  ? GuestLinearAddress
                                  : GuestPhysicalAddress;
        InjectDenialPageFault(Cpu, faultAddress, IsWrite, IsExecute, GuestUserMode);
        return FALSE;
    }

    const ULONG attempted = (ULONG)((IsRead    ? NPT_PERM_READ    : 0) |
                                    (IsWrite   ? NPT_PERM_WRITE   : 0) |
                                    (IsExecute ? NPT_PERM_EXECUTE : 0));

    // ---- Access fully covered by policy: stale fault after a restore —
    //      reopen the attempted access and re-execute. ----
    if (attempted != 0 && (attempted & ~allowedPerms) == 0) {
        SpinAcquire(&g_RangesLock);
        (VOID)g_HvOps->RelaxPermissions(Cpu, page, attempted);
        SpinRelease(&g_RangesLock);
        return TRUE;
    }

    // ---- Read-only probe: grant read permanently, then re-execute. ----
    if (IsRead && !IsWrite && !IsExecute) {
        SpinAcquire(&g_RangesLock);
        (VOID)g_HvOps->RelaxPermissions(Cpu, page, NPT_PERM_READ);
        SpinRelease(&g_RangesLock);
        return TRUE;
    }

    // ---- Write / execute attempt: single-step isolation. ----
    if (Cpu->SingleStepPending != 0) {
        // A previous single-step is still outstanding on this core; the
        // completion exit has not drained it. Deny rather than stacking a
        // second relaxation — the journaled leaf would be overwritten and
        // the original protection lost.
        const UINT64 faultAddress = (GuestLinearValid && GuestLinearAddress != 0)
                                  ? GuestLinearAddress
                                  : GuestPhysicalAddress;
        InjectDenialPageFault(Cpu, faultAddress, IsWrite, IsExecute, GuestUserMode);
        return FALSE;
    }

    SpinAcquire(&g_RangesLock);

    // Journal the strict leaf onto the per-core context; the completion
    // handler restores exactly this descriptor image.
    (VOID)g_HvOps->SaveEntry(Cpu, page);

    // Re-open only the attempted access for the re-execution window.
    (VOID)g_HvOps->RelaxPermissions(Cpu, page, attempted);

    // Arm the hardware trap: MTF on Intel, RFLAGS.TF + #DB on AMD.
    g_HvOps->ArmSingleStep(Cpu);

    Cpu->SingleStepPageGpa  = page;
    Cpu->SingleStepFlipped  = TRUE;
    Cpu->SingleStepPending  = 1;

    SpinRelease(&g_RangesLock);
    return TRUE;
}

// =============================================================================
//  Single-step completion handler.
//
//  Intel: MONITOR_TRAP_FLAG exit. AMD: SVM_EXIT_EXCP_BASE + 1 (#DB intercept).
//
//  If Cpu->SingleStepPending is set, the trap belongs to the isolation
//  engine: restore the journaled strict leaf, disarm the trap, flush the
//  core's translation caches so the sealed mapping is observed on re-entry,
//  and clear the per-core tracking state. RestoreEntry consumes
//  Cpu->SavedPteValue / Cpu->SingleStepPageGpa directly — no global state.
//
//  If the flag is clear on AMD, this #DB is a guest-native breakpoint
//  (debugger or DR7 hardware match). Swallowing it would silently vanish
//  the guest debugger; the event is reinjected through EVENTINJ with the
//  #DB vector so it is delivered at the next VMRUN exactly as raised.
//  On Intel, #DB is not intercepted in this design, so a pending-less MTF
//  exit is treated as spurious and discarded.
// =============================================================================
static VOID
HandleSingleStepCompletion(
    _In_ PPCPU_CONTEXT Cpu,
    _In_ BOOLEAN       IsIntel
    )
{
    if (Cpu->SingleStepPending != 0) {
        SpinAcquire(&g_RangesLock);

        g_HvOps->RestoreEntry(Cpu);
        g_HvOps->DisarmSingleStep(Cpu);
        g_HvOps->InvalidateTlbAll(Cpu);

        Cpu->SingleStepPending  = 0;
        Cpu->SingleStepPageGpa  = 0;
        Cpu->SavedPteValue      = 0;
        Cpu->SingleStepFlipped  = FALSE;

        SpinRelease(&g_RangesLock);
        return;
    }

    if (!IsIntel) {
        (VOID)g_HvOps->InjectException(Cpu, kExceptionDb, 0, 0);
    }
}

// =============================================================================
//  Authenticated teardown hypercall.
//
//  Contract: RAX carries the hypercall token, RBX a one-shot nonce and RCX
//  an HMAC-style signature over it. On AMD the token is read from
//  Vmcb->Save.Rax — GuestRegs[RegRax] holds the host RAX and would never
//  match the token. Nonce and signature live in guest RBX/RCX, which are
//  not swapped by #VMEXIT and are therefore valid in the stub frame.
//
//  VerifyHypercallAuth is constant-time and replay-protected: a nonce
//  window is tracked per caller, so a captured (nonce, signature) pair
//  cannot be replayed. A rejected call is a security event, not a crash —
//  the alarm is logged and the guest resumes at the next instruction; the
//  caller advances RIP either way so no core can spin on the VMMCALL.
// =============================================================================
static VOID
HandleTeardownHypercall(
    _In_ PPCPU_CONTEXT Cpu,
    _Inout_ UINT64*    GuestRegs,
    _In_ BOOLEAN       IsIntel
    )
{
    const UINT64 hypercallId = IsIntel
                             ? GuestRegs[RegRax]
                             : ((PVMCB)Cpu->VmcbVa)->Save.Rax;

    if (hypercallId != HV_HYPERCALL_TEARDOWN)
        return;

    const UINT64 nonce     = GuestRegs[RegRbx];
    const UINT64 signature = GuestRegs[RegRcx];

    UINT64 secretKey = 0;
    if (!VerifyHypercallAuth(nonce, signature, &secretKey)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[vmexit] SECURITY: teardown hypercall auth rejected "
            "(cpu=%u nonce=%llx)\n", Cpu->CpuIndex, nonce);
        return;
    }

    if (IsIntel) {
        (VOID)IntelHandleTeardownVmcall(Cpu);
    } else {
        (VOID)SvmHandleTeardownVmcall(Cpu);
    }
}

// =============================================================================
//  General hypercall router (normal, non-shutdown path).
//
//  Only the teardown token is recognized; any other token is an untrusted
//  probe and the guest resumes past it. RIP advance is owned by the caller
//  for both vendors.
// =============================================================================
static VOID
HandleHypercall(
    _In_ PPCPU_CONTEXT Cpu,
    _Inout_ UINT64*    GuestRegs,
    _In_ BOOLEAN       IsIntel
    )
{
    HandleTeardownHypercall(Cpu, GuestRegs, IsIntel);
}

// =============================================================================
//  Fatal-exit diagnostic + host recovery.
//
//  Reached for VMEXIT_INVALID and any exit code the dispatcher does not
//  recognize. Register context is logged with vendor-correct values, the
//  shutdown latch is set so the remaining cores wind down, and this core is
//  parked: returning would resume a guest whose VMCB/VMCS state just proved
//  to be untrustworthy, and an infinite VMEXIT storm on the same instruction
//  is worse than a quiesced core.
// =============================================================================
static VOID
FatalHostRecovery(
    _In_ UINT32 ExitReason,
    _In_ UINT64 Qualification,
    _In_ UINT64 GuestRip,
    _In_ UINT64 Rax,
    _In_ UINT64 Rbx,
    _In_ UINT64 Rcx,
    _In_ UINT64 Rdx
    )
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[vmexit] FATAL exit=0x%08X qual=0x%016llX rip=0x%016llX "
        "rax=0x%016llX rbx=0x%016llX rcx=0x%016llX rdx=0x%016llX\n",
        ExitReason, Qualification, GuestRip, Rax, Rbx, Rcx, Rdx);

    InterlockedExchange(&g_ShuttingDown, 1);

    for (;;) {
        _mm_pause();
    }
}

// =============================================================================
//  Intel VMX master exit dispatcher.
//
//  All guest GPR traffic flows through the stub frame (VMX does not swap
//  GPRs on exit); RIP advances are explicit via VMCS_EXIT_INSTRUCTION_LENGTH.
// =============================================================================
extern "C"
VOID
VmxVmExitHandlerC(
    _Inout_ UINT64* GuestRegs
    )
{
    PPCPU_CONTEXT Cpu = GetCurrentCpuContext();

    const UINT64 rawReason     = VmRead64(VMCS_EXIT_REASON);
    const UINT64 qualification = VmRead64(VMCS_EXIT_QUALIFICATION);
    const UINT64 guestRip      = VmRead64(VMCS_GUEST_RIP);
    const UINT64 instrLength   = VmRead64(VMCS_EXIT_INSTRUCTION_LENGTH);
    const UINT32 exitReason    = (UINT32)(rawReason & 0xFFFF);

    // VMX uses 0xFFFF as the invalid-exit sentinel; a signed comparison
    // would mask it as a valid reason, so it is filtered before dispatch.
    if (exitReason == 0xFFFF) {
        FatalHostRecovery(0xFFFF, qualification, guestRip,
                          GuestRegs[RegRax], GuestRegs[RegRbx],
                          GuestRegs[RegRcx], GuestRegs[RegRdx]);
        return;
    }

    // ---- Shutdown fast path. Exit reason is decoded FIRST so the teardown
    // hypercall still lands in its handler while g_ShuttingDown is latched;
    // everything else steps past the instruction to guarantee forward
    // progress on a winding-down core. ----
    if (g_ShuttingDown != 0) {
        if (exitReason == EXIT_REASON_VMCALL &&
            GuestRegs[RegRax] == HV_HYPERCALL_TEARDOWN) {
            HandleTeardownHypercall(Cpu, GuestRegs, TRUE);
            VmxAdvanceRip(guestRip, instrLength);
            return;
        }

        switch (exitReason) {
        case EXIT_REASON_CPUID:
            HandleCpuidExitIntel(GuestRegs);
            VmxAdvanceRip(guestRip, instrLength);
            break;
        case EXIT_REASON_VMCALL:
            VmxAdvanceRip(guestRip, instrLength);
            break;
        case EXIT_REASON_MONITOR_TRAP_FLAG:
            if (Cpu->SingleStepPending != 0)
                HandleSingleStepCompletion(Cpu, TRUE);
            break;
        default:
            // Includes unresolved EPT violations: the faulting instruction
            // is skipped so the core cannot loop on it during teardown.
            VmxAdvanceRip(guestRip, instrLength);
            break;
        }
        return;
    }

    switch (exitReason) {

    case EXIT_REASON_CPUID: {
        HandleCpuidExitIntel(GuestRegs);
        VmxAdvanceRip(guestRip, instrLength);
        break;
    }

    case EXIT_REASON_VMCALL: {
        HandleHypercall(Cpu, GuestRegs, TRUE);
        VmxAdvanceRip(guestRip, instrLength);
        break;
    }

    case EXIT_REASON_EPT_VIOLATION: {
        EPT_EXIT_QUALIFICATION eq;
        eq.Value = qualification;

        const UINT64 gpa = VmRead64(VMCS_GUEST_PHYSICAL_ADDRESS);

        // GUEST_LINEAR_ADDRESS is architecturally valid only when the
        // qualification marks it so; it supplies the precise CR2 address
        // for any #PF denial this fault resolves into.
        const BOOLEAN glaValid = eq.GlaValid != 0;
        const UINT64  gla      = glaValid ? VmRead64(VMCS_GUEST_LINEAR_ADDRESS) : 0;

        // Guest privilege for the #PF U/S bit: DPL of the guest CS access
        // rights (bits 6:5); DPL 3 = user-mode fault.
        const UINT32 csAr = (UINT32)VmRead64(VMCS_GUEST_CS_AR);
        const BOOLEAN userMode = ((csAr >> 5) & 3) == 3;

        (VOID)HandleMemoryViolation(
            Cpu, gpa,
            (BOOLEAN)eq.Read, (BOOLEAN)eq.Write, (BOOLEAN)eq.Execute,
            gla, glaValid, userMode);

        // No RIP advance: the faulting instruction re-executes after the
        // permission relaxation takes effect.
        break;
    }

    case EXIT_REASON_MONITOR_TRAP_FLAG: {
        HandleSingleStepCompletion(Cpu, TRUE);
        break;
    }

    default: {
        FatalHostRecovery(exitReason, qualification, guestRip,
                          GuestRegs[RegRax], GuestRegs[RegRbx],
                          GuestRegs[RegRcx], GuestRegs[RegRdx]);
        break;
    }
    }
}

// =============================================================================
//  AMD SVM master exit dispatcher.
//
//  RAX, RSP and RIP live in the VMCB save area (hardware-managed); RBX..R15
//  are guest-live in the stub frame. RIP advancement uses Control.Nrip.
// =============================================================================
extern "C"
VOID
SvmVmExitHandlerC(
    _Inout_ UINT64* GuestRegs
    )
{
    PPCPU_CONTEXT Cpu = GetCurrentCpuContext();
    PVMCB Vmcb = (PVMCB)Cpu->VmcbVa;

    if (Vmcb == NULL)
        return;

    const UINT32 exitReason = (UINT32)(Vmcb->Control.ExitCode & 0xFFFFFFFFULL);
    const UINT64 guestRip   = Vmcb->Save.Rip;

    // ---- Shutdown fast path: identical ordering to the Intel dispatcher —
    // exit reason decoded first, teardown hypercall routed before any
    // bypass, everything else stepped past via NextRip. ----
    if (g_ShuttingDown != 0) {
        if (exitReason == SVM_EXIT_VMMCALL &&
            Vmcb->Save.Rax == HV_HYPERCALL_TEARDOWN) {
            HandleTeardownHypercall(Cpu, GuestRegs, FALSE);
            SvmAdvanceRip(Vmcb, 3);        // VMMCALL = 0F 01 D9 (3 bytes)
            return;
        }

        switch (exitReason) {
        case SVM_EXIT_CPUID:
            HandleCpuidExitAmd(Vmcb, GuestRegs);
            SvmAdvanceRip(Vmcb, 2);        // CPUID = 0F A2 (2 bytes)
            break;
        case SVM_EXIT_VMMCALL:
            SvmAdvanceRip(Vmcb, 3);
            break;
        case SVM_EXIT_EXCP_BASE + 1:
            if (Cpu->SingleStepPending != 0)
                HandleSingleStepCompletion(Cpu, FALSE);
            break;
        default:
            // Includes unresolved NPFs: skip the faulting instruction so a
            // winding-down core cannot spin on the same page fault.
            SvmAdvanceRip(Vmcb, 0);
            break;
        }
        return;
    }

    switch (exitReason) {

    case SVM_EXIT_CPUID: {
        HandleCpuidExitAmd(Vmcb, GuestRegs);
        // Hardware populated Control.Nrip past the CPUID; propagate it into
        // the save-area RIP so VMRUN resumes at the next instruction.
        SvmAdvanceRip(Vmcb, 2);
        break;
    }

    case SVM_EXIT_VMMCALL: {
        HandleHypercall(Cpu, GuestRegs, FALSE);
        SvmAdvanceRip(Vmcb, 3);
        break;
    }

    case SVM_EXIT_NPF: {
        NPF_EXITINFO1 info;
        info.Value = Vmcb->Control.ExitInfo1;

        // The faulting guest physical address is delivered explicitly in
        // ExitInfo2 — it is never derived from ExitInfo1, which is the
        // native #PF error-code image.
        const UINT64 gpa = Vmcb->Control.ExitInfo2;

        (VOID)HandleMemoryViolation(
            Cpu, gpa,
            (BOOLEAN)info.Read,
            (BOOLEAN)info.Write,
            (BOOLEAN)info.Execute,
            0, FALSE,
            Vmcb->Save.Cpl == 3);

        // No RIP advance: the faulting instruction re-executes after the
        // permission fix takes effect.
        break;
    }

    case SVM_EXIT_EXCP_BASE + 1: {
        // #DB. Either the isolation engine's single-step completion or a
        // guest-native debugger breakpoint; the completion handler
        // discriminates on SingleStepPending and reinjects guest-native
        // #DB via EVENTINJ instead of swallowing it.
        HandleSingleStepCompletion(Cpu, FALSE);
        break;
    }

    default: {
        FatalHostRecovery(exitReason, Vmcb->Control.ExitInfo1, guestRip,
                          Vmcb->Save.Rax, GuestRegs[RegRbx],
                          GuestRegs[RegRcx], GuestRegs[RegRdx]);
        break;
    }
    }
}
