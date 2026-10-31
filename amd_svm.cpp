// ============================================================================
//  amd_svm.cpp — AMD-V (SVM) core execution module: VMCB lifecycle, per-CPU
//  bring-up, VMRUN launch, single-step NPT entry maintenance, and teardown.
//
//  Architectural reference: AMD64 Architecture Programmer's Manual Volume 2,
//  Chapter 15 (SVM) and Appendix B (VMCB layout).
//
//  Engine mechanics implemented here:
//
//    SETUP   A 4KB physically contiguous Host Save Area (HSAVE) is allocated
//            per logical processor and registered in MSR_VM_HSAVE_PA. VMRUN
//            microcodes a block host-state save/restore through this area;
//            executing VMRUN with an invalid or unregistered HSAVE pointer
//            raises #GP / machine check. EFER.SVME gates the whole SVM
//            instruction set on the logical processor that owns the MSR.
//
//    LAUNCH  VMRUN loads guest state from the VMCB save area, validates the
//            control area against the architectural consistency checks, and
//            switches CPL/ASID/CR3 context. A consistency-check failure
//            terminates with VMEXIT_INVALID (exit code -1) instead of
//            entering the guest — most commonly caused by a cleared VMRUN
//            intercept (bit 32 of the 64-bit intercept field, exposed here
//            as InterceptMisc2 bit 0) or an invalid HSAVE pointer.
//
//    TLB     TLB_CONTROL (VMCB 0x05C) is a per-VMRUN flush ORDER, not a
//            sticky configuration: encoding 01b orders the next VMRUN to
//            purge the entire TLB, and the order is consumed by that single
//            entry. The order is therefore armed exactly once during VMCB
//            initialization and re-armed only by explicit NPT invalidations;
//            every host-side exit callback parks the field back at 00b so
//            steady-state VMRUN iterations reuse tagged TLB entries instead
//            of forcing a full hardware TLB rebuild per iteration.
//
//    EXIT    #VMEXIT stores guest architectural state into the VMCB save
//            area; the host resumes at RIP+13 of the VMRUN with its own
//            state restored from the HSAVE area by microcode.
//
//    TEARDOWN  SVME is cleared so no further VMRUN can execute. VMSAVE and
//            CLGI belong exclusively to the assembler primitives layer:
//            executing VMSAVE from a host-mode C routine would overwrite
//            the VMCB FS/GS/TR/LDTR (and STAR/LSTAR) save fields with live
//            host values and destroy guest state. Teardown instead captures
//            the guest RIP/RSP/RAX from the VMCB save area, publishes them
//            into the naked stub's register block, and lets the stub perform
//            a native long-mode jump back into guest execution — no SVM
//            instruction ever touches the save area on this path.
//
//  Nested Page Table construction lives in amd_npt.cpp; the single-step
//  entry-maintenance callbacks (save / relax / restore) live here because
//  they are bound to the per-core PCPU_CONTEXT tracking block.
// ============================================================================
#include "common.h"
#include <stddef.h>
#include <intrin.h>

// ----------------------------------------------------------------------------
//  Forward declarations of the lifecycle routines implemented in this TU.
// ----------------------------------------------------------------------------
static NTSTATUS SvmInitialize(VOID);
static VOID     SvmTeardown(VOID);
static VOID     SvmArmSingleStep(PPCPU_CONTEXT Cpu);
static VOID     SvmDisarmSingleStep(PPCPU_CONTEXT Cpu);
static NTSTATUS SvmInjectException(PPCPU_CONTEXT Cpu, UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa);
static NTSTATUS SvmSaveEntry(PPCPU_CONTEXT Cpu, UINT64 Gpa);
static NTSTATUS SvmRelaxPermissions(PPCPU_CONTEXT Cpu, UINT64 Gpa, UINT64 Perms);
static NTSTATUS SvmRestoreEntry(PPCPU_CONTEXT Cpu);

// ----------------------------------------------------------------------------
//  NPT construction exports — implemented in amd_npt.cpp. Page-table build,
//  permission restriction and pool management dispatch into that module; this
//  TU owns the execution lifecycle and the per-core single-step entry edits.
// ----------------------------------------------------------------------------
extern "C" {
    NTSTATUS SvmBuildIdentityMap(const HV_IDENTITY_RANGE* Ranges, ULONG Count);
    NTSTATUS SvmProtectRange(UINT64 Gpa, UINT64 Size, UINT64 Perms);
    VOID     NptFreeAll(VOID);
    UINT64   NptGetPml4Phys(VOID);
    BOOLEAN  NptIsReady(VOID);
}

// ----------------------------------------------------------------------------
//  Dynamic address resolver — implemented in ept_common.cpp. Converts a
//  physical page backing the shared page-table pool into its mapped virtual
//  address, allowing NPT levels to be walked without maintaining parallel
//  virtual arrays.
// ----------------------------------------------------------------------------
extern "C" PVOID HvPtPoolVaFromPa(UINT64 PhysicalAddress);

// ----------------------------------------------------------------------------
//  Assembler-layer primitives. VmxReadTr reads the TR selector through the
//  vendor-neutral stub; SvmLaunch is the naked VMRUN primitive that never
//  "returns" on the success path (it long-jumps away into guest execution).
// ----------------------------------------------------------------------------
extern "C" UINT16 VmxReadTr(VOID);

// ----------------------------------------------------------------------------
//  Exported operations table — bound to the unified template in common.h.
// ----------------------------------------------------------------------------
HV_OPERATIONS g_AmdOps = {
    HvVendorAmd,
    "AMD SVM/NPT",
    SvmInitialize,
    SvmTeardown,
    SvmBuildIdentityMap,
    SvmProtectRange,
    SvmSaveEntry,
    SvmRelaxPermissions,
    SvmRestoreEntry,
    SvmArmSingleStep,
    SvmDisarmSingleStep,
    SvmInjectException,
    SvmInvalidateTlbAll,
};

// ============================================================================
//  SVM constants.
// ============================================================================

#ifndef SVM_GUEST_ASID
#define SVM_GUEST_ASID          1U
#endif

// NP_ENABLE (VMCB control offset 0x090): bit 0 enables nested paging; n_cr3
// at offset 0x0B0 carries the NPT PML4 physical base.
#ifndef SVM_NPT_ENABLE
#define SVM_NPT_ENABLE          1ULL
#endif

// Exception-intercept bitmap (VMCB offset 0x008): bit N traps vector N.
#ifndef SVM_INTERCEPT_DB
#define SVM_INTERCEPT_DB        (1U << 1)
#endif

// #PF (vector 14) is deliberately NEVER armed — see SvmInitializeVmcb.
#ifndef SVM_INTERCEPT_PF
#define SVM_INTERCEPT_PF        (1U << 14)
#endif

// Misc intercept bit for VMRUN (VMCB control offset 0x010, bit 0 of the
// upper 32-bit half of the 64-bit intercept field, i.e. bit 32 architecturally).
// A cleared VMRUN intercept causes the processor's VMRUN consistency check
// to fail with VMEXIT_INVALID (-1) before guest entry ever happens.
#ifndef SVM_INTERCEPT_VMRUN
#define SVM_INTERCEPT_VMRUN     (1U << 0)
#endif

// TLB_CONTROL (VMCB offset 0x05C) encodings.
//   00b — do not flush: steady-state order for every standard VMRUN.
//   01b — flush the entire TLB (all ASIDs, non-global): one-shot purge armed
//         at VMCB initialization and re-armed only by NPT invalidations.
#ifndef SVM_TLBCTL_FLUSH_NOTHING
#define SVM_TLBCTL_FLUSH_NOTHING    0x00
#endif
#ifndef SVM_TLBCTL_FLUSH_ALL
#define SVM_TLBCTL_FLUSH_ALL        0x01
#endif

// MSR_VM_CR (0xC0010114) bit 4: SVMDIS. When set, SVM is disabled by
// platform firmware and cannot be re-enabled by software.
#ifndef SVM_VM_CR_SVMDIS
#define SVM_VM_CR_SVMDIS        (1ULL << 4)
#endif

// Guest PAT is seeded from the host PAT so guest page-attribute encodings
// resolve to the same caching policies the NPT leaves assume.
#ifndef MSR_IA32_PAT
#define MSR_IA32_PAT            0x00000277
#endif

// EVENTINJ (VMCB control offset 0x0A8) field encoding.
#ifndef SVM_EVENTINJ_VALID
#define SVM_EVENTINJ_VALID              (1ULL << 31)   // event consumed by next VMRUN
#define SVM_EVENTINJ_TYPE_EXCEPTION     (3ULL << 8)    // type 3 = hardware exception
#define SVM_EVENTINJ_ERROR_CODE_VALID   (1ULL << 11)   // EV: error code present
#define SVM_EVENTINJ_ERROR_CODE_SHIFT   32             // error code occupies bits 63:32
#endif

// EXITINTINFO (VMCB control offset 0x088): valid bit mirrors EVENTINJ. When
// set, an event intercepted on exit is still pending delivery to the guest.
#ifndef SVM_EXITINTINFO_VALID
#define SVM_EXITINTINFO_VALID   (1U << 31)
#endif

// Teardown hypercall code ('HVmx') issued through the VMMCALL channel.
#ifndef HV_HYPERCALL_TEARDOWN
#define HV_HYPERCALL_TEARDOWN   0x48566D78ULL
#endif

// ----------------------------------------------------------------------------
//  GuestRegs register-block indices.
//
//  The naked assembly stub spills guest GPRs into a linear UINT64 block at
//  #VMEXIT (AMD #VMEXIT does not save GPRs other than RAX/RSP/RIP/RFLAGS —
//  those live in the VMCB save area, everything else is still live in the
//  physical registers when the stub's first instruction executes). These
//  indices must match the GUEST_REGS layout declared in common.h; the
//  overrides below only fire when common.h does not define them.
// ----------------------------------------------------------------------------
#ifndef HV_GUEST_REG_RAX
#define HV_GUEST_REG_RAX    0
#endif
#ifndef HV_GUEST_REG_RSP
#define HV_GUEST_REG_RSP    4
#endif
#ifndef HV_GUEST_REG_RIP
#define HV_GUEST_REG_RIP    17
#endif

// ----------------------------------------------------------------------------
//  NPT leaf-PTE permission masks (AMD64 nested-paging entry format, APM Vol 2
//  chapter 5). The typed NPT_PTE overlay from common.h is the canonical view;
//  permission edits are expressed as mask operations on the raw quadword so
//  the code is independent of compiler bitfield packing order.
// ----------------------------------------------------------------------------
#ifndef NPT_PTE_PRESENT
#define NPT_PTE_PRESENT     (1ULL << 0)                 // P  — readable
#define NPT_PTE_WRITE       (1ULL << 1)                 // R/W
#define NPT_PTE_USER        (1ULL << 2)                 // U/S
#define NPT_PTE_LARGE       (1ULL << 7)                 // PS — 2MB / 1GB leaf
#define NPT_PTE_PFN_MASK    0x000FFFFFFFFFF000ULL       // physical frame, bits 51:12
#define NPT_PTE_NX          (1ULL << 63)                // no-execute
#endif

// Logical permission requests accepted by SvmRelaxPermissions.
#ifndef NPT_PERM_READ
#define NPT_PERM_READ       0x1ULL
#define NPT_PERM_WRITE      0x2ULL
#define NPT_PERM_EXECUTE    0x4ULL
#endif

// ============================================================================
//  VMCB layout definitions (AMD APM Vol 2, App. B).
//
//  Control area: 0x000–0x3FF (1024 bytes)
//  Save area   : 0x400–0x7FF (1024 bytes)
// ============================================================================
#pragma pack(push, 1)

typedef struct _VMCB_SEG {
    UINT16 Selector;    // +0x00
    UINT16 Attrib;      // +0x02  Type[3:0] S[4] DPL[6:5] P[7] AVL[8] L[9]
                        //        DB[10] G[11]
    UINT32 Limit;       // +0x04
    UINT64 Base;        // +0x08
} VMCB_SEG;

typedef struct _VMCB_CONTROL_AREA {
    // 0x000 — CR/DR read/write intercept masks
    UINT16 InterceptCrRead;
    UINT16 InterceptCrWrite;
    UINT16 InterceptDrRead;
    UINT16 InterceptDrWrite;

    // 0x008 — exception intercepts (bit N = vector N)
    UINT32 InterceptExceptions;

    // 0x00C — 64-bit intercept field, split as two dwords:
    //   Misc1 (bits 31:0)  : INTR, NMI, SMI, INIT, VINTR, CR0_SEL_WRITE,
    //                        IDTR/GDTR/LDTR/TR access, RDTSC, RDPMC, PUSHF,
    //                        POPF, CPUID, RSM, IRET, INTn, INVD, PAUSE, HLT,
    //                        INVLPG, INVLPGA, IOIO_PROT, MSR_PROT,
    //                        TASK_SWITCH, FERR_FREEZE, SHUTDOWN
    //   Misc2 (bits 63:32) : VMRUN, VMMCALL, VMLOAD, VMSAVE, STGI, CLGI,
    //                        SKINIT, RDTSCP, ICEBP, WBINVD, MONITOR, MWAIT,
    //                        MWAIT_HALTED, MWAIT_ARMED, XSETBV
    UINT32 InterceptMisc1;
    UINT32 InterceptMisc2;
    UINT32 InterceptMisc3;          // 0x014 — reserved

    UINT8  Reserved0[0x28];

    // 0x040
    UINT64 IopmBasePa;              // I/O permission bitmap (bits 63:12)
    UINT64 MsrpmBasePa;             // MSR permission bitmap (bits 63:12)
    UINT64 TscOffset;               // guest TSC = host TSC + offset

    // 0x058
    UINT32 Asid;                    // address-space identifier (must be != 0)
    UINT8  TlbCtl;                  // TLB_CONTROL — flush order for next VMRUN
    UINT8  Reserved1[3];

    // 0x060 — virtual interrupt delivery
    UINT32 IntCtl;
    UINT32 IntVector;
    UINT32 IntState;
    UINT8  Reserved2[4];

    // 0x070 — exit state
    UINT64 ExitCode;
    UINT64 ExitInfo1;
    UINT64 ExitInfo2;
    UINT32 ExitIntInfo;
    UINT32 ExitIntInfoErr;

    // 0x090
    UINT64 NestedCtl;               // bit 0 = NP_ENABLE

    UINT8  Reserved3[16];

    // 0x0A8 — EVENTINJ: V[7:0] Type[10:8] EV[11] valid[31] ErrorCode[63:32]
    UINT64 EventInj;

    // 0x0B0 — n_cr3: nested (host) page-table base
    UINT64 NestedCr3;

    UINT8  Reserved4[8];

    // 0x0C0 — VMCB clean-bit mask; 0 marks every state group dirty, forcing
    // the processor to re-examine the full control/save surface per VMRUN.
    UINT64 VmcbClean;

    // 0x0C8 — NextRip: saved guest RIP+len of the exiting instruction
    // (requires CPUID Fn8000_000A EDX.NRIPS).
    UINT64 NextRip;

    UINT8  Reserved5[0x330];
} VMCB_CONTROL_AREA;

typedef struct _VMCB_SAVE_AREA {
    // 0x000 (relative to 0x400) — segment save state, 16 bytes each
    VMCB_SEG Es;                    // 0x000
    VMCB_SEG Cs;                    // 0x010
    VMCB_SEG Ss;                    // 0x020
    VMCB_SEG Ds;                    // 0x030
    VMCB_SEG Fs;                    // 0x040
    VMCB_SEG Gs;                    // 0x050
    VMCB_SEG Gdtr;                  // 0x060
    VMCB_SEG Ldtr;                  // 0x070
    VMCB_SEG Idtr;                  // 0x080
    VMCB_SEG Tr;                    // 0x090

    UINT8  Reserved0[0x2B];

    // 0x0CB
    UINT8  Cpl;                     // current privilege level for the guest
    UINT8  Reserved1[0x04];

    // 0x0D0
    UINT64 Efer;                    // guest EFER (SCE/LME/LMA/NXE/SVME)

    UINT8  Reserved2[0x70];

    // 0x148 — control registers
    UINT64 Cr4;
    UINT64 Cr3;
    UINT64 Cr0;
    UINT64 Dr7;
    UINT64 Dr6;
    UINT64 Rflags;
    UINT64 Rip;

    UINT8  Reserved3[0x58];

    // 0x1D8
    UINT64 Rsp;
    UINT64 SCet;
    UINT64 Ssp;
    UINT64 IsstAddr;
    UINT64 Rax;
    UINT64 Star;
    UINT64 Lstar;
    UINT64 Cstar;
    UINT64 Sfmask;
    UINT64 KernelGsBase;
    UINT64 SysenterCs;
    UINT64 SysenterEsp;
    UINT64 SysenterEip;
    UINT64 Cr2;

    UINT8  Reserved4[0x10];

    // 0x258
    UINT64 GPat;                    // guest PAT

    UINT8  Reserved5[0x1A0];
} VMCB_SAVE_AREA;

typedef struct _VMCB {
    VMCB_CONTROL_AREA Control;
    VMCB_SAVE_AREA    Save;
} VMCB, *PVMCB;

#pragma pack(pop)

// ----------------------------------------------------------------------------
//  Compile-time offset guards. Every field this module writes must land on
//  the hardware-defined offset; a padding or field-width mistake would
//  silently corrupt guest state or trip VMRUN consistency checks.
// ----------------------------------------------------------------------------
static_assert(sizeof(VMCB_SEG) == 0x10,                                   "VMCB_SEG size");
static_assert(offsetof(VMCB_CONTROL_AREA, InterceptExceptions) == 0x008,  "VMCB exc intercept");
static_assert(offsetof(VMCB_CONTROL_AREA, InterceptMisc1)      == 0x00C,  "VMCB misc1 intercept");
static_assert(offsetof(VMCB_CONTROL_AREA, InterceptMisc2)      == 0x010,  "VMCB misc2 intercept");
static_assert(offsetof(VMCB_CONTROL_AREA, IopmBasePa)          == 0x040,  "VMCB IOPM base");
static_assert(offsetof(VMCB_CONTROL_AREA, MsrpmBasePa)         == 0x048,  "VMCB MSRPM base");
static_assert(offsetof(VMCB_CONTROL_AREA, TscOffset)           == 0x050,  "VMCB TSC offset");
static_assert(offsetof(VMCB_CONTROL_AREA, Asid)                == 0x058,  "VMCB ASID");
static_assert(offsetof(VMCB_CONTROL_AREA, TlbCtl)              == 0x05C,  "VMCB TLB_CONTROL");
static_assert(offsetof(VMCB_CONTROL_AREA, IntCtl)              == 0x060,  "VMCB INT_CTL");
static_assert(offsetof(VMCB_CONTROL_AREA, ExitCode)            == 0x070,  "VMCB exit code");
static_assert(offsetof(VMCB_CONTROL_AREA, ExitInfo1)           == 0x078,  "VMCB exit info1");
static_assert(offsetof(VMCB_CONTROL_AREA, ExitInfo2)           == 0x080,  "VMCB exit info2");
static_assert(offsetof(VMCB_CONTROL_AREA, NestedCtl)           == 0x090,  "VMCB NP_ENABLE");
static_assert(offsetof(VMCB_CONTROL_AREA, EventInj)            == 0x0A8,  "VMCB EVENTINJ");
static_assert(offsetof(VMCB_CONTROL_AREA, NestedCr3)           == 0x0B0,  "VMCB n_cr3");
static_assert(offsetof(VMCB_CONTROL_AREA, VmcbClean)           == 0x0C0,  "VMCB clean bits");
static_assert(offsetof(VMCB_CONTROL_AREA, NextRip)             == 0x0C8,  "VMCB NextRip");
static_assert(sizeof(VMCB_CONTROL_AREA) == 0x400,                         "VMCB control area size");

static_assert(offsetof(VMCB, Save) == 0x400,                              "VMCB save area base");
static_assert(offsetof(VMCB_SAVE_AREA, Cpl)    == 0x0CB,                  "VMCB CPL");
static_assert(offsetof(VMCB_SAVE_AREA, Efer)   == 0x0D0,                  "VMCB guest EFER");
static_assert(offsetof(VMCB_SAVE_AREA, Cr4)    == 0x148,                  "VMCB guest CR4");
static_assert(offsetof(VMCB_SAVE_AREA, Cr3)    == 0x150,                  "VMCB guest CR3");
static_assert(offsetof(VMCB_SAVE_AREA, Cr0)    == 0x158,                  "VMCB guest CR0");
static_assert(offsetof(VMCB_SAVE_AREA, Dr7)    == 0x160,                  "VMCB guest DR7");
static_assert(offsetof(VMCB_SAVE_AREA, Dr6)    == 0x168,                  "VMCB guest DR6");
static_assert(offsetof(VMCB_SAVE_AREA, Rflags) == 0x170,                  "VMCB guest RFLAGS");
static_assert(offsetof(VMCB_SAVE_AREA, Rip)    == 0x178,                  "VMCB guest RIP");
static_assert(offsetof(VMCB_SAVE_AREA, Rsp)    == 0x1D8,                  "VMCB guest RSP");
static_assert(offsetof(VMCB_SAVE_AREA, Rax)    == 0x1F8,                  "VMCB guest RAX");
static_assert(offsetof(VMCB_SAVE_AREA, Cr2)    == 0x240,                  "VMCB guest CR2");
static_assert(offsetof(VMCB_SAVE_AREA, GPat)   == 0x258,                  "VMCB guest PAT");
static_assert(sizeof(VMCB_SAVE_AREA) == 0x400,                            "VMCB save area size");
static_assert(sizeof(VMCB) == 0x800,                                      "VMCB total size");

// ============================================================================
//  Processor feature audit.
// ============================================================================

// ----------------------------------------------------------------------------
//  SvmAuditHardwareSupport — hard capability gate, run once before any core
//  is touched. Every check here maps to a VMRUN-time fatal condition, so the
//  audit fails the driver before guest state ever exists.
// ----------------------------------------------------------------------------
static NTSTATUS SvmAuditHardwareSupport(VOID)
{
    int regs[4] = {};

    // Extended CPUID range must reach the SVM leaves.
    __cpuid(regs, 0x80000000);
    if ((UINT32)regs[0] < 0x8000000A)
        return STATUS_NOT_SUPPORTED;

    // Fn8000_0001 ECX bit 2 = SVM available in general.
    __cpuid(regs, 0x80000001);
    if (!(regs[2] & (1 << 2)))
        return STATUS_NOT_SUPPORTED;

    __cpuid(regs, 0x8000000A);

    // EDX bit 0 = SVM enabled on this processor.
    if (!(regs[3] & (1 << 0)))
        return STATUS_NOT_SUPPORTED;

    // EDX bit 3 = Next RIP Save. The #VMEXIT NextRip field is required for
    // clean instruction re-execution during single-stepping and for the
    // teardown resume-RIP computation.
    if (!(regs[3] & (1 << 3)))
        return STATUS_NOT_SUPPORTED;

    // EBX = NumASID: the smallest exclusive ASID number NOT supported, i.e.
    // ASIDs 1..EBX-1 are taggable in the TLB. The guest isolation ASID must
    // fit below it; a value of 0 indicates no ASID facility, in which case
    // the fixed TLBCTL flush order provides correctness without ASIDs.
    UINT32 nasids = (UINT32)regs[1] & 0xFFFF;
    if (nasids != 0 && (UINT32)SVM_GUEST_ASID >= nasids)
        return STATUS_NOT_SUPPORTED;

    // MSR_VM_CR.SVMDIS (bit 4): firmware-level SVM lock. When set, VMRUN
    // raises #GP unconditionally and no software path can clear it.
    UINT64 vmCr = __readmsr(MSR_AMD_VM_CR);
    if (vmCr & SVM_VM_CR_SVMDIS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[HV] SVM disabled by BIOS (MSR_VM_CR.SVMDIS=1) — aborting\n");
        return STATUS_NOT_SUPPORTED;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
//  Segment descriptor decoding.
// ============================================================================

// ----------------------------------------------------------------------------
//  Descriptor byte 5 is the access byte (Type[3:0] S[4] DPL[6:5] P[7]) and
//  byte 6 the flags byte (AVL[4] L[5] D/B[6] G[7] + Limit19:16 in [3:0]).
//  The VMCB Attrib halfword mirrors that split: Type[3:0] S[4] DPL[6:5]
//  P[7] AVL[8] L[9] DB[10] G[11] (APM Vol 2, App. B).
// ----------------------------------------------------------------------------
static UINT16 SvmEncodeAttrib(UINT8 Access, UINT8 FlagsByte)
{
    UINT16 attrib = 0;

    attrib |= (UINT16)((Access     >> 0) & 0x0F);           // Type
    attrib |= (UINT16)(((Access    >> 4) & 0x01) << 4);     // S
    attrib |= (UINT16)(((Access    >> 5) & 0x03) << 5);     // DPL
    attrib |= (UINT16)(((Access    >> 7) & 0x01) << 7);     // P
    attrib |= (UINT16)(((FlagsByte >> 4) & 0x01) << 8);     // AVL
    attrib |= (UINT16)(((FlagsByte >> 5) & 0x01) << 9);     // L
    attrib |= (UINT16)(((FlagsByte >> 6) & 0x01) << 10);    // D/B
    attrib |= (UINT16)(((FlagsByte >> 7) & 0x01) << 11);    // G

    return attrib;
}

// ----------------------------------------------------------------------------
//  SvmSetupSegment — compliant x64 GDT decode of one selector into a VMCB
//  segment save field.
//
//  Width discipline in long mode: code/data descriptors (access-byte S=1)
//  are 8 bytes and their canonical base is fully contained in bytes 2-4 + 7;
//  system descriptors (S=0, e.g. the 64-bit TSS backing TR, or an LDT) are
//  16 bytes and extend the base through bytes 8-11. The access byte at
//  offset +5 is probed first so the correct width is bounds-checked against
//  GDTR.Limit: a 16-byte read at the final GDT slot of an 8-byte-only table
//  can never run past the table edge, and a 16-byte system descriptor
//  sitting exactly at the edge is accepted rather than falsely dropped.
//
//  ExpectedS constrains the caller: 1 requires a code/data descriptor, 0
//  requires a system descriptor (LDT/TSS/etc.).
// ----------------------------------------------------------------------------
static BOOLEAN SvmSetupSegment(VMCB_SEG* Seg, UINT16 Selector, UINT8 ExpectedS)
{
    // Null selector: the VMCB save field carries the (zero) selector with
    // all attributes cleared, matching architectural load semantics.
    if ((Selector & ~3U) == 0) {
        Seg->Selector = Selector;
        Seg->Attrib   = 0;
        Seg->Limit    = 0;
        Seg->Base     = 0;
        return TRUE;
    }

    // LDT-qualified selector: no LDT in the Windows x64 kernel.
    if (Selector & 0x4)
        return FALSE;

    DESCRIPTOR_TABLE_REGISTER64 gdtr = {};
    __sgdt(&gdtr);

    UINT32 offset  = Selector & ~0x7U;
    UINT64 gdtSize = (UINT64)gdtr.Limit + 1ULL;

    // Access byte at descriptor offset +5 is required to determine width.
    if ((UINT64)offset + 6 > gdtSize)
        return FALSE;

    const UINT8* desc = (const UINT8*)(gdtr.Base + offset);
    UINT8  access   = desc[5];
    UINT8  sBit     = (UINT8)((access >> 4) & 0x01);
    UINT32 width    = sBit ? 8u : 16u;

    if (sBit != ExpectedS)
        return FALSE;

    if ((UINT64)offset + width > gdtSize)
        return FALSE;

    UINT16 limitLow  = *(const UINT16*)(desc + 0);
    UINT16 baseLow   = *(const UINT16*)(desc + 2);
    UINT8  baseMid   = desc[4];
    UINT8  flagsByte = desc[6];
    UINT8  baseHigh  = desc[7];

    UINT64 base = (UINT64)baseLow
                | ((UINT64)baseMid  << 16)
                | ((UINT64)baseHigh << 24);

    if (width == 16) {
        // 16-byte system descriptor: canonical base bits 63:32 live in the
        // second quadword (bytes 8-11).
        UINT32 baseUpper = *(const UINT32*)(desc + 8);
        base |= ((UINT64)baseUpper << 32);
    }

    UINT32 limit = (UINT32)limitLow | ((UINT32)(flagsByte & 0x0F) << 16);
    if (flagsByte & 0x80)                       // G — granularity
        limit = (limit << 12) | 0xFFF;

    Seg->Selector = Selector;
    Seg->Attrib   = SvmEncodeAttrib(access, flagsByte);
    Seg->Limit    = limit;
    Seg->Base     = base;

    return TRUE;
}

// ----------------------------------------------------------------------------
//  SvmSetupTableRegister — populate a table-register save field (GDTR/IDTR/
//  LDTR). Table registers carry base and limit only; the VMCB Attrib field
//  is reserved for them (an explicit unusable-LDT encoding is supplied by
//  the caller for LDTR so VMRUN consistency checks accept the save state).
// ----------------------------------------------------------------------------
static VOID SvmSetupTableRegister(
    VMCB_SEG* Seg, UINT16 Selector, UINT64 Base, UINT32 Limit, UINT16 Attrib)
{
    Seg->Selector = Selector;
    Seg->Attrib   = Attrib;
    Seg->Limit    = Limit;
    Seg->Base     = Base;
}

// ============================================================================
//  TLB_CONTROL maintenance.
// ============================================================================

// ----------------------------------------------------------------------------
//  SvmParkTlbFlushOrder — consume-side of the one-shot flush discipline.
//
//  TLB_CONTROL is an ORDER evaluated at VMRUN entry, not sticky hardware
//  state: after one VMRUN executed with order 01b the full purge happened
//  and the field has no further meaning. Every host-side exit callback that
//  touches the VMCB therefore parks the order back at 00b before the exit
//  dispatcher re-enters the guest, so standard VMRUN iterations never force
//  a comprehensive hardware TLB rebuild. NPT paths that mutate a nested PTE
//  re-arm the order explicitly for exactly one entry via SvmInvalidateTlbAll
//  after their mutation completes.
// ----------------------------------------------------------------------------
static VOID SvmParkTlbFlushOrder(PPCPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb)
        return;

    vmcb->Control.TlbCtl = SVM_TLBCTL_FLUSH_NOTHING;
}

// ----------------------------------------------------------------------------
//  SvmTlbFlushDpc — per-core body of the coordinated NPT flush. Runs on
//  every logical processor via KeGenericCallDpc. Arming TLB_CONTROL=01b on a
//  core that is currently executing guest code is architecturally safe: the
//  control area is plain memory while VMRUN is active, the order is read at
//  the next VMRUN entry, and that entry then performs the purge — killing
//  every stale nested translation on the core before guest execution
//  observes the mutated PTE.
// ----------------------------------------------------------------------------
static VOID SvmTlbFlushDpc(
    PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PCPU_CONTEXT cpu = GetCurrentCpu();
    if (cpu && cpu->Launched && cpu->VmcbVa) {
        PVMCB vmcb = (PVMCB)cpu->VmcbVa;
        vmcb->Control.TlbCtl = SVM_TLBCTL_FLUSH_ALL;
    }

    // KeGenericCallDpc blocks until every processor signals completion; the
    // signal must be unconditional or the initiator deadlocks.
    if (SystemArgument1)
        KeSignalCallDpcDone(SystemArgument1);
}

// ----------------------------------------------------------------------------
//  SvmInvalidateTlbAll — coordinated all-core NPT TLB invalidation.
//
//  Called after a nested PTE mutation (single-step relax/restore) so no core
//  keeps servicing guest translations through the stale entry. The DPC
//  barrier guarantees every core has re-armed its one-shot purge before this
//  routine returns; the calling core's next VMRUN therefore runs against a
//  fully consistent NPT view. Must be invoked at IRQL <= DISPATCH_LEVEL and
//  never while holding g_Npt.Lock — a core spinning on that lock cannot run
//  its DPC and the barrier would deadlock.
// ----------------------------------------------------------------------------
extern "C" VOID SvmInvalidateTlbAll(PPCPU_CONTEXT Cpu)
{
    UNREFERENCED_PARAMETER(Cpu);

    if (InterlockedCompareExchange(&g_ShuttingDown, 0, 0) != 0)
        return;

    KeGenericCallDpc(SvmTlbFlushDpc, NULL);
}

// ============================================================================
//  Per-core single-step NPT entry maintenance.
//
//  All temporary step state (SavedPteValue, SingleStepPageGpa) is isolated
//  inside the local core's PCPU_CONTEXT tracking block — never in global
//  storage — so concurrent single-stepping on different cores cannot cross-
//  contaminate PTE snapshots.
// ============================================================================

// ----------------------------------------------------------------------------
//  SvmLocateNptPte — 4-level NPT walk returning the address of the leaf PTE
//  quadword that translates Gpa (APM Vol 2, chapter 5). Table pages are
//  resolved through the dynamic pool resolver HvPtPoolVaFromPa, so no
//  parallel virtual mirror of the NPT is required. Large-page intermediates
//  (2MB/1GB leaves) are rejected: single-step granularity is one 4KB page
//  and amd_npt.cpp owns the split path that must run first.
// ----------------------------------------------------------------------------
static NTSTATUS SvmLocateNptPte(UINT64 Gpa, volatile UINT64** PteOut)
{
    if (!PteOut)
        return STATUS_INVALID_PARAMETER;

    *PteOut = NULL;

    UINT64 tablePa = NptGetPml4Phys();
    if (!tablePa)
        return STATUS_UNSUCCESSFUL;

    static const ULONG levelShift[3] = { 39, 30, 21 };

    // PML4 -> PDPT -> PD: descend through non-leaf entries.
    for (ULONG level = 0; level < 3; level++) {
        PVOID tableVa = HvPtPoolVaFromPa(tablePa);
        if (!tableVa)
            return STATUS_UNSUCCESSFUL;

        volatile UINT64* entry =
            (volatile UINT64*)tableVa + ((Gpa >> levelShift[level]) & 0x1FF);

        UINT64 value = *entry;
        if (!(value & NPT_PTE_PRESENT))
            return STATUS_NOT_FOUND;

        // PDPT bit 7 = 1GB leaf, PD bit 7 = 2MB leaf. PML4 bit 7 is
        // reserved and intentionally not checked.
        if (level >= 1 && (value & NPT_PTE_LARGE))
            return STATUS_NOT_SUPPORTED;

        tablePa = value & NPT_PTE_PFN_MASK;
    }

    PVOID ptVa = HvPtPoolVaFromPa(tablePa);
    if (!ptVa)
        return STATUS_UNSUCCESSFUL;

    *PteOut = (volatile UINT64*)ptVa + ((Gpa >> 12) & 0x1FF);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  SvmSaveEntry — snapshot the current leaf PTE of Gpa into the local core's
//  tracking block. Read-only: no TLB order is armed and no flush is needed.
//  The snapshot is the raw 64-bit entry, so a restriction that cleared the
//  present bit (entry value 0) round-trips losslessly through RestoreEntry.
// ----------------------------------------------------------------------------
static NTSTATUS SvmSaveEntry(PPCPU_CONTEXT Cpu, UINT64 Gpa)
{
    if (!Cpu || !Cpu->VmcbVa)
        return STATUS_INVALID_PARAMETER;

    UINT64 pageGpa = Gpa & ~0xFFFULL;

    volatile UINT64* slot = NULL;
    NTSTATUS status = SvmLocateNptPte(pageGpa, &slot);
    if (!NT_SUCCESS(status))
        return status;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Npt.Lock, &oldIrql);

    Cpu->SavedPteValue     = *slot;
    Cpu->SingleStepPageGpa = pageGpa;

    KeReleaseSpinLock(&g_Npt.Lock, oldIrql);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  SvmRelaxPermissions — grant at least Perms on the 4KB leaf translating
//  Gpa (OR-in semantics: present/read, write, and NX-removal for execute).
//  This is the re-entry half of NPT single-stepping: after the faulting
//  access trapped, the page is relaxed so the trapped guest instruction can
//  execute exactly once before #DB terminates the step.
//
//  The PTE edit runs under the short g_Npt.Lock spinlock; the coordinated
//  TLB invalidation is issued strictly AFTER the lock is released — a core
//  spinning on g_Npt.Lock cannot service its DPC, and calling the barrier
//  under the lock would deadlock the flush.
// ----------------------------------------------------------------------------
static NTSTATUS SvmRelaxPermissions(PPCPU_CONTEXT Cpu, UINT64 Gpa, UINT64 Perms)
{
    if (!Cpu || !Cpu->VmcbVa)
        return STATUS_INVALID_PARAMETER;

    SvmParkTlbFlushOrder(Cpu);

    UINT64 pageGpa = Gpa & ~0xFFFULL;

    volatile UINT64* slot = NULL;
    NTSTATUS status = SvmLocateNptPte(pageGpa, &slot);
    if (!NT_SUCCESS(status))
        return status;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Npt.Lock, &oldIrql);

    UINT64 raw = *slot;
    if (!(raw & NPT_PTE_PRESENT)) {
        KeReleaseSpinLock(&g_Npt.Lock, oldIrql);
        return STATUS_NOT_FOUND;
    }

    // Typed overlay through the dedicated NPT_PTE union (common.h); edits
    // stay mask-driven on the raw value so behaviour is independent of the
    // bitfield declaration order in the header.
    NPT_PTE pte;
    RtlCopyMemory(&pte, &raw, sizeof(NPT_PTE));

    if (Perms & NPT_PERM_READ)
        raw |= NPT_PTE_PRESENT;
    if (Perms & NPT_PERM_WRITE)
        raw |= NPT_PTE_WRITE;
    if (Perms & NPT_PERM_EXECUTE)
        raw &= ~NPT_PTE_NX;

    UNREFERENCED_PARAMETER(pte);

    *slot = raw;

    KeReleaseSpinLock(&g_Npt.Lock, oldIrql);

    // Re-arm the one-shot flush on every core so no stale nested translation
    // survives the permission change.
    SvmInvalidateTlbAll(Cpu);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  SvmRestoreEntry — reinstall the PTE snapshot taken by SvmSaveEntry for
//  the page recorded in the local core's tracking block, re-tightening the
//  permission state the single step temporarily relaxed. The tracking block
//  is cleared only after the restore is committed so a failed walk leaves
//  the snapshot intact for a retry.
// ----------------------------------------------------------------------------
static NTSTATUS SvmRestoreEntry(PPCPU_CONTEXT Cpu)
{
    if (!Cpu || !Cpu->VmcbVa)
        return STATUS_INVALID_PARAMETER;

    if (Cpu->SingleStepPageGpa == 0)
        return STATUS_UNSUCCESSFUL;     // nothing staged by SvmSaveEntry

    SvmParkTlbFlushOrder(Cpu);

    volatile UINT64* slot = NULL;
    NTSTATUS status = SvmLocateNptPte(Cpu->SingleStepPageGpa, &slot);
    if (!NT_SUCCESS(status))
        return status;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Npt.Lock, &oldIrql);

    *slot = Cpu->SavedPteValue;

    KeReleaseSpinLock(&g_Npt.Lock, oldIrql);

    Cpu->SavedPteValue     = 0;
    Cpu->SingleStepPageGpa = 0;

    // The re-tightened PTE is invisible until every core's stale translation
    // dies — re-arm the coordinated one-shot purge.
    SvmInvalidateTlbAll(Cpu);
    return STATUS_SUCCESS;
}

// ============================================================================
//  VMCB initialisation.
// ============================================================================
static NTSTATUS SvmInitializeVmcb(PPCPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb)
        return STATUS_UNSUCCESSFUL;

    RtlZeroMemory(vmcb, sizeof(VMCB));

    // ---- Control area: intercept vectors ----
    //  * CPUID (Misc1)      : guest CPUID must be answered by the VMM so the
    //                         SVM feature leaf can be shaped.
    //  * VMMCALL (Misc2)    : hypercall channel (teardown handshake).
    //  * VMRUN  (Misc2 b0)  : architecturally mandatory — a cleared VMRUN
    //                         intercept fails the VMRUN consistency check and
    //                         terminates with VMEXIT_INVALID (-1) before any
    //                         guest instruction executes.
    //  * #DB    (exc bit 1) : single-step / hardware-breakpoint delivery; kept
    //                         permanently armed so guest DR7 breakpoints never
    //                         silently vanish.
    //  Deliberately NOT armed:
    //  * #PF (exc bit 14)   : with nested paging active, guest page faults are
    //                         resolved entirely by the guest page tables under
    //                         NPT permissions; intercepting them would push
    //                         every guest memory operation through #VMEXIT.
    //  * CR0/CR3/CR4 writes : InterceptCrRead/InterceptCrWrite stay zeroed —
    //                         NPT decouples guest CR3 from host translation,
    //                         so CR interception adds exit pressure with no
    //                         protection benefit while NPT is active.
    vmcb->Control.InterceptCrRead     = 0;
    vmcb->Control.InterceptCrWrite    = 0;
    vmcb->Control.InterceptMisc1      |= SVM_INTERCEPT_CPUID;
    vmcb->Control.InterceptMisc2      |= SVM_INTERCEPT_VMMCALL
                                      |  SVM_INTERCEPT_VMRUN;
    vmcb->Control.InterceptExceptions |= SVM_INTERCEPT_DB;
    vmcb->Control.InterceptExceptions &= ~SVM_INTERCEPT_PF;

    // ---- Control area: NPT ----
    vmcb->Control.Asid      = SVM_GUEST_ASID;
    vmcb->Control.NestedCtl = SVM_NPT_ENABLE;
    vmcb->Control.NestedCr3 = NptGetPml4Phys();

    // ---- Control area: one-shot TLB purge ----
    // Order 01b makes the FIRST VMRUN on this VMCB flush the entire TLB (all
    // ASIDs, non-global), discarding stale guest-tagged translations left by
    // any prior SVM state on this core. The order is consumed by that single
    // entry; SvmParkTlbFlushOrder parks the field back at 00b from every
    // subsequent host-side callback so standard VMRUN iterations never force
    // a comprehensive hardware TLB rebuild.
    vmcb->Control.TlbCtl = SVM_TLBCTL_FLUSH_ALL;

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
    vmcb->Save.Dr7  = 0x400;    // bit 10 is architecturally fixed to 1
    vmcb->Save.Cpl  = 0;
    vmcb->Save.GPat = __readmsr(MSR_IA32_PAT);

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

    if (!SvmSetupSegment(&cs, __readcs(), 1)) return STATUS_UNSUCCESSFUL;
    if (!SvmSetupSegment(&ss, __readss(), 1)) return STATUS_UNSUCCESSFUL;
    if (!SvmSetupSegment(&ds, __readds(), 1)) return STATUS_UNSUCCESSFUL;
    if (!SvmSetupSegment(&es, __reades(), 1)) return STATUS_UNSUCCESSFUL;
    if (!SvmSetupSegment(&fs, __readfs(), 1)) return STATUS_UNSUCCESSFUL;
    if (!SvmSetupSegment(&gs, __readgs(), 1)) return STATUS_UNSUCCESSFUL;

    // TR is a 16-byte system descriptor (S=0) in the GDT; the 64-bit TSS
    // base lives in bytes 8-11 and the type must be 64-bit TSS (9 =
    // available, 11 = busy).
    UINT16 trSelector = VmxReadTr();
    if (!SvmSetupSegment(&tr, trSelector, 0))
        return STATUS_UNSUCCESSFUL;

    UINT8 trType = (UINT8)(tr.Attrib & 0x0F);
    if (trType != 0x9 && trType != 0xB)
        return STATUS_UNSUCCESSFUL;

    // In long mode FS/GS bases live in MSRs; the GDT image is stale.
    fs.Base = __readmsr(MSR_IA32_FS_BASE);
    gs.Base = __readmsr(MSR_IA32_GS_BASE);

    vmcb->Save.Cs = cs;
    vmcb->Save.Ss = ss;
    vmcb->Save.Ds = ds;
    vmcb->Save.Es = es;
    vmcb->Save.Fs = fs;
    vmcb->Save.Gs = gs;
    vmcb->Save.Tr = tr;

    // No LDT in the Windows x64 kernel: encode an unusable LDT descriptor
    // (type 2 = LDT, P=1) so VMRUN consistency checks accept the save state.
    SvmSetupTableRegister(&vmcb->Save.Ldtr, 0, 0, 0, 0x0082);

    // Table registers: base and limit only; the Attrib field is reserved as 0.
    SvmSetupTableRegister(&vmcb->Save.Gdtr, 0, gdtr.Base, gdtr.Limit, 0);
    SvmSetupTableRegister(&vmcb->Save.Idtr, 0, idtr.Base, idtr.Limit, 0);

    // ---- Save area: RFLAGS, RIP, RSP ----
    // RIP and RSP are overwritten by the launch sequence before VMRUN.
    vmcb->Save.Rflags = __readeflags();
    vmcb->Save.Rip    = 0;
    vmcb->Save.Rsp    = 0;

    return STATUS_SUCCESS;
}

// ============================================================================
//  Per-CPU bring-up.
// ============================================================================

// ----------------------------------------------------------------------------
//  SvmSetupCurrentCpu — runs pinned to one logical processor.
//
//  1. Allocate the HSAVE area: a physically contiguous, 4KB-aligned, cached
//     page. VMRUN microcodes the host FS/GS/TR/LDTR/GDTR/IDTR/EFER/RFLAGS/
//     RSP/RIP block save and restore through it; without a valid pointer in
//     MSR_VM_HSAVE_PA the VMRUN faults (#GP / machine check).
//  2. Program the VMCB.
//  3. Set EFER.SVME on this core (EFER is strictly per-logical-processor).
//  4. Register the HSAVE physical address in MSR_VM_HSAVE_PA (bits 63:12;
//     bits 11:0 must read zero, which the page-aligned contiguous allocator
//     guarantees).
//
//  Launched is deliberately NOT set here — a core is marked launched only
//  after its launch primitive has completed successfully.
// ----------------------------------------------------------------------------
static NTSTATUS SvmSetupCurrentCpu(PVOID /*Context*/)
{
    PCPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu || !cpu->VmcbVa)
        return STATUS_UNSUCCESSFUL;

    if (!cpu->HostSaveVa) {
        PHYSICAL_ADDRESS lowBoundary  = {};
        PHYSICAL_ADDRESS highBoundary = {};
        PHYSICAL_ADDRESS skipBytes    = {};
        highBoundary.QuadPart = MAXULONG64;

        PVOID save = MmAllocateContiguousMemorySpecifyCacheNode(
            PAGE_SIZE,
            lowBoundary,
            highBoundary,
            skipBytes,
            MmCached,
            MM_ANY_NODE_OK);

        if (!save)
            return STATUS_INSUFFICIENT_RESOURCES;

        RtlZeroMemory(save, PAGE_SIZE);
        cpu->HostSaveVa = save;
        cpu->HostSavePa =
            MmGetPhysicalAddress(save).QuadPart & ~0xFFFULL;
    }

    NTSTATUS status = SvmInitializeVmcb(cpu);
    if (!NT_SUCCESS(status))
        return status;

    UINT64 efer = __readmsr(MSR_IA32_EFER);
    __writemsr(MSR_IA32_EFER, efer | X86_EFER_SVME);

    __writemsr(MSR_AMD_VM_HSAVE_PA, cpu->HostSavePa);

    return STATUS_SUCCESS;
}

// ============================================================================
//  Launch: VMRUN.
// ============================================================================

// ----------------------------------------------------------------------------
//  SvmLaunchCurrentCpu — enter the guest through the assembler primitive.
//
//  SvmLaunch executes VMRUN and returns only when guest execution has been
//  left for good (final teardown path) — VMRUN itself never "returns" on
//  success, it switches CPU context. A non-zero return is the VMRUN error
//  code (VMEXIT_INVALID = -1 on a consistency-check failure); the core then
//  falls back cleanly: SVM is disabled, the HSAVE pointer is unregistered,
//  and the core stays unlaunched so teardown skips it and the rest of the
//  system keeps running without a dead root-mode VMMCALL path.
// ----------------------------------------------------------------------------
static NTSTATUS SvmLaunchCurrentCpu(VOID)
{
    PCPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu || !cpu->VmcbVa || !cpu->HostSaveVa)
        return STATUS_UNSUCCESSFUL;

    UINT8 err = SvmLaunch();
    if (err != 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[HV] VMRUN failed on CPU %u: err=%u (0xFF = VMEXIT_INVALID)\n",
            cpu->CpuIndex, err);

        UINT64 efer = __readmsr(MSR_IA32_EFER);
        __writemsr(MSR_IA32_EFER, efer & ~X86_EFER_SVME);
        __writemsr(MSR_AMD_VM_HSAVE_PA, 0);

        cpu->Launched = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    cpu->Launched = TRUE;
    return STATUS_SUCCESS;
}

// ============================================================================
//  Teardown.
// ============================================================================

// ----------------------------------------------------------------------------
//  SvmHandleTeardownVmcall — runs in host context after the guest's teardown
//  VMMCALL #VMEXIT. The VMCB save area already holds the guest's RAX, RSP,
//  RIP and RFLAGS (hardware stored them at exit) while the remaining GPRs
//  were spilled by the naked stub into its GuestRegs block.
//
//  Host-state overwrite vectors eliminated on this path:
//    * No VMSAVE: from host mode VMSAVE writes the live host FS/GS/TR/LDTR
//      (and STAR/LSTAR) values into the VMCB save area, destroying guest
//      state. VMSAVE stays an asm-layer primitive only.
//    * No CLGI: global interrupt masking belongs to the assembler layer.
//    * EFER.SVME is cleared first so no further VMRUN can execute and the
//      HSAVE pointer is unregistered.
//
//  The captured guest RIP/RSP/RAX are published into the GuestRegs block so
//  the stub can restore all guest GPRs and execute a native long-mode jump
//  back into guest execution outside SVM boundaries. The resume RIP prefers
//  NextRip: the teardown VMMCALL has architecturally committed, and re-
//  executing it natively (SVME now clear) would raise #UD. Save.Rip is kept
//  as the fallback when the NRIPS save is absent.
// ----------------------------------------------------------------------------
extern "C" NTSTATUS SvmHandleTeardownVmcall(UINT64* GuestRegs, PPCPU_CONTEXT Cpu)
{
    if (!Cpu)
        return STATUS_INVALID_PARAMETER;

    if (!GuestRegs) {
        Cpu->Launched = FALSE;
        return STATUS_INVALID_PARAMETER;
    }

    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb) {
        Cpu->Launched = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    // 1) Extract the active guest context into stack storage BEFORE any
    //    host-side MSR or VMCB mutation can touch the save area.
    const UINT64 guestRip    = vmcb->Save.Rip;
    const UINT64 guestRsp    = vmcb->Save.Rsp;
    const UINT64 guestRax    = vmcb->Save.Rax;
    const UINT64 resumeRip   = (vmcb->Control.NextRip != 0)
                             ? vmcb->Control.NextRip
                             : guestRip;

    // 2) De-register the core from the SVM execution plane.
    Cpu->Launched = FALSE;

    // 3) Disable global virtualization: clear EFER.SVME so VMRUN can no
    //    longer execute on this logical processor, then unmap the HSAVE
    //    area from the MSR (required to be re-registered before any future
    //    relaunch and harmless to clear once SVME is down).
    UINT64 efer = __readmsr(MSR_IA32_EFER);
    if (efer & X86_EFER_SVME)
        __writemsr(MSR_IA32_EFER, efer & ~X86_EFER_SVME);

    __writemsr(MSR_AMD_VM_HSAVE_PA, 0);

    // 4) Publish the captured guest context into the naked stub register
    //    block. The stub restores the full GPR set from GuestRegs (which
    //    already carries the stub-spilled guest RBX..R15 etc.) merged with
    //    these VMCB-sourced values, then performs the native long-mode jmp
    //    back into guest execution.
    GuestRegs[HV_GUEST_REG_RAX] = guestRax;
    GuestRegs[HV_GUEST_REG_RSP] = guestRsp;
    GuestRegs[HV_GUEST_REG_RIP] = resumeRip;

    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
//  SvmTeardownDpc — pinned teardown trampoline. Issues the teardown
//  hypercall from the target core; the #VMEXIT handler above performs the
//  SVM shutdown and the stub resumes this thread natively at the return
//  address of the VMMCALL.
// ----------------------------------------------------------------------------
static VOID SvmTeardownDpc(
    PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PCPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu || !cpu->Launched) return;

    __svm_vmmcall((unsigned long)(HV_HYPERCALL_TEARDOWN), 0, 0);
}

// ----------------------------------------------------------------------------
//  SvmTeardown — global shutdown. Order matters: cores are detached from SVM
//  first (no further VMRUN), then per-core allocations are released, then the
//  NPT pool. The page pool must outlive the NPT release.
// ----------------------------------------------------------------------------
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
            if (g_PerCpu[i].HostSaveVa) {
                MmFreeContiguousMemory(g_PerCpu[i].HostSaveVa);
                g_PerCpu[i].HostSaveVa = NULL;
                g_PerCpu[i].HostSavePa = 0;
            }
        }
        ExFreePoolWithTag(g_PerCpu, 'HvC0');
        g_PerCpu = NULL;
    }

    // NPT page-table release lives in amd_npt.cpp; the pool must outlive it.
    NptFreeAll();
    HvPtPoolDestroy();

    InterlockedExchange(&g_HypervisorActive, 0);
}

// ============================================================================
//  Initialization vector.
// ============================================================================

// ----------------------------------------------------------------------------
//  SvmInitialize — three ordered phases:
//    1. Capability audit (CPUID + MSR_VM_CR) before any state is created.
//    2. Per-CPU setup, each core pinned: HSAVE allocation, VMCB
//       programming, EFER.SVME, MSR_VM_HSAVE_PA.
//    3. Per-CPU launch through VMRUN.
//  NPT construction is delegated to amd_npt.cpp and must have completed
//  before any VMCB references n_cr3.
// ----------------------------------------------------------------------------
static NTSTATUS SvmInitialize(VOID)
{
    NTSTATUS status = SvmAuditHardwareSupport();
    if (!NT_SUCCESS(status))
        return status;

    status = HvPtPoolInit();
    if (!NT_SUCCESS(status) && status != STATUS_ALREADY_REGISTERED)
        return status;

    status = SvmBuildIdentityMap(g_IdentityRanges, g_IdentityRangeCount);
    if (!NT_SUCCESS(status))
        return status;

    if (!NptIsReady())
        return STATUS_UNSUCCESSFUL;

    ULONG count = g_CpuCount;

    // Phase 2: per-core setup. EFER.SVME and MSR_VM_HSAVE_PA are strictly
    // per-logical-processor, so every MSR write happens under group affinity.
    for (ULONG i = 0; i < count; i++) {
        PROCESSOR_NUMBER pn;
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) continue;

        GROUP_AFFINITY aff = {};
        aff.Group = pn.Group;
        aff.Mask  = 1ULL << pn.Number;
        GROUP_AFFINITY old = {};
        KeSetSystemGroupAffinityThread(&aff, &old);
        status = SvmSetupCurrentCpu(NULL);
        KeRevertToUserGroupAffinityThread(&old);
        if (!NT_SUCCESS(status)) return status;
    }

    // Phase 3: per-core launch.
    for (ULONG i = 0; i < count; i++) {
        PROCESSOR_NUMBER pn;
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) continue;

        GROUP_AFFINITY aff = {};
        aff.Group = pn.Group;
        aff.Mask  = 1ULL << pn.Number;
        GROUP_AFFINITY old = {};
        KeSetSystemGroupAffinityThread(&aff, &old);
        status = SvmLaunchCurrentCpu();
        KeRevertToUserGroupAffinityThread(&old);
        if (!NT_SUCCESS(status)) return status;
    }

    InterlockedExchange(&g_HypervisorActive, 1);
    return STATUS_SUCCESS;
}

// ============================================================================
//  Single-step control.
// ============================================================================

// ----------------------------------------------------------------------------
//  SvmArmSingleStep — arm RFLAGS.TF in the VMCB save area and record the
//  pending state atomically in the local core's context. The #DB intercept
//  is left permanently enabled: clearing it would stop guest DR7 hardware
//  breakpoints from exiting, silently vanishing them. The exit handler
//  discriminates the two sources: SingleStepPending marks the debug fault
//  raised by TF, anything else is a guest breakpoint (DR6/DR7 in the save
//  area) and is reinjected.
// ----------------------------------------------------------------------------
static VOID SvmArmSingleStep(PPCPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb) return;

    SvmParkTlbFlushOrder(Cpu);

    Cpu->SingleStepPending = TRUE;
    vmcb->Save.Rflags |= X86_RFLAGS_TF;
}

static VOID SvmDisarmSingleStep(PPCPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb) return;

    SvmParkTlbFlushOrder(Cpu);

    vmcb->Save.Rflags &= ~X86_RFLAGS_TF;
    Cpu->SingleStepPending = FALSE;
}

// ----------------------------------------------------------------------------
//  SvmInjectException — defensively hardened EVENTINJ programming (APM Vol 2,
//  App. B).
//    bits  7:0   V       exception vector
//    bits 10:8   Type    3 = hardware exception
//    bit  11     EV      error code present
//    bit  31     V^      event valid — consumed by the next VMRUN
//    bits 63:32  error code
//  The processor delivers the event at guest entry as if raised natively.
//
//  Hardening contract:
//    * The single EVENTINJ slot must be free: if EXITINTINFO still carries a
//      valid pending event (or EVENTINJ itself is armed), injection is
//      rejected with STATUS_UNSUCCESSFUL rather than silently overwriting a
//      queued event.
//    * Vectors that architecturally push an error code get the 32-bit code
//      packed into EVENTINJ bits 63:32 with EV set; the code is delivered
//      on the guest stack by the microcode event delivery.
//    * #PF additionally requires the architectural CR2 value: the faulting
//      guest physical address is written into Vmcb->Save.Cr2 before the
//      event is armed.
// ----------------------------------------------------------------------------
static NTSTATUS SvmInjectException(PPCPU_CONTEXT Cpu, UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa)
{
    if (!Cpu || !Cpu->VmcbVa)
        return STATUS_INVALID_PARAMETER;

    if (Vector > 31)
        return STATUS_INVALID_PARAMETER;

    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;

    // Reject injection while an event is still pending delivery: EXITINTINFO
    // valid bit set, or an already-armed EVENTINJ slot.
    if (vmcb->Control.ExitIntInfo & SVM_EXITINTINFO_VALID)
        return STATUS_UNSUCCESSFUL;

    if (vmcb->Control.EventInj & SVM_EVENTINJ_VALID)
        return STATUS_UNSUCCESSFUL;

    SvmParkTlbFlushOrder(Cpu);

    UINT64 eventInj = SVM_EVENTINJ_VALID                    // bit 31: valid
                    | SVM_EVENTINJ_TYPE_EXCEPTION           // type 3: hardware exception
                    | (UINT64)(Vector & 0xFF);              // bits 7:0: vector

    // Vectors that architecturally require an error code (#DF, #TS, #NP,
    // #SS, #GP, #PF, #AC, #CP, #VC, #SX): pack the 32-bit code into the
    // upper half of the 64-bit control field and mark EV.
    static const BOOLEAN needsErrorCode[32] = {
        FALSE, // 0  #DE
        FALSE, // 1  #DB
        FALSE, // 2  NMI
        FALSE, // 3  #BP
        FALSE, // 4  #OF
        FALSE, // 5  #BR
        FALSE, // 6  #UD
        FALSE, // 7  #NM
        TRUE,  // 8  #DF
        FALSE, // 9  reserved
        TRUE,  // 10 #TS
        TRUE,  // 11 #NP
        TRUE,  // 12 #SS
        TRUE,  // 13 #GP
        TRUE,  // 14 #PF
        FALSE, // 15 reserved
        FALSE, // 16 #MF
        TRUE,  // 17 #AC
        FALSE, // 18 #MC
        FALSE, // 19 #XF
        FALSE, // 20 reserved
        TRUE,  // 21 #CP
        FALSE, // 22 reserved
        FALSE, // 23 reserved
        FALSE, // 24 reserved
        FALSE, // 25 reserved
        FALSE, // 26 reserved
        FALSE, // 27 reserved
        FALSE, // 28 reserved
        TRUE,  // 29 #VC
        TRUE,  // 30 #SX
        FALSE, // 31 reserved
    };

    if (needsErrorCode[Vector]) {
        eventInj |= SVM_EVENTINJ_ERROR_CODE_VALID;
        eventInj |= ((UINT64)ErrorCode << SVM_EVENTINJ_ERROR_CODE_SHIFT);
    }

    // #PF delivers its fault address through CR2, not through the event
    // payload: stage the faulting guest physical address in the save area.
    if (Vector == 14)
        vmcb->Save.Cr2 = FaultingGpa;

    vmcb->Control.EventInj = eventInj;
    return STATUS_SUCCESS;
}
