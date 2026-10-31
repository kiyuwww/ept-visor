// ============================================================================
//  amd_svm.cpp — AMD-V (SVM) core execution module: VMCB lifecycle, per-CPU
//  bring-up, VMRUN launch, and teardown.
//
//  Architectural reference: AMD64 Architecture Programmer's Manual Volume 2,
//  Chapter 15 (SVM) and Appendix B (VMCB layout).
//
//  Nested Page Table operations live in amd_npt.cpp; this module binds the
//  vendor-agnostic operations template to those exports and drives the VMCB
//  lifecycle around them.
//
//  SVM lifecycle mechanics implemented here:
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
//    EXIT    #VMEXIT stores guest architectural state into the VMCB save
//            area; the host resumes at RIP+13 of the VMRUN with its own
//            state restored from the HSAVE area by microcode.
//
//    TEARDOWN  SVME is cleared so no further VMRUN can execute; all guest
//            context survives in the VMCB save area. VMSAVE/CLGI belong to
//            the assembler primitives layer only — executing VMSAVE from a
//            host-mode C routine would overwrite VMCB FS/GS/TR/LDTR state
//            with live host values and destroy guest state.
// ============================================================================
#include "common.h"
#include <stddef.h>
#include <intrin.h>

// ----------------------------------------------------------------------------
//  Forward declarations of the core lifecycle routines implemented here.
// ----------------------------------------------------------------------------
static NTSTATUS SvmInitialize(VOID);
static VOID     SvmTeardown(VOID);
static VOID     SvmArmSingleStep(PPER_CPU_CONTEXT Cpu);
static VOID     SvmDisarmSingleStep(PPER_CPU_CONTEXT Cpu);
static NTSTATUS SvmInjectException(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa);

// ----------------------------------------------------------------------------
//  NPT operations — implemented in amd_npt.cpp. The memory-protection half
//  of the operations template dispatches straight into that module; this TU
//  owns only the execution lifecycle.
// ----------------------------------------------------------------------------
extern "C" {
    NTSTATUS SvmBuildIdentityMap(const HV_IDENTITY_RANGE* Ranges, ULONG Count);
    NTSTATUS SvmProtectRange(UINT64 Gpa, UINT64 Size, UINT64 Perms);
    NTSTATUS SvmSaveAndGrant(UINT64 Gpa, UINT64 Perms, UINT64* OutOriginal);
    NTSTATUS SvmRestoreEntry(UINT64 Gpa, UINT64 OriginalValue);
    NTSTATUS SvmSplitAndGetPte(UINT64 Gpa, PEPT_ENTRY* OutPte);
    VOID     SvmInvalidateTlbAll(VOID);
    VOID     NptFreeAll(VOID);
    UINT64   NptGetPml4Phys(VOID);
    BOOLEAN  NptIsReady(VOID);
}

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
//  SVM constants.
// ----------------------------------------------------------------------------
#define SVM_GUEST_ASID          1U

// NP_ENABLE (VMCB control offset 0x090): bit 0 enables nested paging; n_cr3
// at offset 0x0B0 carries the NPT PML4 physical base.
#define SVM_NPT_ENABLE          1ULL

// Exception-intercept bitmap (VMCB offset 0x008): bit N traps vector N.
#define SVM_INTERCEPT_DB        (1U << 1)

// Misc intercept bit for VMRUN (VMCB control offset 0x010, bit 0 of the
// upper 32-bit half of the 64-bit intercept field, i.e. bit 32 architecturally).
// A cleared VMRUN intercept causes the processor's VMRUN consistency check
// to fail with VMEXIT_INVALID (-1) before guest entry ever happens.
#ifndef SVM_INTERCEPT_VMRUN
#define SVM_INTERCEPT_VMRUN     (1U << 0)
#endif

// TLB_CONTROL (VMCB offset 0x05C). Encoding 01b orders the processor to
// flush its entire TLB (all ASIDs, non-global) on the next VMRUN, purging
// stale guest TLB tags left by any prior SVM state on the core.
#define SVM_TLBCTL_FLUSH_ALL    0x01

// MSR_VM_CR (0xC0010114) bit 4: SVMDIS. When set, SVM is disabled by
// platform firmware and cannot be re-enabled by software.
#define SVM_VM_CR_SVMDIS        (1ULL << 4)

// Guest PAT is seeded from the host PAT so guest page-attribute encodings
// resolve to the same caching policies the NPT leaves assume.
#define MSR_IA32_PAT            0x00000277

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
    // clean instruction re-execution during single-stepping.
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
//  SvmSetupSegment — populate a VMCB segment save field from explicit parts.
// ----------------------------------------------------------------------------
static VOID SvmSetupSegment(
    VMCB_SEG* Seg, UINT16 Selector, UINT64 Base, UINT32 Limit, UINT16 Attrib)
{
    Seg->Selector = Selector;
    Seg->Attrib   = Attrib;
    Seg->Limit    = Limit;
    Seg->Base     = Base;
}

// ----------------------------------------------------------------------------
//  SvmReadGdtDescriptor — decode one GDT entry into a VMCB save field.
//
//  Width discipline in long mode: code/data descriptors (access-byte S=1)
//  are 8 bytes and their canonical base is fully contained in bytes 2-4 + 7;
//  system descriptors (S=0, e.g. the 64-bit TSS backing TR) are 16 bytes and
//  extend the base through bytes 8-11. The access byte at offset +5 is probed
//  first so the correct width is bounds-checked against GDTR.Limit — a 16-byte
//  read at the final GDT slot of an 8-byte-only table can never run past the
//  table edge, and a 16-byte system descriptor sitting exactly at the edge is
//  accepted rather than falsely dropped.
//
//  ExpectedS constrains the caller: 1 requires a code/data descriptor, 0
//  requires a system descriptor (LDT/TSS/etc.).
// ----------------------------------------------------------------------------
static BOOLEAN SvmReadGdtDescriptor(UINT16 Selector, VMCB_SEG* Seg, UINT8 ExpectedS)
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
//  SvmReadSegment — code/data descriptor (S=1, 8 bytes).
// ----------------------------------------------------------------------------
static BOOLEAN SvmReadSegment(UINT16 Selector, VMCB_SEG* Seg)
{
    return SvmReadGdtDescriptor(Selector, Seg, 1);
}

// ----------------------------------------------------------------------------
//  SvmReadTssBase — TR points to a 16-byte system descriptor; the 64-bit TSS
//  lives in long mode and the base is fully expressed through bytes 8-11.
//  Type must be a TSS (9 = 64-bit available, 11 = 64-bit busy).
// ----------------------------------------------------------------------------
static BOOLEAN SvmReadTssBase(UINT16 Selector, VMCB_SEG* Seg)
{
    if (!SvmReadGdtDescriptor(Selector, Seg, 0))
        return FALSE;

    UINT8 type = (UINT8)(Seg->Attrib & 0x0F);
    if (type != 0x9 && type != 0xB)
        return FALSE;

    return TRUE;
}

extern "C" UINT16 VmxReadTr(VOID);

// ============================================================================
//  VMCB initialisation.
// ============================================================================
static NTSTATUS SvmInitializeVmcb(PPER_CPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb)
        return STATUS_UNSUCCESSFUL;

    RtlZeroMemory(vmcb, sizeof(VMCB));

    // ---- Control area: intercepts ----
    // CPUID in Misc1, VMMCALL + VMRUN in Misc2. The VMRUN intercept must be
    // set (bit 0 of Misc2, i.e. bit 32 of the 64-bit intercept field) or the
    // processor's VMRUN consistency check aborts with VMEXIT_INVALID (-1)
    // before any guest instruction executes. #DB interception is mandatory
    // for single-step and is kept enabled permanently so guest hardware
    // breakpoints never silently vanish.
    vmcb->Control.InterceptMisc1      |= SVM_INTERCEPT_CPUID;
    vmcb->Control.InterceptMisc2      |= SVM_INTERCEPT_VMMCALL
                                      |  SVM_INTERCEPT_VMRUN;
    vmcb->Control.InterceptExceptions |= SVM_INTERCEPT_DB;

    // ---- Control area: NPT ----
    vmcb->Control.Asid      = SVM_GUEST_ASID;
    vmcb->Control.NestedCtl = SVM_NPT_ENABLE;
    vmcb->Control.NestedCr3 = NptGetPml4Phys();

    // ---- Control area: TLB flush on first VMRUN ----
    // Purges any stale ASID-tagged TLB entries left by prior SVM state on
    // this core, so the first guest entry observes only the current NPT.
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

    if (!SvmReadSegment(__readcs(), &cs)) return STATUS_UNSUCCESSFUL;
    if (!SvmReadSegment(__readss(), &ss)) return STATUS_UNSUCCESSFUL;
    if (!SvmReadSegment(__readds(), &ds)) return STATUS_UNSUCCESSFUL;
    if (!SvmReadSegment(__reades(), &es)) return STATUS_UNSUCCESSFUL;
    if (!SvmReadSegment(__readfs(), &fs)) return STATUS_UNSUCCESSFUL;
    if (!SvmReadSegment(__readgs(), &gs)) return STATUS_UNSUCCESSFUL;

    UINT16 trSelector = VmxReadTr();
    if (!SvmReadTssBase(trSelector, &tr)) return STATUS_UNSUCCESSFUL;

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
    SvmSetupSegment(&vmcb->Save.Ldtr, 0, 0, 0, 0x0082);

    // Table registers: base and limit only; the Attrib field is reserved as 0.
    SvmSetupSegment(&vmcb->Save.Gdtr, 0, gdtr.Base, gdtr.Limit, 0);
    SvmSetupSegment(&vmcb->Save.Idtr, 0, idtr.Base, idtr.Limit, 0);

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
//  4. Immediately register the HSAVE physical address in MSR_VM_HSAVE_PA
//     (bits 63:12; bits 11:0 must read zero, which the page-aligned
//     contiguous allocator guarantees).
//
//  Launched is deliberately NOT set here — a core is marked launched only
//  after its launch primitive has completed successfully.
// ----------------------------------------------------------------------------
static NTSTATUS SvmSetupCurrentCpu(PVOID /*Context*/)
{
    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu || !cpu->VmcbVa)
        return STATUS_UNSUCCESSFUL;

    if (!cpu->HostSaveVa) {
        PVOID save = MmAllocateContiguousMemorySpecifyCacheNode(
            PAGE_SIZE,
            (PHYSICAL_ADDRESS) { 0 },
            (PHYSICAL_ADDRESS) { MAXULONG64 },
            (PHYSICAL_ADDRESS) { 0 },
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
    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
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
#define HV_HYPERCALL_TEARDOWN  0x48566D78ULL   // 'HVmx'

// ----------------------------------------------------------------------------
//  SvmHandleTeardownVmcall — runs in host context after the guest's VMMCALL
//  #VMEXIT. The VMCB save area already holds the full guest register state
//  (VMEXIT stored it in hardware) and the assembler stub owns the bare-metal
//  host-state restoration loop. VMSAVE must never execute here: from host
//  mode it writes the live host FS/GS/TR/LDTR values into the VMCB save
//  area, destroying guest state. CLGI is likewise an asm-layer primitive.
//  Clearing EFER.SVME fences off any further VMRUN on this core.
// ----------------------------------------------------------------------------
NTSTATUS SvmHandleTeardownVmcall(PPER_CPU_CONTEXT Cpu)
{
    if (!Cpu)
        return STATUS_SUCCESS;

    UINT64 efer = __readmsr(MSR_IA32_EFER);
    if (efer & X86_EFER_SVME)
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
//  Single-step arming toggles RFLAGS.TF in the VMCB save area and records
//  the pending state atomically in the per-CPU context. The #DB intercept
//  is left permanently enabled: clearing it would stop guest DR7 hardware
//  breakpoints from exiting, silently vanishing them. The exit handler
//  discriminates the two sources: SingleStepPending marks the debug fault
//  raised by TF, anything else is a guest breakpoint (DR6/DR7 in the save
//  area) and is reinjected.
// ----------------------------------------------------------------------------
static VOID SvmArmSingleStep(PPER_CPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb) return;

    Cpu->SingleStepPending = TRUE;
    vmcb->Save.Rflags |= X86_RFLAGS_TF;
}

static VOID SvmDisarmSingleStep(PPER_CPU_CONTEXT Cpu)
{
    PVMCB vmcb = (PVMCB)Cpu->VmcbVa;
    if (!vmcb) return;

    vmcb->Save.Rflags &= ~X86_RFLAGS_TF;
    Cpu->SingleStepPending = FALSE;
}

// ----------------------------------------------------------------------------
//  SvmInjectException — EVENTINJ programming (APM Vol 2, App. B).
//    bits  7:0   V       exception vector
//    bits 10:8   Type    3 = hardware exception
//    bit  11     EV      error code present
//    bit  31     V^      event valid — consumed by the next VMRUN
//    bits 63:32  error code
//  The processor delivers the event at guest entry as if raised natively.
// ----------------------------------------------------------------------------
static NTSTATUS SvmInjectException(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa)
{
    UNREFERENCED_PARAMETER(FaultingGpa);

    PPER_CPU_CONTEXT cpu = GetCurrentCpu();
    if (!cpu || !cpu->VmcbVa)
        return STATUS_UNSUCCESSFUL;

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
    return STATUS_SUCCESS;
}
