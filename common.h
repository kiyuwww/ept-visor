#pragma once

// ============================================================================
//  common.h — single source of truth for the dual-vendor hypervisor.
//
//  Consumers: vmm.cpp, vmexit.cpp, intel_vmm.cpp, amd_svm.cpp, amd_npt.cpp,
//  ept_common.cpp. Every structural definition shared across those modules is
//  declared exactly once here:
//
//    * VMCB hardware layout matrix (AMD APM Vol 2, Appendix B) with
//      compile-time offset checkpoints. Offsets 0x000–0x3FF form the control
//      area, 0x400–0x7FF the save area; the VMCB page is 4KB and must be
//      physically 4KB-aligned because the processor indexes it physically.
//
//    * EPT (Intel, SDM Vol 3C 28.2) and NPT (AMD, APM Vol 2 5.3) descriptor
//      formats. These are deliberately distinct unions: Intel EPT encodes an
//      explicit 3-bit MemType, while AMD NPT carries the classic PWT/PCD/PAT
//      paging-attribute bits. Merging them into one type is how EPT MemType
//      values historically leaked into NPT leaves and forced host RAM
//      uncached (PCD=1/PWT=1).
//
//    * PCPU_CONTEXT — the per-logical-processor state block, 64-byte aligned
//      so one context never shares a cache line with its neighbours in the
//      VM-exit hot path.
//
//    * HV_OPERATIONS — the vendor dispatch table. Function pointers must only
//      ever be invoked through g_HvOps after g_HvOps->Vendor is bound.
//
//  Layout invariant rule for this header: any field a module reads or writes
//  must either be covered by a static_assert in this file or be reachable
//  only through typed struct members. Raw numeric offsets are allowed only
//  in the VMCB_OFF_* macros and the asm primitives layer.
// ============================================================================

#include <ntddk.h>
#include <stddef.h>
#include <intrin.h>
#include <stdint.h>

// ============================================================================
//  1. MSRs — Intel VT-x
// ============================================================================
#define MSR_IA32_FEATURE_CONTROL        0x0000003A
#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048B
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048C

// ============================================================================
//  2. MSRs — generic x64 / AMD SVM
// ============================================================================
#define MSR_IA32_EFER                   0xC0000080
#define MSR_IA32_STAR                   0xC0000081
#define MSR_IA32_LSTAR                  0xC0000082
#define MSR_IA32_CSTAR                  0xC0000083
#define MSR_IA32_FMASK                  0xC0000084
#define MSR_IA32_SFMASK                 0xC0000084
#define MSR_IA32_SYSENTER_CS            0x00000174
#define MSR_IA32_SYSENTER_ESP           0x00000175
#define MSR_IA32_SYSENTER_EIP           0x00000176
#define MSR_IA32_PAT                    0x00000277
#define MSR_IA32_FS_BASE                0xC0000100
#define MSR_IA32_GS_BASE                0xC0000101
#define MSR_IA32_KERNEL_GS_BASE         0xC0000102
#define MSR_AMD_VM_CR                   0xC0010114
#define MSR_AMD_VM_HSAVE_PA             0xC0010117

// ============================================================================
//  3. Control-register and EFER bits
// ============================================================================
#define X86_CR0_PE                      (1ULL <<  0)
#define X86_CR0_MP                      (1ULL <<  1)
#define X86_CR0_EM                      (1ULL <<  2)
#define X86_CR0_TS                      (1ULL <<  3)
#define X86_CR0_ET                      (1ULL <<  4)
#define X86_CR0_NE                      (1ULL <<  5)
#define X86_CR0_WP                      (1ULL << 16)
#define X86_CR0_AM                      (1ULL << 18)
#define X86_CR0_NW                      (1ULL << 29)
#define X86_CR0_CD                      (1ULL << 30)
#define X86_CR0_PG                      (1ULL << 31)
#define X86_CR4_DE                      (1ULL <<  3)
#define X86_CR4_PSE                     (1ULL <<  4)
#define X86_CR4_PAE                     (1ULL <<  5)
#define X86_CR4_MCE                     (1ULL <<  6)
#define X86_CR4_PGE                     (1ULL <<  7)
#define X86_CR4_PCE                     (1ULL <<  8)
#define X86_CR4_OSFXSR                  (1ULL <<  9)
#define X86_CR4_OSXMMEXCPT              (1ULL << 10)
#define X86_CR4_VMXE                    (1ULL << 13)
#define X86_CR4_SMXE                    (1ULL << 14)
#define X86_CR4_OSXSAVE                 (1ULL << 18)
#define X86_CR4_SMEP                    (1ULL << 20)
#define X86_CR4_SMAP                    (1ULL << 21)
#define X86_EFER_SCE                    (1ULL <<  0)
#define X86_EFER_LME                    (1ULL <<  8)
#define X86_EFER_LMA                    (1ULL << 10)
#define X86_EFER_NXE                    (1ULL << 11)
#define X86_EFER_SVME                   (1ULL << 12)
#define X86_RFLAGS_TF                   (1ULL <<  8)
#define X86_RFLAGS_IF                   (1ULL <<  9)

// IA32_FEATURE_CONTROL bits
#define FC_LOCK                         (1ULL <<  0)
#define FC_VMXON_SMX                    (1ULL <<  1)
#define FC_VMXON_OUTSIDE_SMX            (1ULL <<  2)

// ============================================================================
//  4. VMCS field encodings (Intel SDM Vol 3C App. B)
// ============================================================================
// 16-bit
#define VMCS_VPID                            0x0000
#define VMCS_GUEST_ES_SEL                    0x0800
#define VMCS_GUEST_CS_SEL                    0x0802
#define VMCS_GUEST_SS_SEL                    0x0804
#define VMCS_GUEST_DS_SEL                    0x0806
#define VMCS_GUEST_FS_SEL                    0x0808
#define VMCS_GUEST_GS_SEL                    0x080A
#define VMCS_GUEST_LDTR_SEL                  0x080C
#define VMCS_GUEST_TR_SEL                    0x080E
#define VMCS_HOST_ES_SEL                     0x0C00
#define VMCS_HOST_CS_SEL                     0x0C02
#define VMCS_HOST_SS_SEL                     0x0C04
#define VMCS_HOST_DS_SEL                     0x0C06
#define VMCS_HOST_FS_SEL                     0x0C08
#define VMCS_HOST_GS_SEL                     0x0C0A
#define VMCS_HOST_TR_SEL                     0x0C0C
// 16-bit natural-width (access rights)
#define VMCS_GUEST_ES_AR                     0x4814
#define VMCS_GUEST_CS_AR                     0x4816
#define VMCS_GUEST_SS_AR                     0x4818
#define VMCS_GUEST_DS_AR                     0x481A
#define VMCS_GUEST_FS_AR                     0x481C
#define VMCS_GUEST_GS_AR                     0x481E
#define VMCS_GUEST_LDTR_AR                   0x4820
#define VMCS_GUEST_TR_AR                     0x4822
// 64-bit
#define VMCS_IO_BITMAP_A                     0x2000
#define VMCS_IO_BITMAP_B                     0x2002
#define VMCS_MSR_BITMAP                      0x2004
#define VMCS_EXIT_MSR_STORE_ADDR             0x2006
#define VMCS_EXIT_MSR_LOAD_ADDR              0x2008
#define VMCS_ENTRY_MSR_LOAD_ADDR             0x200A
#define VMCS_EXECUTIVE_VMCS_PTR              0x200C
#define VMCS_TSC_OFFSET                      0x2010
#define VMCS_VIRTUAL_APIC_ADDR               0x2012
#define VMCS_APIC_ACCESS_ADDR                0x2014
#define VMCS_EPTP                            0x201A
#define VMCS_EOI_EXIT0                       0x201C
#define VMCS_EOI_EXIT1                       0x201E
#define VMCS_EOI_EXIT2                       0x2020
#define VMCS_EOI_EXIT3                       0x2022
#define VMCS_GUEST_PHYSICAL_ADDRESS          0x2400
#define VMCS_GUEST_LINEAR_ADDRESS            0x2402
#define VMCS_VMCS_LINK_POINTER               0x2800
#define VMCS_GUEST_IA32_DEBUGCTL             0x2802
#define VMCS_GUEST_IA32_PAT                  0x2804
#define VMCS_GUEST_IA32_EFER                 0x2806
// 32-bit
#define VMCS_PIN_BASED_CTLS                  0x4000
#define VMCS_PROC_BASED_CTLS                 0x4002
#define VMCS_EXCEPTION_BITMAP                0x4004
#define VMCS_PF_ERROR_CODE_MASK              0x4006
#define VMCS_PF_ERROR_CODE_MATCH             0x4008
#define VMCS_CR3_TARGET_COUNT                0x400A
#define VMCS_EXIT_CTLS                       0x400C
#define VMCS_EXIT_MSR_STORE_COUNT            0x400E
#define VMCS_EXIT_MSR_LOAD_COUNT             0x4010
#define VMCS_ENTRY_CTLS                      0x4012
#define VMCS_ENTRY_MSR_LOAD_COUNT            0x4014
#define VMCS_ENTRY_INTR_INFO                 0x4016
#define VMCS_ENTRY_EXCEPTION_ERR             0x4018
#define VMCS_ENTRY_INSTR_LEN                 0x401A
#define VMCS_PROC_BASED_CTLS2                0x401E
#define VMCS_VM_INSTRUCTION_ERROR            0x4400
#define VMCS_EXIT_REASON                     0x4402
#define VMCS_EXIT_INTR_INFO                  0x4404
#define VMCS_EXIT_INTR_ERR                   0x4406
#define VMCS_IDT_VECTORING_INFO              0x4408
#define VMCS_IDT_VECTORING_ERR               0x440A
// 32-bit VM-exit instruction length: bytes of the exiting instruction, used
// to advance guest RIP after emulation or to rewind it on event reinjection.
#define VMCS_EXIT_INSTRUCTION_LENGTH         0x0000440CULL
#define VMCS_EXIT_INSTR_LEN                  VMCS_EXIT_INSTRUCTION_LENGTH
#define VMCS_EXIT_INSTR_INFO                 0x440E
// Natural width
#define VMCS_CR0_GUEST_HOST_MASK             0x6000
#define VMCS_CR4_GUEST_HOST_MASK             0x6002
#define VMCS_CR0_READ_SHADOW                 0x6004
#define VMCS_CR4_READ_SHADOW                 0x6006
#define VMCS_EXIT_QUALIFICATION              0x6400
#define VMCS_GUEST_ES_BASE                   0x6404
#define VMCS_GUEST_CS_BASE                   0x6406
#define VMCS_GUEST_SS_BASE                   0x6408
#define VMCS_GUEST_DS_BASE                   0x640A
#define VMCS_GUEST_FS_BASE                   0x640C
#define VMCS_GUEST_GS_BASE                   0x640E
#define VMCS_GUEST_LDTR_BASE                 0x6810
#define VMCS_GUEST_TR_BASE                   0x6812
#define VMCS_GUEST_GDTR_BASE                 0x6814
#define VMCS_GUEST_IDTR_BASE                 0x6816
#define VMCS_GUEST_ES_LIMIT                  0x4800
#define VMCS_GUEST_CS_LIMIT                  0x4802
#define VMCS_GUEST_SS_LIMIT                  0x4804
#define VMCS_GUEST_DS_LIMIT                  0x4806
#define VMCS_GUEST_FS_LIMIT                  0x4808
#define VMCS_GUEST_GS_LIMIT                  0x480A
#define VMCS_GUEST_LDTR_LIMIT                0x480C
#define VMCS_GUEST_TR_LIMIT                  0x480E
#define VMCS_GUEST_GDTR_LIMIT                0x4810
#define VMCS_GUEST_IDTR_LIMIT                0x4812
#define VMCS_GUEST_DR7                       0x681A
#define VMCS_GUEST_RSP                       0x681C
#define VMCS_GUEST_RIP                       0x681E
#define VMCS_GUEST_RFLAGS                    0x6820
#define VMCS_GUEST_PENDING_DBG               0x6822
#define VMCS_GUEST_SYSENTER_ESP              0x6824
#define VMCS_GUEST_SYSENTER_EIP              0x6826
#define VMCS_HOST_CR0                        0x6C00
#define VMCS_HOST_CR3                        0x6C02
#define VMCS_HOST_CR4                        0x6C04
#define VMCS_HOST_FS_BASE                    0x6C06
#define VMCS_HOST_GS_BASE                    0x6C08
#define VMCS_HOST_TR_BASE                    0x6C0A
#define VMCS_HOST_GDTR_BASE                  0x6C0C
#define VMCS_HOST_IDTR_BASE                  0x6C0E
#define VMCS_HOST_SYSENTER_ESP               0x6C10
#define VMCS_HOST_SYSENTER_EIP               0x6C12
#define VMCS_HOST_RSP                        0x6C14
#define VMCS_HOST_RIP                        0x6C16

// ============================================================================
//  5. VMX execution controls (Intel SDM Vol 3C Tables 24-x / 25-7)
// ============================================================================
// Pin-based
#define PIN_BASED_EXT_INTR_EXITING       (1U << 0)
#define PIN_BASED_NMI_EXITING            (1U << 3)
#define PIN_BASED_VIRTUAL_NMIS           (1U << 5)
#define PIN_BASED_PREEMPT_TIMER          (1U << 6)
// Primary processor-based
#define CPU_BASED_HLT_EXITING            (1U <<  7)
#define CPU_BASED_INVLPG_EXITING         (1U <<  9)
#define CPU_BASED_MWAIT_EXITING          (1U << 10)
#define CPU_BASED_RDPMC_EXITING          (1U << 11)
#define CPU_BASED_RDTSC_EXITING          (1U << 12)
#define CPU_BASED_CR3_LOAD_EXITING       (1U << 15)
#define CPU_BASED_CR3_STORE_EXITING      (1U << 16)
#define CPU_BASED_MOV_DR_EXITING         (1U << 23)
#define CPU_BASED_UNCOND_IO_EXITING      (1U << 24)
#define CPU_BASED_USE_IO_BITMAPS         (1U << 25)
#define CPU_BASED_MONITOR_TRAP_FLAG      (1U << 27)
#define CPU_BASED_USE_MSR_BITMAPS        (1U << 28)
#define CPU_BASED_ACTIVATE_SECONDARY     (1U << 31)
// Secondary processor-based
#define CPU_BASED2_VIRTUALIZE_APIC       (1U <<  0)
#define CPU_BASED2_ENABLE_EPT            (1U <<  1)
#define CPU_BASED2_DESCRIPTOR_TABLE_EXIT (1U <<  2)
#define CPU_BASED2_ENABLE_RDTSCP         (1U <<  3)
#define CPU_BASED2_ENABLE_VPID           (1U <<  5)
#define CPU_BASED2_WBINVD_EXITING        (1U <<  6)
#define CPU_BASED2_UNRESTRICTED_GUEST    (1U <<  7)
#define CPU_BASED2_MODE_BASED_EPT_EXEC   (1U << 22)
// Exit controls
#define VM_EXIT_SAVE_DBG_CTLS            (1U <<  2)
#define VM_EXIT_HOST_ADDR_SPACE_SIZE     (1U <<  9)
#define VM_EXIT_ACK_INTR_ON_EXIT         (1U << 15)
#define VM_EXIT_SAVE_IA32_PAT            (1U << 18)
#define VM_EXIT_LOAD_IA32_PAT            (1U << 19)
#define VM_EXIT_SAVE_IA32_EFER           (1U << 20)
#define VM_EXIT_LOAD_IA32_EFER           (1U << 21)
// Entry controls
#define VM_ENTRY_IA32E_MODE              (1U <<  9)
#define VM_ENTRY_LOAD_IA32_PAT           (1U << 14)
#define VM_ENTRY_LOAD_IA32_EFER          (1U << 15)

// ============================================================================
//  6. VM-exit reasons (Intel)
// ============================================================================
#define EXIT_REASON_EXCEPTION_NMI        0
#define EXIT_REASON_EXTERNAL_INTR        1
#define EXIT_REASON_CPUID                10
#define EXIT_REASON_HLT                  12
#define EXIT_REASON_INVLPG               14
#define EXIT_REASON_RDPMC                15
#define EXIT_REASON_RDTSC                16
#define EXIT_REASON_VMCALL               18
#define EXIT_REASON_VMCLEAR              19
#define EXIT_REASON_VMLAUNCH             20
#define EXIT_REASON_VMPTRLD              21
#define EXIT_REASON_VMPTRST              22
#define EXIT_REASON_VMREAD               23
#define EXIT_REASON_VMWRITE              24
#define EXIT_REASON_VMXOFF               25
#define EXIT_REASON_VMXON                26
#define EXIT_REASON_CR_ACCESS            28
#define EXIT_REASON_DR_ACCESS            29
#define EXIT_REASON_IO_INSTRUCTION       30
#define EXIT_REASON_MSR_READ             31
#define EXIT_REASON_MSR_WRITE            32
#define EXIT_REASON_INVALID_GUEST_STATE  33
#define EXIT_REASON_MSR_LOADING          34
#define EXIT_REASON_MWAIT                36
#define EXIT_REASON_MONITOR_TRAP_FLAG    37
#define EXIT_REASON_MONITOR              39
#define EXIT_REASON_PAUSE                40
#define EXIT_REASON_EPT_VIOLATION        48
#define EXIT_REASON_EPT_MISCONFIG        49
#define EXIT_REASON_INVEPT               50
#define EXIT_REASON_RDTSCP               51
#define EXIT_REASON_PREEMPT_TIMER        52
#define EXIT_REASON_INVVPID              53
#define EXIT_REASON_WBINVD               54
#define EXIT_REASON_XSETBV               55

// ============================================================================
//  7. AMD SVM intercepts and exit codes
//
//  Bit layout of the 64-bit intercept field (control offset 0x00C, presented
//  as two dwords in the VMCB structure below):
//    dword @0x00C (bits 31:0)  : INTR .. SHUTDOWN
//    dword @0x010 (bits 63:32) : VMRUN .. XSETBV
//  The CR intercept masks are the two 16-bit halves at 0x000/0x002; DR at
//  0x004/0x006. Exception vector N is bit N of the dword at 0x008.
// ============================================================================
// CR read/write masks (each 16 bits, CR0–CR15)
#define SVM_INTERCEPT_CR0_READ           (1U <<  0)
#define SVM_INTERCEPT_CR2_READ           (1U <<  2)
#define SVM_INTERCEPT_CR3_READ           (1U <<  3)
#define SVM_INTERCEPT_CR4_READ           (1U <<  4)
#define SVM_INTERCEPT_CR8_READ           (1U <<  8)
#define SVM_INTERCEPT_CR0_WRITE          (1U << 16)
#define SVM_INTERCEPT_CR2_WRITE          (1U << 18)
#define SVM_INTERCEPT_CR3_WRITE          (1U << 19)
#define SVM_INTERCEPT_CR4_WRITE          (1U << 20)

// dword @0x00C — INTR..SHUTDOWN
#define SVM_INTERCEPT_INTR               (1U <<  0)
#define SVM_INTERCEPT_NMI                (1U <<  1)
#define SVM_INTERCEPT_SMI                (1U <<  2)
#define SVM_INTERCEPT_INIT               (1U <<  3)
#define SVM_INTERCEPT_VINTR              (1U <<  4)
#define SVM_INTERCEPT_CR0_SEL_WRITE      (1U <<  5)
#define SVM_INTERCEPT_IDTR_READ          (1U <<  6)
#define SVM_INTERCEPT_GDTR_READ          (1U <<  7)
#define SVM_INTERCEPT_LDTR_READ          (1U <<  8)
#define SVM_INTERCEPT_TR_READ            (1U <<  9)
#define SVM_INTERCEPT_IDTR_WRITE         (1U << 10)
#define SVM_INTERCEPT_GDTR_WRITE         (1U << 11)
#define SVM_INTERCEPT_LDTR_WRITE         (1U << 12)
#define SVM_INTERCEPT_TR_WRITE           (1U << 13)
#define SVM_INTERCEPT_RDTSC              (1U << 14)
#define SVM_INTERCEPT_RDPMC              (1U << 15)
#define SVM_INTERCEPT_PUSHF              (1U << 16)
#define SVM_INTERCEPT_POPF               (1U << 17)
#define SVM_INTERCEPT_CPUID              (1U << 18)
#define SVM_INTERCEPT_RSM                (1U << 19)
#define SVM_INTERCEPT_IRET               (1U << 20)
#define SVM_INTERCEPT_INTn               (1U << 21)
#define SVM_INTERCEPT_INVD               (1U << 22)
#define SVM_INTERCEPT_PAUSE              (1U << 23)
#define SVM_INTERCEPT_HLT                (1U << 24)
#define SVM_INTERCEPT_INVLPG             (1U << 25)
#define SVM_INTERCEPT_INVLPGA            (1U << 26)
#define SVM_INTERCEPT_IOIO_PROT          (1U << 27)
#define SVM_INTERCEPT_MSR_PROT           (1U << 28)
#define SVM_INTERCEPT_TASK_SWITCH        (1U << 29)
#define SVM_INTERCEPT_FERR_FREEZE        (1U << 30)
#define SVM_INTERCEPT_SHUTDOWN           (1U << 31)

// dword @0x010 — VMRUN..XSETBV. VMRUN must be set for VMRUN to be accepted
// at all; a clear bit terminates with VMEXIT_INVALID (-1) per the APM Vol 2
// consistency checks.
#define SVM_INTERCEPT_VMRUN              (1U <<  0)
#define SVM_INTERCEPT_VMMCALL            (1U <<  1)
#define SVM_INTERCEPT_VMLOAD             (1U <<  2)
#define SVM_INTERCEPT_VMSAVE             (1U <<  3)
#define SVM_INTERCEPT_STGI               (1U <<  4)
#define SVM_INTERCEPT_CLGI               (1U <<  5)
#define SVM_INTERCEPT_SKINIT             (1U <<  6)
#define SVM_INTERCEPT_RDTSCP             (1U <<  7)
#define SVM_INTERCEPT_ICEBP              (1U <<  8)
#define SVM_INTERCEPT_WBINVD             (1U <<  9)
#define SVM_INTERCEPT_MONITOR            (1U << 10)
#define SVM_INTERCEPT_MWAIT_UNCOND       (1U << 11)
#define SVM_INTERCEPT_MWAIT_ARMED        (1U << 12)
#define SVM_INTERCEPT_XSETBV             (1U << 13)

// Exception-intercept bitmap (@0x008): bit N traps exception vector N.
#define SVM_INTERCEPT_DB                 (1U << 1)   // vector 1 — #DB
#define SVM_INTERCEPT_PF                 (1U << 14)  // vector 14 — #PF

// TLB_CONTROL byte encodings (control offset 0x05C)
#define SVM_TLBCTL_DO_NOTHING            0x00
#define SVM_TLBCTL_FLUSH_ALL             0x01   // entire TLB, all ASIDs, non-global

// NP_ENABLE bit (control offset 0x090)
#define SVM_NP_ENABLE                    (1ULL << 0)

// AMD exit codes
#define SVM_EXIT_READ_CR0                0x000
#define SVM_EXIT_WRITE_CR0               0x010
#define SVM_EXIT_READ_DR0                0x020
#define SVM_EXIT_WRITE_DR0               0x030
#define SVM_EXIT_EXCP_BASE               0x040
#define SVM_EXIT_INTR                    0x060
#define SVM_EXIT_NMI                     0x061
#define SVM_EXIT_SMI                     0x062
#define SVM_EXIT_INIT                    0x063
#define SVM_EXIT_VINTR                   0x064
#define SVM_EXIT_CPUID                   0x072
#define SVM_EXIT_HLT                     0x078
#define SVM_EXIT_INVLPG                  0x079
#define SVM_EXIT_INVLPGA                 0x07A
#define SVM_EXIT_IOIO                    0x07B
#define SVM_EXIT_MSR                     0x07C
#define SVM_EXIT_TASK_SWITCH             0x07D
#define SVM_EXIT_SHUTDOWN                0x07F
#define SVM_EXIT_VMRUN                   0x080
#define SVM_EXIT_VMMCALL                 0x081
#define SVM_EXIT_RDTSCP                  0x087
#define SVM_EXIT_NPF                     0x400
#define SVM_EXIT_AVIC_INCOMPLETE         0x401
#define SVM_EXIT_AVIC_NOACCEL            0x402

// ============================================================================
//  8. EPT / NPT permission and index macros
//
//  The permission bit positions are identical in both formats (R=0, W=1,
//  X-suppress=2 on Intel; R=0, W=1, NX=63 on AMD), which is why a single
//  perm mask travels through the vendor dispatch layer. The bit layouts of
//  the leaf descriptors themselves are NOT interchangeable — see section 9.
// ============================================================================
#define EPT_PERM_READ                    (1ULL << 0)
#define EPT_PERM_WRITE                   (1ULL << 1)
#define EPT_PERM_EXECUTE                 (1ULL << 2)
#define EPT_PERM_RWX                     (EPT_PERM_READ | EPT_PERM_WRITE | EPT_PERM_EXECUTE)

// EPT MemType encoding (field at bits 5:3 of the leaf). WB = 6.
#define EPT_MEMTYPE_UC                   (0ULL << 3)
#define EPT_MEMTYPE_WC                   (1ULL << 3)
#define EPT_MEMTYPE_WB                   (6ULL << 3)

#define NPT_PERM_READ                    (1ULL << 0)
#define NPT_PERM_WRITE                   (1ULL << 1)
#define NPT_PERM_EXECUTE                 (1ULL << 2)
#define NPT_PERM_RWX                     (NPT_PERM_READ | NPT_PERM_WRITE | NPT_PERM_EXECUTE)

// Four-level walk indices — shared geometry (9 bits per level, 512 entries).
#define EPT_PML4_INDEX(gpa)              (((gpa) >> 39) & 0x1FFULL)
#define EPT_PDPT_INDEX(gpa)              (((gpa) >> 30) & 0x1FFULL)
#define EPT_PD_INDEX(gpa)                (((gpa) >> 21) & 0x1FFULL)
#define EPT_PT_INDEX(gpa)                (((gpa) >> 12) & 0x1FFULL)

#define NPT_PML4_INDEX(gpa)              (((gpa) >> 39) & 0x1FFULL)
#define NPT_PDPT_INDEX(gpa)              (((gpa) >> 30) & 0x1FFULL)
#define NPT_PD_INDEX(gpa)                (((gpa) >> 21) & 0x1FFULL)
#define NPT_PT_INDEX(gpa)                (((gpa) >> 12) & 0x1FFULL)

// ============================================================================
//  9. Hardware structures
// ============================================================================
#pragma pack(push, 1)

// ----------------------------------------------------------------------------
//  EPT_PTE — Intel SDM Vol 3C, Table 28-1 (4KB leaf) and Table 28-3 (2MB).
//  Bits 5:3 carry the explicit EPT MemType; bit 63 is the suppress-VE bit.
//  This union is the ABI type of the vendor-neutral leaf handle in the
//  dispatch layer; it is a single UINT64 of storage in all vendor formats.
// ----------------------------------------------------------------------------
typedef union _EPT_ENTRY {
    UINT64 Value;
    struct {
        UINT64 Read        : 1;    // [0]
        UINT64 Write       : 1;    // [1]
        UINT64 Execute     : 1;    // [2]  execute-suppress on EPT
        UINT64 MemType     : 3;    // [5:3] EPT memory type (UC/WC/WB/...)
        UINT64 IgnorePat   : 1;    // [6]
        UINT64 LargePage   : 1;    // [7]  PS — 2MB leaf when set (PD level)
        UINT64 Accessed    : 1;    // [8]
        UINT64 Dirty       : 1;    // [9]
        UINT64 UserExec    : 1;    // [10] mode-based execute control
        UINT64 Reserved0   : 1;    // [11]
        UINT64 PhysAddr    : 40;   // [51:12] frame number (4KB granularity);
                                   //        for a 2MB leaf bits [51:21] hold
                                   //        the frame and [20:12] are reserved
        UINT64 Reserved1   : 11;   // [62:52]
        UINT64 SuppressVe  : 1;    // [63]
    } Fields;
} EPT_ENTRY, *PEPT_ENTRY;

// ----------------------------------------------------------------------------
//  NPT_PTE — AMD APM Vol 2, Figures 5-12..5-16.
//
//  Distinct from EPT_ENTRY on purpose. AMD NPT has no MemType field: the
//  paging-attribute bits PWT [3], PCD [4] and PAT [7]/[12-on-2MB-leaf] index
//  the host PAT/MTRR state exactly as ordinary paging does, so a Write-Back
//  policy is encoded as all three bits CLEAR (PAT entry 0), never as an
//  EPT-style numeric MemType. Bit 63 (NX) is the native execution gate and
//  is recognized in nested translations whenever NPT is enabled.
// ----------------------------------------------------------------------------
typedef union _NPT_PTE {
    UINT64 Value;
    struct {
        UINT64 Present  : 1;    // [0]      P
        UINT64 Write    : 1;    // [1]      R/W
        UINT64 User     : 1;    // [2]      U/S — must be 1 at every level so
                                        // CPL=3 never raises an unresolvable
                                        // nested page fault
        UINT64 Pwt      : 1;    // [3]      must stay 0 for WB
        UINT64 Pcd      : 1;    // [4]      must stay 0 for WB
        UINT64 Accessed : 1;    // [5]
        UINT64 Dirty    : 1;    // [6]
        UINT64 Pat      : 1;    // [7]      PAT index on a 4KB leaf; PS (page
                                        // size) on a PD descriptor
        UINT64 Avl1     : 4;    // [11:8]   ignored
        UINT64 PhysAddr : 40;   // [51:12]  frame number (4KB granularity);
                                        // for a 2MB leaf bits [51:13] hold the
                                        // frame and bit 12 is the PAT index
        UINT64 Avl2     : 11;   // [62:52]  ignored
        UINT64 Nx       : 1;    // [63]     no-execute
    } Fields;
} NPT_PTE, *PNPT_PTE;

// GDTR/IDTR register image as returned by SGDT/SIDT: 16-bit limit at +0,
// 64-bit base at +2 in hardware. Use the packed alias pattern when capturing
// with __sgdt/__sidt — this aligned struct is for arithmetic only.
typedef struct _DESCRIPTOR_TABLE_REGISTER64 {
    UINT16 Limit;
    UINT64 Base;
} DESCRIPTOR_TABLE_REGISTER64, *PDESCRIPTOR_TABLE_REGISTER64;

// GDT descriptor image. Bytes 0-7 are the classic 8-byte code/data
// descriptor; long-mode system descriptors (64-bit TSS, LDT) extend through
// bytes 8-11 with Base63:32 and must never be read for code/data entries.
// Byte 5 is the access byte (Type[3:0] S[4] DPL[6:5] P[7]); byte 6 the flags
// byte (Limit19:16 in [3:0], AVL[4] L[5] D/B[6] G[7]).
typedef struct _SEGMENT_DESCRIPTOR64 {
    UINT16 Limit15_0;
    UINT16 Base15_0;
    UINT8  Base23_16;
    UINT8  Type;                  // access byte (contains S/DPL/P)
    UINT8  Limit19_16_Flags;      // granularity/width flags + limit high
    UINT8  Base31_24;
    UINT32 Base63_32;             // system descriptors only
    UINT32 Reserved;              // must be zero
} SEGMENT_DESCRIPTOR64, *PSEGMENT_DESCRIPTOR64;

#pragma pack(pop)

// Segment access-rights byte format (VMCS AR field)
#define AR_PRESENT                      (1U << 7)
#define AR_DPL(x)                       (((x) & 3) << 5)
#define AR_S                            (1U << 4)
#define AR_TYPE(x)                      ((x) & 0xF)
#define AR_UNUSABLE                     (1U << 16)

C_ASSERT(sizeof(EPT_ENTRY) == sizeof(UINT64));
C_ASSERT(sizeof(NPT_PTE)   == sizeof(UINT64));

// ============================================================================
//  10. AMD VMCB layout matrix (AMD APM Vol 2, Appendix B)
//
//  The VMCB is a 4KB page: control area 0x000–0x3FF, save area 0x400–0x7FF.
//  The processor treats it as physical memory; it must be 4KB-aligned and is
//  examined on every VMRUN against the architectural consistency checks.
//
//  Offset checkpoints in this section are the canonical APM values. Two
//  frequently mistaken aliases are called out inline:
//    * TLB_CONTROL is the byte at 0x05C, immediately after the ASID dword at
//      0x058. The window 0x060–0x08F holds virtual-interrupt delivery and
//      exit state; 0x090 is NP_ENABLE — a flush order written at 0x090 would
//      alias NP_ENABLE and silently disable nested paging.
//    * n_cr3 is at 0x0B0. 0x0B8 is reserved padding; 0x0C0 is the clean-bit
//      mask and 0x0C8 NextRip.
//    * G_PAT is at save-relative 0x258 (absolute 0x658). CR2 occupies 0x640
//      and 0x648–0x657 is reserved.
// ============================================================================
#pragma pack(push, 1)

typedef struct _VMCB_SEG {
    UINT16 Selector;        // +0x00
    UINT16 Attrib;          // +0x02  Type[3:0] S[4] DPL[6:5] P[7] AVL[8]
                            //        L[9] DB[10] G[11]
    UINT32 Limit;           // +0x04
    UINT64 Base;            // +0x08
} VMCB_SEG;

typedef struct _VMCB_CONTROL_AREA {
    // 0x000 — CR0–CR15 read mask (16 bits), CR0–CR15 write mask (16 bits)
    UINT16 InterceptCrRead;
    UINT16 InterceptCrWrite;
    // 0x004 — DR0–DR15 read mask, DR0–DR15 write mask
    UINT16 InterceptDrRead;
    UINT16 InterceptDrWrite;

    // 0x008 — exception intercepts (bit N = vector N)
    UINT32 InterceptExceptions;

    // 0x00C — 64-bit intercept field, low dword (INTR..SHUTDOWN)
    UINT32 InterceptMisc1;
    // 0x010 — 64-bit intercept field, high dword (VMRUN..XSETBV)
    UINT32 InterceptMisc2;
    // 0x014 — reserved extension
    UINT32 InterceptMisc3;

    // 0x018–0x03F — reserved
    UINT8  Reserved0[0x28];

    // 0x040 — bitmap bases and TSC offsetting
    UINT64 IopmBasePa;              // I/O permission bitmap (bits 63:12)
    UINT64 MsrpmBasePa;             // MSR permission bitmap (bits 63:12)
    UINT64 TscOffset;               // guest TSC = host TSC + offset

    // 0x058 — TLB control
    UINT32 Asid;                    // address-space identifier (must be != 0)
    UINT8  TlbCtl;                  // TLB_CONTROL: flush order for next VMRUN
    UINT8  Reserved1[3];

    // 0x060 — virtual interrupt delivery
    UINT32 IntCtl;                  // V_TPR / V_IRQ / V_INTR_PRIO / V_IGN_TPR
    UINT32 IntVector;
    UINT32 IntState;                // interrupt shadow / exit-interrupt state
    UINT8  Reserved2[4];

    // 0x070 — exit state (written by the processor on #VMEXIT)
    UINT64 ExitCode;
    UINT64 ExitInfo1;
    UINT64 ExitInfo2;
    UINT32 ExitIntInfo;
    UINT32 ExitIntInfoErr;

    // 0x090 — nested paging enable (bit 0)
    UINT64 NestedCtl;               // NP_ENABLE

    // 0x098–0x0A7 — reserved
    UINT8  Reserved3[16];

    // 0x0A8 — EVENTINJ: V[7:0] Type[10:8] EV[11] valid[31] ErrorCode[63:32]
    UINT64 EventInj;

    // 0x0B0 — n_cr3: nested (host) page-table base, loaded by VMRUN
    UINT64 NestedCr3;

    // 0x0B8 — reserved
    UINT8  Reserved4[8];

    // 0x0C0 — clean-bit mask: a 1 marks a state group clean so VMRUN may
    // skip reloading it; 0 (all dirty) forces a full re-examination.
    UINT64 VmcbCleanBits;

    // 0x0C8 — NextRip: RIP + length of the exiting instruction (requires
    // CPUID Fn8000_000A EDX.NRIPS); used to advance or rewind guest RIP.
    UINT64 Nrip;

    // 0x0D0–0x3FF — reserved
    UINT8  Reserved5[0x330];
} VMCB_CONTROL_AREA;

typedef struct _VMCB_SAVE_AREA {
    // 0x400 (absolute) — segment save state, 16 bytes each
    VMCB_SEG Es;                    // 0x400
    VMCB_SEG Cs;                    // 0x410
    VMCB_SEG Ss;                    // 0x420
    VMCB_SEG Ds;                    // 0x430
    VMCB_SEG Fs;                    // 0x440
    VMCB_SEG Gs;                    // 0x450
    VMCB_SEG Gdtr;                  // 0x460
    VMCB_SEG Ldtr;                  // 0x470
    VMCB_SEG Idtr;                  // 0x480
    VMCB_SEG Tr;                    // 0x490 (16-byte long-mode TSS image)

    // 0x4A0–0x4CA — reserved
    UINT8  Reserved0[0x2B];

    UINT8  Cpl;                     // 0x4CB — guest current privilege level
    UINT8  Reserved1[4];

    UINT64 Efer;                    // 0x4D0 — guest EFER (SCE/LME/LMA/NXE/SVME)

    // 0x4D8–0x547 — reserved
    UINT8  Reserved2[0x70];

    UINT64 Cr4;                     // 0x548
    UINT64 Cr3;                     // 0x550
    UINT64 Cr0;                     // 0x558
    UINT64 Dr7;                     // 0x560
    UINT64 Dr6;                     // 0x568
    UINT64 Rflags;                  // 0x570
    UINT64 Rip;                     // 0x578

    // 0x580–0x5D7 — reserved
    UINT8  Reserved3[0x58];

    UINT64 Rsp;                     // 0x5D8
    UINT64 SCet;                    // 0x5E0
    UINT64 Ssp;                     // 0x5E8
    UINT64 IsstAddr;                // 0x5F0
    UINT64 Rax;                     // 0x5F8
    UINT64 Star;                    // 0x600
    UINT64 Lstar;                   // 0x608
    UINT64 Cstar;                   // 0x610
    UINT64 Sfmask;                  // 0x618
    UINT64 KernelGsBase;            // 0x620
    UINT64 SysenterCs;              // 0x628
    UINT64 SysenterEsp;             // 0x630
    UINT64 SysenterEip;             // 0x638
    UINT64 Cr2;                     // 0x640

    // 0x648–0x657 — reserved
    UINT8  Reserved4[0x10];

    UINT64 GPat;                    // 0x658 — guest PAT

    // 0x660–0x7FF — reserved (debug/LBR state, SEV-ES extension area)
    UINT8  Reserved5[0x1A0];
} VMCB_SAVE_AREA;

typedef struct _VMCB {
    VMCB_CONTROL_AREA Control;
    VMCB_SAVE_AREA    Save;
} VMCB, *PVMCB;

#pragma pack(pop)

// ----------------------------------------------------------------------------
//  Compile-time offset checkpoints. These are the layout invariant contract:
//  if the struct definitions above drift, the build fails here instead of at
//  VMRUN time as VMEXIT_INVALID / guest-state corruption.
// ----------------------------------------------------------------------------
static_assert(sizeof(VMCB_SEG) == 0x10,                                    "VMCB_SEG size");

static_assert(offsetof(VMCB, Control.InterceptCrRead)    == 0x000,         "VMCB offset error: InterceptCrRead");
static_assert(offsetof(VMCB, Control.InterceptCrWrite)   == 0x002,         "VMCB offset error: InterceptCrWrite");
static_assert(offsetof(VMCB, Control.InterceptDrRead)    == 0x004,         "VMCB offset error: InterceptDrRead");
static_assert(offsetof(VMCB, Control.InterceptDrWrite)   == 0x006,         "VMCB offset error: InterceptDrWrite");
static_assert(offsetof(VMCB, Control.InterceptExceptions)== 0x008,         "VMCB offset error: InterceptExceptions");
static_assert(offsetof(VMCB, Control.InterceptMisc1)     == 0x00C,         "VMCB offset error: InterceptMisc1");
static_assert(offsetof(VMCB, Control.InterceptMisc2)     == 0x010,         "VMCB offset error: InterceptMisc2");
static_assert(offsetof(VMCB, Control.IopmBasePa)         == 0x040,         "VMCB offset error: IopmBasePa");
static_assert(offsetof(VMCB, Control.MsrpmBasePa)        == 0x048,         "VMCB offset error: MsrpmBasePa");
static_assert(offsetof(VMCB, Control.TscOffset)          == 0x050,         "VMCB offset error: TscOffset");
static_assert(offsetof(VMCB, Control.Asid)               == 0x058,         "VMCB offset error: Asid");
static_assert(offsetof(VMCB, Control.TlbCtl)             == 0x05C,         "VMCB offset error: TlbCtl");
static_assert(offsetof(VMCB, Control.IntCtl)             == 0x060,         "VMCB offset error: IntCtl");
static_assert(offsetof(VMCB, Control.ExitCode)           == 0x070,         "VMCB offset error: ExitCode");
static_assert(offsetof(VMCB, Control.ExitInfo1)          == 0x078,         "VMCB offset error: ExitInfo1");
static_assert(offsetof(VMCB, Control.ExitInfo2)          == 0x080,         "VMCB offset error: ExitInfo2");
static_assert(offsetof(VMCB, Control.ExitIntInfo)        == 0x088,         "VMCB offset error: ExitIntInfo");
static_assert(offsetof(VMCB, Control.NestedCtl)          == 0x090,         "VMCB offset error: NestedCtl");
static_assert(offsetof(VMCB, Control.EventInj)           == 0x0A8,         "VMCB offset error: EventInj");
static_assert(offsetof(VMCB, Control.NestedCr3)          == 0x0B0,         "VMCB offset error: NestedCr3");
static_assert(offsetof(VMCB, Control.VmcbCleanBits)      == 0x0C0,         "VMCB offset error: VmcbCleanBits");
static_assert(offsetof(VMCB, Control.Nrip)               == 0x0C8,         "VMCB offset error: Nrip");
static_assert(sizeof(VMCB_CONTROL_AREA) == 0x400,                          "VMCB control area size");

static_assert(offsetof(VMCB, Save)             == 0x400,                   "VMCB offset error: SaveArea base");
static_assert(offsetof(VMCB, Save.Es)          == 0x400,                   "VMCB offset error: Save.Es");
static_assert(offsetof(VMCB, Save.Cs)          == 0x410,                   "VMCB offset error: Save.Cs");
static_assert(offsetof(VMCB, Save.Ss)          == 0x420,                   "VMCB offset error: Save.Ss");
static_assert(offsetof(VMCB, Save.Ds)          == 0x430,                   "VMCB offset error: Save.Ds");
static_assert(offsetof(VMCB, Save.Fs)          == 0x440,                   "VMCB offset error: Save.Fs");
static_assert(offsetof(VMCB, Save.Gs)          == 0x450,                   "VMCB offset error: Save.Gs");
static_assert(offsetof(VMCB, Save.Gdtr)        == 0x460,                   "VMCB offset error: Save.Gdtr");
static_assert(offsetof(VMCB, Save.Ldtr)        == 0x470,                   "VMCB offset error: Save.Ldtr");
static_assert(offsetof(VMCB, Save.Idtr)        == 0x480,                   "VMCB offset error: Save.Idtr");
static_assert(offsetof(VMCB, Save.Tr)          == 0x490,                   "VMCB offset error: Save.Tr");
static_assert(offsetof(VMCB, Save.Cpl)         == 0x4CB,                   "VMCB offset error: Save.Cpl");
static_assert(offsetof(VMCB, Save.Efer)        == 0x4D0,                   "VMCB offset error: Save.Efer");
static_assert(offsetof(VMCB, Save.Cr4)         == 0x548,                   "VMCB offset error: Save.Cr4");
static_assert(offsetof(VMCB, Save.Cr3)         == 0x550,                   "VMCB offset error: Save.Cr3");
static_assert(offsetof(VMCB, Save.Cr0)         == 0x558,                   "VMCB offset error: Save.Cr0");
static_assert(offsetof(VMCB, Save.Dr7)         == 0x560,                   "VMCB offset error: Save.Dr7");
static_assert(offsetof(VMCB, Save.Dr6)         == 0x568,                   "VMCB offset error: Save.Dr6");
static_assert(offsetof(VMCB, Save.Rflags)      == 0x570,                   "VMCB offset error: Save.Rflags");
static_assert(offsetof(VMCB, Save.Rip)         == 0x578,                   "VMCB offset error: Save.Rip");
static_assert(offsetof(VMCB, Save.Rsp)         == 0x5D8,                   "VMCB offset error: Save.Rsp");
static_assert(offsetof(VMCB, Save.SCet)        == 0x5E0,                   "VMCB offset error: Save.SCet");
static_assert(offsetof(VMCB, Save.Ssp)         == 0x5E8,                   "VMCB offset error: Save.Ssp");
static_assert(offsetof(VMCB, Save.IsstAddr)    == 0x5F0,                   "VMCB offset error: Save.IsstAddr");
static_assert(offsetof(VMCB, Save.Rax)         == 0x5F8,                   "VMCB offset error: Save.Rax");
static_assert(offsetof(VMCB, Save.Star)        == 0x600,                   "VMCB offset error: Save.Star");
static_assert(offsetof(VMCB, Save.Lstar)       == 0x608,                   "VMCB offset error: Save.Lstar");
static_assert(offsetof(VMCB, Save.Cstar)       == 0x610,                   "VMCB offset error: Save.Cstar");
static_assert(offsetof(VMCB, Save.Sfmask)      == 0x618,                   "VMCB offset error: Save.Sfmask");
static_assert(offsetof(VMCB, Save.KernelGsBase)== 0x620,                   "VMCB offset error: Save.KernelGsBase");
static_assert(offsetof(VMCB, Save.SysenterCs)  == 0x628,                   "VMCB offset error: Save.SysenterCs");
static_assert(offsetof(VMCB, Save.SysenterEsp) == 0x630,                   "VMCB offset error: Save.SysenterEsp");
static_assert(offsetof(VMCB, Save.SysenterEip) == 0x638,                   "VMCB offset error: Save.SysenterEip");
static_assert(offsetof(VMCB, Save.Cr2)         == 0x640,                   "VMCB offset error: Save.Cr2");
static_assert(offsetof(VMCB, Save.GPat)        == 0x658,                   "VMCB offset error: Save.GPat");
static_assert(sizeof(VMCB_SAVE_AREA) == 0x400,                             "VMCB save area size");
static_assert(sizeof(VMCB) == 0x800,                                       "VMCB total size");

// ----------------------------------------------------------------------------
//  Raw VMCB offsets for the assembler primitives layer (vmexit entry stubs).
//  These mirror the static_assert contract above and must never be edited
//  independently of it.
// ----------------------------------------------------------------------------
#define VMCB_OFF_INTERCEPT_CR           0x000
#define VMCB_OFF_INTERCEPT_DR           0x004
#define VMCB_OFF_INTERCEPT_EXCP         0x008
#define VMCB_OFF_INTERCEPT_MISC1        0x00C
#define VMCB_OFF_INTERCEPT_MISC2        0x010
#define VMCB_OFF_IOPM_BASE              0x040
#define VMCB_OFF_MSRPM_BASE             0x048
#define VMCB_OFF_ASID                   0x058
#define VMCB_OFF_TLB_CTL                0x05C
#define VMCB_OFF_EXIT_CODE              0x070
#define VMCB_OFF_EXIT_INFO1             0x078
#define VMCB_OFF_EXIT_INFO2             0x080
#define VMCB_OFF_EXIT_INT_INFO          0x088
#define VMCB_OFF_NP_ENABLE              0x090
#define VMCB_OFF_EVENTINJ               0x0A8
#define VMCB_OFF_N_CR3                  0x0B0
#define VMCB_OFF_VMCB_CLEAN             0x0C0
#define VMCB_OFF_NRIP                   0x0C8
#define VMCB_OFF_SAVE_AREA              0x400
#define VMCB_OFF_CPL                    0x4CB
#define VMCB_OFF_EFER                   0x4D0
#define VMCB_OFF_CR4                    0x548
#define VMCB_OFF_CR3                    0x550
#define VMCB_OFF_CR0                    0x558
#define VMCB_OFF_DR7                    0x560
#define VMCB_OFF_DR6                    0x568
#define VMCB_OFF_RFLAGS                 0x570
#define VMCB_OFF_RIP                    0x578
#define VMCB_OFF_RSP                    0x5D8
#define VMCB_OFF_RAX                    0x5F8
#define VMCB_OFF_CR2                    0x640
#define VMCB_OFF_G_PAT                  0x658

// ============================================================================
//  11. Dynamic identity-map range
// ============================================================================
typedef struct _HV_IDENTITY_RANGE {
    UINT64 Base;
    UINT64 Size;
} HV_IDENTITY_RANGE, *PHV_IDENTITY_RANGE;

// ============================================================================
//  12. Pre-allocated 4KB page-table sheet pool
//
//  All EPT/NPT split tables are carved from this pool so the VM-exit hot
//  path never calls a paged or IRQL-restricted allocator. Sheets are
//  physically contiguous 4KB pages, returned zeroed.
// ============================================================================
#define HV_PT_POOL_MAX_PAGES            4096
#define HV_PT_POOL_GUARD_QWORDS         8
#define HV_PT_POOL_GUARD_COOKIE         0x48565054504F4F4CULL

typedef struct __declspec(align(64)) _HV_PT_POOL {
    PVOID        Pages[HV_PT_POOL_MAX_PAGES];
    UINT64       Phys[HV_PT_POOL_MAX_PAGES];
    volatile LONG Top;
    volatile LONG Lock;
    volatile LONG FaultCount;
    UINT64       GuardCookie;
    UINT64       Guard[HV_PT_POOL_GUARD_QWORDS];
    BOOLEAN      Initialized;
} HV_PT_POOL, *PHV_PT_POOL;

static __forceinline BOOLEAN HvPtPoolIndexValid(LONG Index)
{
    return (Index >= 0) && (Index < HV_PT_POOL_MAX_PAGES);
}

static __forceinline BOOLEAN HvPtPoolValidate(PHV_PT_POOL Pool)
{
    return (Pool != NULL) &&
           (Pool->Initialized != FALSE) &&
           (Pool->GuardCookie == HV_PT_POOL_GUARD_COOKIE);
}

// ============================================================================
//  13. Protection dictionary (anti-cheat policy)
//
//  A single flat dictionary guarded by one atomic spinlock (g_RangesLock).
//  Lookup copies results out under the lock and never returns interior
//  pointers, so the exit handler can consume policy without holding the
//  lock across guest re-entry.
// ============================================================================
#define MAX_PROTECTED_RANGES            256

typedef struct _PROTECTED_RANGE {
    UINT64 Start;               // 4KB-aligned range base (GPA)
    UINT64 Size;                // byte length, multiple of 4KB
    UINT64 AllowedPerms;        // NPT_PERM_*/EPT_PERM_* bit mask
    ULONG  OwnerPid;            // owning process id
} PROTECTED_RANGE, *PPROTECTED_RANGE;

// ============================================================================
//  14. Per-CPU context (vendor-agnostic layout)
//
//  One instance per logical processor, 64-byte aligned so a context never
//  straddles a cache line boundary against its neighbour. Vendor-specific
//  allocations coexist in one block: only the pair used by the detected
//  vendor is valid; the other pair stays NULL/0.
//
//  Single-step invariant (lock-free, per-core only — the state is touched
//  exclusively on the CPU that owns the context, so no lock is required):
//    SingleStepPending  execution flags raised, waiting for the #DB/MTF exit
//    SingleStepPageGpa  GPA whose translation bit was flipped for the trap
//    SavedPteValue      raw leaf descriptor captured before the flip
//    SingleStepFlipped  TRUE while the leaf is in its trap state; the exit
//                       handler restores SavedPteValue before re-entry
// ============================================================================
#define VMX_HOST_STACK_SIZE             (64 * 1024)
#define HV_CPU_STATE_FENCE()            _ReadWriteBarrier()

typedef struct __declspec(align(64)) _PCPU_CONTEXT {
    // Primitives
    ULONG          CpuIndex;
    BOOLEAN        Launched;
    volatile LONG  SingleStepPending;

    // Intel allocations
    PVOID          VmxonVa;
    UINT64         VmxonPa;
    PVOID          VmcsVa;
    UINT64         VmcsPa;

    // AMD allocations
    PVOID          VmcbVa;
    UINT64         VmcbPa;
    PVOID          HostSaveVa;
    UINT64         HostSavePa;

    // Shared allocations
    PVOID          MsrBitmapVa;
    UINT64         MsrBitmapPa;
    UINT64         HostStackTop;
    PVOID          HostStack;

    // Per-core single-step tracking (MTF on Intel / RFLAGS.TF+#DB on AMD)
    UINT64         SingleStepPageGpa;
    UINT64         SavedPteValue;
    BOOLEAN        SingleStepFlipped;

    UINT64         Reserved[4];
} PCPU_CONTEXT, *PPCPU_CONTEXT;

// ============================================================================
//  15. Abstract runtime interface — vendor dispatch
// ============================================================================
typedef enum _HV_VENDOR {
    HvVendorUnknown = 0,
    HvVendorIntel   = 1,
    HvVendorAmd     = 2,
} HV_VENDOR;

// ----------------------------------------------------------------------------
//  HV_OPERATIONS — the contract every vendor backend must implement. All
//  exit-driven callbacks receive the PPCPU_CONTEXT of the core that took
//  the exit so the vendor module never needs to re-derive it. Perms are
//  ULONG per the unified NPT_PERM_*/EPT_PERM_* bit definitions.
// ----------------------------------------------------------------------------
typedef struct _HV_OPERATIONS {
    HV_VENDOR   Vendor;
    const char* Name;

    // Lifecycle
    NTSTATUS (*Initialize)(VOID);
    VOID     (*Teardown)(VOID);

    // Memory protection (exit path)
    NTSTATUS (*ProtectRange)(UINT64 Gpa, UINT64 Size, ULONG Perms);
    NTSTATUS (*SaveEntry)(PPCPU_CONTEXT Cpu, UINT64 Gpa);
    NTSTATUS (*RelaxPermissions)(PPCPU_CONTEXT Cpu, UINT64 Gpa, ULONG RelaxPerms);
    NTSTATUS (*RestoreEntry)(PPCPU_CONTEXT Cpu);

    // Single-step (MTF on Intel / RFLAGS.TF+#DB on AMD)
    VOID     (*ArmSingleStep)(PPCPU_CONTEXT Cpu);
    VOID     (*DisarmSingleStep)(PPCPU_CONTEXT Cpu);

    // Exception injection into the guest architectural state
    NTSTATUS (*InjectException)(PPCPU_CONTEXT Cpu, UINT32 Vector,
                                UINT32 ErrorCode, UINT64 FaultingGpa);

    // TLB maintenance for the core that owns Cpu
    VOID     (*InvalidateTlbAll)(PPCPU_CONTEXT Cpu);
} HV_OPERATIONS, *PHV_OPERATIONS;

// ============================================================================
//  16. Cross-module globals
// ============================================================================
extern HV_PT_POOL           g_PtPool;
extern PPCPU_CONTEXT        g_PerCpu;
extern ULONG                g_CpuCount;
extern volatile LONG        g_HypervisorActive;
extern volatile LONG        g_ShuttingDown;
extern volatile LONG        g_RangesLock;
extern HV_OPERATIONS*       g_HvOps;
extern HV_IDENTITY_RANGE*   g_IdentityRanges;
extern ULONG                g_IdentityRangeCount;
extern PROTECTED_RANGE      g_ProtectedRanges[MAX_PROTECTED_RANGES];

// ============================================================================
//  17. Inline helpers
// ============================================================================

// Any-IRQL atomic spinlock, safe inside VM-exit context. The CMPXCHG loop is
// paired with PAUSE to keep contended cores from speculating the lock bus.
static __forceinline void SpinAcquire(volatile LONG* Lock)
{
    while (_InterlockedCompareExchange(Lock, 1, 0) != 0)
        _mm_pause();
    _ReadWriteBarrier();
}

static __forceinline void SpinRelease(volatile LONG* Lock)
{
    _ReadWriteBarrier();
    _InterlockedExchange(Lock, 0);
}

// VMCS accessors evaluate the architectural status byte returned by the
// compiler intrinsics. A non-zero status is a programming or hardware
// interface failure and is asserted in debug builds.
#define HV_VMX_STATUS_ASSERT(Status) NT_ASSERT((Status) == 0)

static __forceinline unsigned char VmRead64Status(UINT64 Field, UINT64* Value)
{
    unsigned char status = __vmx_vmread(Field, Value);
    if (status != 0)
        HV_VMX_STATUS_ASSERT(status);
    return status;
}

static __forceinline unsigned char VmWrite64Status(UINT64 Field, UINT64 Value)
{
    unsigned char status = __vmx_vmwrite(Field, Value);
    if (status != 0)
        HV_VMX_STATUS_ASSERT(status);
    return status;
}

static __forceinline unsigned char VmRead32Status(UINT64 Field, UINT32* Value)
{
    UINT64 tmp = 0;
    unsigned char status = VmRead64Status(Field, &tmp);
    if (status == 0 && Value != NULL)
        *Value = (UINT32)tmp;
    return status;
}

static __forceinline unsigned char VmRead16Status(UINT64 Field, UINT16* Value)
{
    UINT64 tmp = 0;
    unsigned char status = VmRead64Status(Field, &tmp);
    if (status == 0 && Value != NULL)
        *Value = (UINT16)tmp;
    return status;
}

static __forceinline unsigned char VmWrite32Status(UINT64 Field, UINT32 Value)
{
    return VmWrite64Status(Field, (UINT64)Value);
}

static __forceinline unsigned char VmWrite16Status(UINT64 Field, UINT16 Value)
{
    return VmWrite64Status(Field, (UINT64)Value);
}

static __forceinline UINT64 VmRead64(UINT64 Field)
{
    UINT64 value = 0;
    unsigned char status = VmRead64Status(Field, &value);
    return (status == 0) ? value : 0;
}

static __forceinline UINT32 VmRead32(UINT64 Field)
{
    UINT32 value = 0;
    unsigned char status = VmRead32Status(Field, &value);
    return (status == 0) ? value : 0;
}

static __forceinline UINT16 VmRead16(UINT64 Field)
{
    UINT16 value = 0;
    unsigned char status = VmRead16Status(Field, &value);
    return (status == 0) ? value : 0;
}

static __forceinline void VmWrite64(UINT64 Field, UINT64 Value)
{
    (void)VmWrite64Status(Field, Value);
}

static __forceinline void VmWrite32(UINT64 Field, UINT32 Value)
{
    (void)VmWrite32Status(Field, Value);
}

static __forceinline void VmWrite16(UINT64 Field, UINT16 Value)
{
    (void)VmWrite16Status(Field, Value);
}

// VmxAdjustControls applies Intel SDM Vol 3C capability MSR semantics:
// bits[31:0] are the must-be-1 mask and bits[63:32] are the must-be-0 mask.
static __forceinline void VmxAdjustControls(UINT32* Ctl, UINT32 Msr)
{
    UINT64 caps = __readmsr(Msr);
    *Ctl |=  (UINT32)(caps & 0xFFFFFFFF);
    *Ctl &=  (UINT32)((caps >> 32) & 0xFFFFFFFF);
}

// Vendor detection. The MSVC x64 __cpuid array layout is:
//   r[0] = EAX, r[1] = EBX, r[2] = ECX, r[3] = EDX.
static __forceinline HV_VENDOR HvDetectVendor(VOID)
{
    int regs[4] = { 0 };
    __cpuid(regs, 0);

    UINT32 ebx = (UINT32)regs[1];
    UINT32 ecx = (UINT32)regs[2];
    UINT32 edx = (UINT32)regs[3];

    // "GenuineIntel": EBX="Genu", ECX="ntel", EDX="ineI"
    if (ebx == 0x756E6547 &&
        ecx == 0x6C65746E &&
        edx == 0x49656E69)
    {
        return HvVendorIntel;
    }

    // "AuthenticAMD": EBX="Auth", ECX="cAMD", EDX="enti"
    if (ebx == 0x68747541 &&
        ecx == 0x444D4163 &&
        edx == 0x69746E65)
    {
        return HvVendorAmd;
    }

    return HvVendorUnknown;
}

// ============================================================================
//  18. Cryptographic hypercall configuration
//
//  The teardown hypercall token is a magic constant in VMCALL exit-info1.
//  Guest-originated VMMCALL/VMCALL exits are untrusted: every handler must
//  validate the token and then VerifyHypercallAuth before acting.
// ============================================================================
#define HV_HYPERCALL_TEARDOWN           0x48566D78ULL   // 'HVmx'

// Constant-time, replay-protected hypercall authorization. Implemented by
// the security module; the nonce window is tracked per-caller so a captured
// (nonce, signature) pair cannot be replayed.
extern "C" BOOLEAN VerifyHypercallAuth(UINT64 Nonce, UINT64 Signature, UINT64* OutSecretKey);

// ============================================================================
//  19. Cross-module API declarations
// ============================================================================

// ept_common.cpp — page-table sheet pool
NTSTATUS HvPtPoolInit(VOID);
VOID     HvPtPoolDestroy(VOID);
PVOID    HvPtPoolAlloc(UINT64* OutPhys);
VOID     HvPtPoolFree(PVOID Page);

// ept_common.cpp — physical RAM layout collection
NTSTATUS HvCollectPhysicalRanges(PHV_IDENTITY_RANGE* OutRanges, PULONG OutCount);
VOID     HvFreePhysicalRanges(HV_IDENTITY_RANGE* Ranges);

// ept_common.cpp — guest #PF synthesis. The fault address must be the guest
// LINEAR address, never the GPA produced by the EPT/NPT walk; the vendor
// backend maps it into VMCS_GUEST_CR2 / the VMCB CR2 save field.
VOID     HvInjectGuestPageFault(UINT64 GuestLinearAddress, BOOLEAN Present,
                                BOOLEAN Write, BOOLEAN Execute, BOOLEAN UserMode);

// vmm.cpp — per-CPU lifecycle and context access
extern "C" PPCPU_CONTEXT GetCurrentCpuContext(VOID);

// Legacy accessor name kept as a thin inline forward for modules that have
// not been migrated to GetCurrentCpuContext yet.
static __forceinline PPCPU_CONTEXT GetCurrentCpu(VOID)
{
    return GetCurrentCpuContext();
}

// Security module — protection policy dictionary lookup. Called from the
// exit path under g_RangesLock; outputs are copied, never aliased.
extern "C" BOOLEAN PolicyLookup(UINT64 Gpa, ULONG* OwnerPid, ULONG* TargetPerms);

// vmexit.cpp — C entry points of the assembly VM-exit stubs
extern "C" void VmxVmExitHandlerC(UINT64* GuestRegs);
extern "C" void SvmVmExitHandlerC(UINT64* GuestRegs);

// Assembler primitives layer — the only code that executes VMRUN/VMRESUME,
// VMSAVE/VMLOAD, CLGI/STGI and owns the bare-metal host-state save/restore
// loops. C code must never invoke those instructions directly.
extern "C" {
    UINT16 VmxReadTr(VOID);
    UINT8  VmxLaunch(VOID);
    VOID   VmxVmExitEntry(VOID);
    UINT8  SvmLaunch(VOID);
    VOID   SvmVmExitEntry(VOID);
}
