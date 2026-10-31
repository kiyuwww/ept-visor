#pragma once

#include <ntddk.h>
#include <intrin.h>
#include <stdint.h>

// ============================================================================
//  1. MSRs - Intel VT-x
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
//  2. MSRs - generic x64 / AMD SVM
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
#define VMCS_EXIT_INSTR_LEN                  0x440C
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
//  7. AMD SVM intercepts, exit codes, VMCB layout constants
// ============================================================================
// Intercept bits in VMCB control area at offset 0x000 (CR reads/writes, misc)
#define SVM_INTERCEPT_CR0_READ           (1U <<  0)
#define SVM_INTERCEPT_CR1_READ           (1U <<  1)
#define SVM_INTERCEPT_CR2_READ           (1U <<  2)
#define SVM_INTERCEPT_CR3_READ           (1U <<  3)
#define SVM_INTERCEPT_CR4_READ           (1U <<  4)
#define SVM_INTERCEPT_CR5_READ           (1U <<  5)
#define SVM_INTERCEPT_CR6_READ           (1U <<  6)
#define SVM_INTERCEPT_CR7_READ           (1U <<  7)
#define SVM_INTERCEPT_CR8_READ           (1U <<  8)
#define SVM_INTERCEPT_CR9_READ           (1U <<  9)
#define SVM_INTERCEPT_CR10_READ          (1U << 10)
#define SVM_INTERCEPT_CR11_READ          (1U << 11)
#define SVM_INTERCEPT_CR12_READ          (1U << 12)
#define SVM_INTERCEPT_CR13_READ          (1U << 13)
#define SVM_INTERCEPT_CR14_READ          (1U << 14)
#define SVM_INTERCEPT_CR15_READ          (1U << 15)
#define SVM_INTERCEPT_CR0_WRITE          (1U << 16)
#define SVM_INTERCEPT_CR1_WRITE          (1U << 17)
#define SVM_INTERCEPT_CR2_WRITE          (1U << 18)
#define SVM_INTERCEPT_CR3_WRITE          (1U << 19)
#define SVM_INTERCEPT_CR4_WRITE          (1U << 20)
#define SVM_INTERCEPT_CR5_WRITE          (1U << 21)
#define SVM_INTERCEPT_CR6_WRITE          (1U << 22)
#define SVM_INTERCEPT_CR7_WRITE          (1U << 23)
#define SVM_INTERCEPT_CR8_WRITE          (1U << 24)
#define SVM_INTERCEPT_CR9_WRITE          (1U << 25)
#define SVM_INTERCEPT_CR10_WRITE         (1U << 26)
#define SVM_INTERCEPT_CR11_WRITE         (1U << 27)
#define SVM_INTERCEPT_CR12_WRITE         (1U << 28)
#define SVM_INTERCEPT_CR13_WRITE         (1U << 29)
#define SVM_INTERCEPT_CR14_WRITE         (1U << 30)
#define SVM_INTERCEPT_CR15_WRITE         (1U << 31)

// VMCB offset 0x004 - misc intercepts
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

// VMCB offset 0x008 - misc intercepts 2
#define SVM_INTERCEPT_VMRUN              (1ULL <<  0)
#define SVM_INTERCEPT_VMMCALL            (1ULL <<  1)
#define SVM_INTERCEPT_VMLOAD             (1ULL <<  2)
#define SVM_INTERCEPT_VMSAVE             (1ULL <<  3)
#define SVM_INTERCEPT_STGI               (1ULL <<  4)
#define SVM_INTERCEPT_CLGI               (1ULL <<  5)
#define SVM_INTERCEPT_SKINIT             (1ULL <<  6)
#define SVM_INTERCEPT_RDTSCP             (1ULL <<  7)
#define SVM_INTERCEPT_ICEBP              (1ULL <<  8)
#define SVM_INTERCEPT_WBINVD             (1ULL <<  9)
#define SVM_INTERCEPT_MONITOR            (1ULL << 10)
#define SVM_INTERCEPT_MWAIT_UNCOND       (1ULL << 11)
#define SVM_INTERCEPT_MWAIT_ARMED        (1ULL << 12)
#define SVM_INTERCEPT_XSETBV             (1ULL << 13)

// VMCB control offsets
#define VMCB_CTRL_INTERCEPT_VECTOR      0x000
#define VMCB_CTRL_INTERCEPT_MISC        0x004
#define VMCB_CTRL_INTERCEPT_MISC2       0x008
#define VMCB_CTRL_PAUSE_FILTER          0x00C
#define VMCB_CTRL_IOPM_BASE             0x010
#define VMCB_CTRL_MSRPM_BASE            0x018
#define VMCB_CTRL_TSC_OFFSET            0x020
#define VMCB_CTRL_ASID                  0x030
#define VMCB_CTRL_TLB_CTL               0x038
#define VMCB_CTRL_VTLB_CTL              0x040
#define VMCB_CTRL_NESTED_CTL            0x048
#define VMCB_CTRL_NESTED_CR3            0x050
#define VMCB_CTRL_INTR_SHADOW           0x058
#define VMCB_CTRL_EXIT_CODE             0x070
#define VMCB_CTRL_EXIT_INFO1            0x078
#define VMCB_CTRL_EXIT_INFO2            0x080
#define VMCB_CTRL_EXIT_INT_INFO         0x088
#define VMCB_CTRL_NP_ENABLE             0x090
#define VMCB_CTRL_EVENTINJ              0x0A8
#define VMCB_CTRL_NCR3                  0x0B0
#define VMCB_CTRL_LBR_VIRT              0x0B8
#define VMCB_CTRL_VMCB_CLEAN            0x0C0
#define VMCB_CTRL_NRIP                  0x0C8
#define VMCB_CTRL_NINST_RET             0x0D0

// VMCB save-state offsets (AMD APM Volume 2 Appendix B)
#define VMCB_SAVE_ES_SEL                0x400
#define VMCB_SAVE_CS_SEL                0x410
#define VMCB_SAVE_SS_SEL                0x420
#define VMCB_SAVE_DS_SEL                0x430
#define VMCB_SAVE_FS_SEL                0x440
#define VMCB_SAVE_GS_SEL                0x450
#define VMCB_SAVE_GDTR_SEL              0x460
#define VMCB_SAVE_LDTR_SEL              0x470
#define VMCB_SAVE_IDTR_SEL              0x480
#define VMCB_SAVE_TR_SEL                0x490
#define VMCB_SAVE_CPL                   (VMCB_SAVE_CS_SEL + 0xBB)
#define VMCB_SAVE_EFER                  0x4D0
#define VMCB_SAVE_CR4                   0x548
#define VMCB_SAVE_CR3                   0x550
#define VMCB_SAVE_CR0                   0x558
#define VMCB_SAVE_CR2                   0x560
#define VMCB_SAVE_DR6                   0x568
#define VMCB_SAVE_DR7                   0x570
#define VMCB_SAVE_RIP                   0x578
#define VMCB_SAVE_RSP                   0x5D0
#define VMCB_SAVE_RFLAGS                0x5D8
#define VMCB_SAVE_RAX                   0x5E0
#define VMCB_SAVE_STAR                  0x5E8
#define VMCB_SAVE_LSTAR                 0x5F0
#define VMCB_SAVE_CSTAR                 0x5F8
#define VMCB_SAVE_SFMASK                0x600
#define VMCB_SAVE_KERNEL_GS_BASE        0x608
#define VMCB_SAVE_SYSENTER_CS           0x610
#define VMCB_SAVE_SYSENTER_ESP          0x618
#define VMCB_SAVE_SYSENTER_EIP          0x620
#define VMCB_SAVE_G_PAT                 0x640

// AMD exit codes
#define SVM_EXIT_READ_CR0               0x000
#define SVM_EXIT_READ_CR2               0x002
#define SVM_EXIT_READ_CR3               0x003
#define SVM_EXIT_READ_CR4               0x004
#define SVM_EXIT_WRITE_CR0              0x010
#define SVM_EXIT_WRITE_CR2              0x012
#define SVM_EXIT_WRITE_CR3              0x013
#define SVM_EXIT_WRITE_CR4              0x014
#define SVM_EXIT_READ_DR0               0x020
#define SVM_EXIT_WRITE_DR0              0x030
#define SVM_EXIT_EXCP_BASE              0x040
#define SVM_EXIT_INTR                   0x060
#define SVM_EXIT_NMI                    0x061
#define SVM_EXIT_SMI                    0x062
#define SVM_EXIT_INIT                   0x063
#define SVM_EXIT_VINTR                  0x064
#define SVM_EXIT_CPUID                  0x072
#define SVM_EXIT_HLT                    0x078
#define SVM_EXIT_INVLPG                 0x079
#define SVM_EXIT_INVLPGA                0x07A
#define SVM_EXIT_IOIO                   0x07B
#define SVM_EXIT_MSR                    0x07C
#define SVM_EXIT_TASK_SWITCH            0x07D
#define SVM_EXIT_SHUTDOWN               0x07F
#define SVM_EXIT_VMRUN                  0x080
#define SVM_EXIT_VMMCALL                0x081
#define SVM_EXIT_VMLOAD                 0x082
#define SVM_EXIT_VMSAVE                 0x083
#define SVM_EXIT_STGI                   0x084
#define SVM_EXIT_CLGI                   0x085
#define SVM_EXIT_SKINIT                 0x086
#define SVM_EXIT_RDTSCP                 0x087
#define SVM_EXIT_ICEBP                  0x088
#define SVM_EXIT_NPF                    0x400
#define SVM_EXIT_AVIC_INCOMPLETE        0x401
#define SVM_EXIT_AVIC_NOACCEL           0x402

// ============================================================================
//  8. EPT / NPT permissions
// ============================================================================
#define EPT_PERM_READ                   (1ULL << 0)
#define EPT_PERM_WRITE                  (1ULL << 1)
#define EPT_PERM_EXECUTE                (1ULL << 2)
#define EPT_PERM_RWX                    (EPT_PERM_READ | EPT_PERM_WRITE | EPT_PERM_EXECUTE)

#define EPT_MEMTYPE_UC                  (0ULL << 3)
#define EPT_MEMTYPE_WC                  (1ULL << 3)
#define EPT_MEMTYPE_WB                  (6ULL << 3)

#define NPT_PERM_READ                   (1ULL << 0)
#define NPT_PERM_WRITE                  (1ULL << 1)
#define NPT_PERM_EXECUTE                (1ULL << 2)
#define NPT_PERM_RWX                    (NPT_PERM_READ | NPT_PERM_WRITE | NPT_PERM_EXECUTE)

#define EPT_PML4_INDEX(gpa)             (((gpa) >> 39) & 0x1FFULL)
#define EPT_PDPT_INDEX(gpa)             (((gpa) >> 30) & 0x1FFULL)
#define EPT_PD_INDEX(gpa)               (((gpa) >> 21) & 0x1FFULL)
#define EPT_PT_INDEX(gpa)               (((gpa) >> 12) & 0x1FFULL)

// ============================================================================
//  9. Hardware structures
// ============================================================================
#pragma pack(push, 1)
typedef union _EPT_ENTRY {
    UINT64 Value;
    struct {
        UINT64 Read        : 1;
        UINT64 Write       : 1;
        UINT64 Execute     : 1;
        UINT64 MemType     : 3;
        UINT64 IgnorePat   : 1;
        UINT64 LargePage   : 1;
        UINT64 Accessed    : 1;
        UINT64 Dirty       : 1;
        UINT64 UserExec    : 1;
        UINT64 Reserved0   : 1;
        UINT64 PhysAddr    : 40;
        UINT64 Reserved1   : 11;
        UINT64 SuppressVe  : 1;
    } Fields;
} EPT_ENTRY, *PEPT_ENTRY;

typedef struct _DESCRIPTOR_TABLE_REGISTER64 {
    UINT16 Limit;
    UINT64 Base;
} DESCRIPTOR_TABLE_REGISTER64, *PDESCRIPTOR_TABLE_REGISTER64;

typedef struct _SEGMENT_DESCRIPTOR64 {
    UINT16 Limit15_0;
    UINT16 Base15_0;
    UINT8  Base23_16;
    UINT8  Type;
    UINT8  Limit19_16_Flags;
    UINT8  Base31_24;
    UINT32 Base63_32;
    UINT32 Reserved;
} SEGMENT_DESCRIPTOR64, *PSEGMENT_DESCRIPTOR64;
#pragma pack(pop)

// Segment access-rights byte format (VMCS AR field)
#define AR_PRESENT                      (1U << 7)
#define AR_DPL(x)                       (((x) & 3) << 5)
#define AR_S                            (1U << 4)
#define AR_TYPE(x)                      ((x) & 0xF)
#define AR_UNUSABLE                     (1U << 16)

// ============================================================================
//  10. Dynamic identity-map range
// ============================================================================
typedef struct _HV_IDENTITY_RANGE {
    UINT64 Base;
    UINT64 Size;
} HV_IDENTITY_RANGE, *PHV_IDENTITY_RANGE;

// ============================================================================
//  11. Pre-allocated 4 KB page table pool
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
//  12. Protected range (anti-cheat policy)
// ============================================================================
#define MAX_PROTECTED_RANGES            32

typedef struct _PROTECTED_RANGE {
    UINT64 Start;
    UINT64 Size;
    UINT64 AllowedPerms;
    ULONG  OwnerPid;
} PROTECTED_RANGE, *PPROTECTED_RANGE;

// ============================================================================
//  13. Per-CPU context (vendor-agnostic layout)
// ============================================================================
#define VMX_HOST_STACK_SIZE             (64 * 1024)
#define HV_CPU_STATE_FENCE()            _ReadWriteBarrier()

typedef struct __declspec(align(64)) _PER_CPU_CONTEXT {
    ULONG   CpuIndex;

    // Intel
    PVOID   VmxonVa;
    UINT64  VmxonPa;
    PVOID   VmcsVa;
    UINT64  VmcsPa;
    PVOID   MsrBitmapVa;
    UINT64  MsrBitmapPa;

    // AMD
    PVOID   VmcbVa;
    UINT64  VmcbPa;
    PVOID   HostSaveVa;
    UINT64  HostSavePa;

    // Common
    PVOID   HostStack;
    UINT64  HostStackTop;
    volatile BOOLEAN Launched;

    // Single-step pending state (MTF on Intel / RFLAGS.TF on AMD)
    volatile BOOLEAN SingleStepPending;
    volatile UINT64  PendingGpa;
    volatile UINT64  PendingOrigVal;

    UINT64  Reserved[4];
} PER_CPU_CONTEXT, *PPER_CPU_CONTEXT;

// ============================================================================
//  14. Abstract runtime interface - vendor dispatch
// ============================================================================
typedef enum _HV_VENDOR {
    HvVendorUnknown = 0,
    HvVendorIntel   = 1,
    HvVendorAmd     = 2,
} HV_VENDOR;

typedef struct _HV_OPERATIONS {
    HV_VENDOR    Vendor;
    const char*  Name;

    // Lifecycle
    NTSTATUS (*Initialize)(VOID);
    VOID     (*Teardown)(VOID);

    // Memory protection
    NTSTATUS (*BuildIdentityMap)(const HV_IDENTITY_RANGE* Ranges, ULONG Count);
    NTSTATUS (*ProtectRange)(UINT64 Gpa, UINT64 Size, UINT64 Perms);
    NTSTATUS (*SaveAndGrant)(UINT64 Gpa, UINT64 Perms, UINT64* OutOriginal);
    NTSTATUS (*RestoreEntry)(UINT64 Gpa, UINT64 OriginalValue);
    NTSTATUS (*SplitAndGetPte)(UINT64 Gpa, PEPT_ENTRY* OutPte);

    // Single-step (MTF on Intel, RFLAGS.TF on AMD)
    VOID     (*ArmSingleStep)(PPER_CPU_CONTEXT Cpu);
    VOID     (*DisarmSingleStep)(PPER_CPU_CONTEXT Cpu);

    // Exception injection
    NTSTATUS (*InjectException)(UINT32 Vector, UINT32 ErrorCode, UINT64 FaultingGpa);

    // TLB maintenance
    VOID     (*InvalidateTlbAll)(VOID);
} HV_OPERATIONS, *PHV_OPERATIONS;

// ============================================================================
//  15. Cross-module globals
// ============================================================================
extern HV_PT_POOL       g_PtPool;
extern PER_CPU_CONTEXT* g_PerCpu;
extern ULONG            g_CpuCount;
extern volatile LONG    g_HypervisorActive;
extern volatile LONG    g_ShuttingDown;
extern HV_OPERATIONS*   g_HvOps;
extern HV_IDENTITY_RANGE* g_IdentityRanges;
extern ULONG            g_IdentityRangeCount;

// ============================================================================
//  16. Inline helpers
// ============================================================================

// Any-IRQL spinlock safe inside VM-exit context.
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

// VmxAdjustControls applies Intel SDM Vol 3C App. B capability semantics:
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
//  17. Cross-module API declarations
// ============================================================================

// ept_common.cpp - page-table pool
NTSTATUS HvPtPoolInit(VOID);
VOID     HvPtPoolDestroy(VOID);
PVOID    HvPtPoolAlloc(UINT64* OutPhys);
VOID     HvPtPoolFree(PVOID Page);

// ept_common.cpp - identity ranges
NTSTATUS HvCollectPhysicalRanges(PHV_IDENTITY_RANGE* OutRanges, PULONG OutCount);
VOID     HvFreePhysicalRanges(HV_IDENTITY_RANGE* Ranges);

// ept_common.cpp - exception injection
NTSTATUS HvInjectGuestPageFault(UINT64 Gpa, BOOLEAN Write, BOOLEAN Execute);

// vmm.cpp
PPER_CPU_CONTEXT GetCurrentCpu(VOID);

// vmexit.cpp - called from asm stub
extern "C" void VmxVmExitHandlerC(UINT64* GuestRegs);
extern "C" void SvmVmExitHandlerC(UINT64* GuestRegs);

// asm stubs
extern "C" {
    UINT16 VmxReadTr(VOID);
    UINT8  VmxLaunch(VOID);
    VOID   VmxVmExitEntry(VOID);
    UINT8  SvmLaunch(VOID);
    VOID   SvmVmExitEntry(VOID);
}
