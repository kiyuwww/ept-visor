; ============================================================================
;  intel_vmm_stub.asm — Intel VT-x bare-metal execution stub (MASM x64 / WDK)
;
;  Architectural reference: Intel SDM Vol 3C chapters 24-27 (VMX operation,
;  VM-entry, VM-exit) and Vol 3D Appendix B (VMCS field encodings).
;
;  Engine mechanics implemented here:
;
;    LAUNCH   VmxLaunch captures the return address of its own host call
;             frame — the point where the driver would normally resume — and
;             programs it as VMCS.GUEST_RIP, with VMCS.GUEST_RSP set to the
;             matching live host stack image. VM-entry therefore transfers
;             the core into guest execution exactly as if VmxLaunch had
;             executed RET: the OS kernel thread continues transparently.
;             On the success path the stub returns to its caller in GUEST
;             mode with RAX = 0 (VMX_SUCCESS); a failed vmlaunch never
;             enters the guest and returns the VM-fail block code in RAX.
;
;    EXIT     VmxVmExitEntry is the VMCS_HOST_RIP transfer point. A VM-exit
;             does NOT save GPRs to memory — every guest register is still
;             live in the physical register file at the first stub
;             instruction. The stub spills all 15 guest GPRs into a stack
;             frame whose linear layout is the GUEST_REGS contract consumed
;             by VmxVmExitHandlerC (vmexit.cpp), mirrors the archived guest
;             RIP/RSP/RFLAGS from the VMCS into an exit-state block, and
;             calls the C++ dispatcher through the MS x64 calling convention
;             (16-byte stack alignment, 32-byte shadow space, DF=0).
;
;    RESUME   On the normal path the dispatcher programs updated guest state
;             into the VMCS (vmwrite) and the stub reloads all 15 guest GPRs
;             from the frame before VMRESUME. A VMRESUME failure means the
;             VMCS has suffered consistency corruption — the stub raises a
;             fatal ud2 trap instead of executing undefined guest state.
;
;    TEARDOWN When the dispatcher completed the teardown hypercall and
;             executed __vmx_vmxoff, the core is already in bare-metal
;             (non-root) mode: VMRESUME is architecturally impossible and
;             would fault unresolvably. The stub instead rebuilds the guest
;             context natively — staged restore chain on the guest stack,
;             all 15 GPRs restored, updated guest RSP loaded, and a naked
;             indirect long-mode jump to the updated guest RIP.
;
;  VMCS setup contract (vmexit.cpp, per logical processor, before launch):
;    VMCS_HOST_RIP  = VmxVmExitEntry
;    VMCS_HOST_RSP  = per-core host stack top, MUST be 16-byte aligned
;                     (the frame alignment arithmetic below depends on it)
;    host selector/base/CR0/CR3/CR4/MSR fields per SDM ch. 27.5
; ============================================================================
        OPTION CASEMAP:NONE

; ----------------------------------------------------------------------------
;  VMCS field encodings used by this stub (SDM Vol 3D, Appendix B).
; ----------------------------------------------------------------------------
VMCS_GUEST_RSP          EQU 0000681Ch
VMCS_GUEST_RIP          EQU 0000681Eh
VMCS_GUEST_RFLAGS       EQU 00006820h
VMCS_VM_INSTRUCTION_ERR EQU 00004400h

; ----------------------------------------------------------------------------
;  Guest register file (GUEST_REGS) — a linear array of 15 guest GPR
;  quadwords. This is the exact memory layout VmxVmExitHandlerC indexes
;  through its PGUEST_REGS argument. The guest RSP is NOT one of the 15
;  array entries; it lives in the exit-state mirror block immediately below
;  the array base (negative offsets, see frame layout in VmxVmExitEntry).
; ----------------------------------------------------------------------------
VMX_GPR_RAX     EQU 000h
VMX_GPR_RCX     EQU 008h
VMX_GPR_RDX     EQU 010h
VMX_GPR_RBX     EQU 018h
VMX_GPR_RBP     EQU 020h
VMX_GPR_RSI     EQU 028h
VMX_GPR_RDI     EQU 030h
VMX_GPR_R8      EQU 038h
VMX_GPR_R9      EQU 040h
VMX_GPR_R10     EQU 048h
VMX_GPR_R11     EQU 050h
VMX_GPR_R12     EQU 058h
VMX_GPR_R13     EQU 060h
VMX_GPR_R14     EQU 068h
VMX_GPR_R15     EQU 070h

; Exit-state mirror block, addressed by vmexit.cpp as NEGATIVE offsets from
; the register-file pointer handed over in RCX:
;   [regs - 18h] = guest RSP     (entry: archived value; teardown: updated)
;   [regs - 10h] = guest RIP     (entry: archived value; teardown: updated —
;                                 for the teardown VMMCALL exit the dispatcher
;                                 MUST advance this past the VMMCALL so the
;                                 native resume never re-executes it, which
;                                 would #UD outside VMX)
;   [regs - 08h] = guest RFLAGS  (entry: archived value)
VMX_MIRROR_GUEST_RSP    EQU -018h
VMX_MIRROR_GUEST_RIP    EQU -010h
VMX_MIRROR_GUEST_RFLAGS EQU -008h

; Stub frame layout after the VmxVmExitEntry prologue (offsets from RSP):
VMX_FRAME_SHADOW        EQU 000h    ; 32-byte MS-ABI shadow/home space
VMX_FRAME_MIRROR_RSP    EQU 020h    ; guest RSP mirror
VMX_FRAME_MIRROR_RIP    EQU 028h    ; guest RIP mirror
VMX_FRAME_MIRROR_RFLAGS EQU 030h    ; guest RFLAGS mirror
VMX_FRAME_REGFILE       EQU 038h    ; frame base F = register-file pointer

; Lifecycle token returned in RAX by VmxVmExitHandlerC (must match vmexit.cpp):
;   0            — continue: VMCS state is current, execute VMRESUME
;   VMX_TOKEN_*  — teardown completed (__vmx_vmxoff executed), native resume
VMX_TOKEN_VMXOFF        EQU 0564D4F46h      ; 'VMOF'

        PUBLIC  VmxReadTr
        PUBLIC  VmxLaunch
        PUBLIC  VmxVmExitEntry

        EXTERN  VmxVmExitHandlerC:proc

.code
; ============================================================================
;  VmxReadTr — return the current Task Register selector in RAX, zero-extended.
;
;  STR stores the 16-bit TR selector; the MOVZX zero-extension guarantees the
;  upper 48 bits of RAX are clean for C callers reading a 64-bit return.
; ============================================================================
VmxReadTr       proc
        str     ax                  ; STR r/m16: TR selector -> AX
        movzx   eax, ax             ; zero-extend into RAX (bits 63:16 = 0)
        ret
VmxReadTr       endp

; ============================================================================
;  VmxLaunch — transfer the core into guest execution through VMLAUNCH.
;
;  The launch payload is this PROC's own host call frame:
;    [rsp+00h]  return address into the driver  -> VMCS.GUEST_RIP
;    [rsp+08h]  driver frame                    -> VMCS.GUEST_RSP image
;  Guest RSP is the live host RSP adjusted past the captured return slot, so
;  the resumed stack image is byte-exact with a normal RET epilogue.
;
;  Return value (RAX):
;    0            guest-mode success return (the caller continues in guest)
;    1            VMfailInvalid  (CF=1 — no current VMCS / launch blocked)
;    VM_INSTRUCTION_ERROR field (VMfailValid, ZF=1 — VMCS consistency error)
;    0FFh         indeterminate flag state (defensive)
; ============================================================================
VmxLaunch       proc
        mov     rax, [rsp]              ; capture driver resume address
        lea     rdx, [rsp+8]            ; live host RSP -> guest stack image

        mov     rcx, VMCS_GUEST_RIP
        vmwrite rcx, rax                ; VMCS.GUEST_RIP = driver resume RIP
        mov     rcx, VMCS_GUEST_RSP
        vmwrite rcx, rdx                ; VMCS.GUEST_RSP = live host RSP

        xor     eax, eax                ; RAX = 0 travels into the guest-mode
                                        ; return path (VMX_SUCCESS token)
        vmlaunch
        ; VM-entry success never falls through: the core is executing the
        ; guest (the live OS kernel) until the next VM-exit re-enters the stub.

        ; ---- VMfail path: decode the VM-instruction status flags ----
        jc      LaunchFailInvalid       ; CF=1 -> VMfailInvalid
        jz      LaunchFailValid         ; ZF=1 -> VMfailValid
        mov     eax, 0FFh               ; indeterminate status
        ret

LaunchFailInvalid:
        mov     eax, 1                  ; block code: VMfailInvalid
        ret

LaunchFailValid:
        mov     ecx, VMCS_VM_INSTRUCTION_ERR
        vmread  rax, rcx                ; detailed error block (1..N)
        ret
VmxLaunch       endp

; ============================================================================
;  VmxVmExitEntry — hardware VM-exit transfer point (VMCS_HOST_RIP target).
;
;  VM-exit entry state (SDM Vol 3C, ch. 27):
;    GPRs    : live GUEST values — VM-exit does not save GPRs to memory
;    RSP     : VMCS_HOST_RSP (per-core host stack, 16-byte aligned contract)
;    RIP     : VmxVmExitEntry
;    RFLAGS  : 00000002h (IF=0 — the host side runs interrupt-disabled)
;    VMCS    : current; guest RIP/RSP/RFLAGS archived in the guest state area
;
;  Frame construction (descent from VMCS_HOST_RSP):
;    15 x push  = 078h   guest GPR spill            -> F+000h .. F+070h
;    sub  038h  = 038h   shadow space + mirror block
;    total      = 0A0h, and 078h mod 16 = 8, 038h mod 16 = 8  ->  8+8 = 16
;    => RSP is exactly 16-byte aligned at the CALL, as the MS x64 ABI demands
;       before transferring control to foreign code.
; ============================================================================
        align   16
VmxVmExitEntry  proc
        ; ---- Stage 1: spill all 15 guest GPRs (reverse of file order) ----
        push    r15                     ; [F+070h]
        push    r14                     ; [F+068h]
        push    r13                     ; [F+060h]
        push    r12                     ; [F+058h]
        push    r11                     ; [F+050h]
        push    r10                     ; [F+048h]
        push    r9                      ; [F+040h]
        push    r8                      ; [F+038h]
        push    rdi                     ; [F+030h]
        push    rsi                     ; [F+028h]
        push    rbp                     ; [F+020h]
        push    rbx                     ; [F+018h]
        push    rdx                     ; [F+010h]
        push    rcx                     ; [F+008h]
        push    rax                     ; [F+000h]   F = register-file base

        ; ---- Stage 2: reserve shadow space + exit-state mirror block ----
        sub     rsp, VMX_FRAME_REGFILE

        ; ---- Stage 3: mirror guest exit state out of the VMCS ----
        ; RAX and R10 are already saved in the register file -> free scratch.
        mov     eax, VMCS_GUEST_RIP
        vmread  r10, rax
        mov     [rsp+VMX_FRAME_MIRROR_RIP], r10
        mov     eax, VMCS_GUEST_RSP
        vmread  r10, rax
        mov     [rsp+VMX_FRAME_MIRROR_RSP], r10
        mov     eax, VMCS_GUEST_RFLAGS
        vmread  r10, rax
        mov     [rsp+VMX_FRAME_MIRROR_RFLAGS], r10

        ; ---- Stage 4: dispatch the C++ VM-exit dispatcher ----
        cld                             ; MS x64 ABI: DF=0 on foreign calls
        lea     rcx, [rsp+VMX_FRAME_REGFILE]    ; arg1 = PGUEST_REGS (base F)
        call    VmxVmExitHandlerC               ; lifecycle token -> RAX
        ; RSP is unchanged: the callee restored its own frame per the ABI and
        ; the shadow space below stays reserved for the next dispatcher call.

        ; ---- Stage 5: interrogate the core lifecycle token ----
        cmp     eax, VMX_TOKEN_VMXOFF
        je      VmxExitTeardown

; ---------------------------------------------------------------------------
;  Normal path — the VMCS guest area holds the (possibly handler-updated)
;  guest RIP/RSP/RFLAGS; VMRESUME loads them with the architectural checks.
;  Only the 15 GPRs must be re-loaded into the physical registers, because
;  VMRESUME does not restore GPRs from anywhere.
; ---------------------------------------------------------------------------
VmxExitResume:
        mov     rax, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RAX]
        mov     rcx, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RCX]
        mov     rdx, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RDX]
        mov     rbx, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RBX]
        mov     rbp, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RBP]
        mov     rsi, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RSI]
        mov     rdi, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RDI]
        mov     r8,  [rsp+VMX_FRAME_REGFILE+VMX_GPR_R8]
        mov     r9,  [rsp+VMX_FRAME_REGFILE+VMX_GPR_R9]
        mov     r10, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R10]
        mov     r11, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R11]
        mov     r12, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R12]
        mov     r13, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R13]
        mov     r14, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R14]
        mov     r15, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R15]
        ; The host frame is intentionally not unwound: every VM-exit reloads
        ; RSP from VMCS_HOST_RSP, so the frame region is reused next exit.
        vmresume
        ud2                             ; VMCS consistency corruption: the
                                        ; machine cannot continue safely —
                                        ; fatal hardware breakdown trap.

; ---------------------------------------------------------------------------
;  Teardown path — the dispatcher already executed __vmx_vmxoff, so the core
;  is in bare-metal operation and VMRESUME is architecturally impossible.
;  The guest context is rebuilt natively:
;
;    Staged restore chain, built just below the updated guest RSP:
;      [guest_rsp-18h]  guest RFLAGS  -> POPFQ  (guest IF re-armed)
;      [guest_rsp-10h]  guest RBP     -> POP RBP (carrier register released)
;      [guest_rsp-08h]  updated RIP   -> RET    (naked indirect long-mode JMP;
;                                        simultaneously finalizes RSP to the
;                                        exact guest RSP in one step)
;
;    Interrupt-atomicity of the staging window: CLI masks maskable interrupts
;    while the chain is built. POPFQ re-arms IF, but from that point every
;    staged slot still needed sits AT or ABOVE RSP — interrupt and NMI frames
;    are pushed strictly BELOW RSP and can only overwrite slots already
;    consumed. The transfer therefore has no clobber window.
;
;    The dispatcher must have written the updated guest RSP into
;    [regs-18h] and the resume RIP (advanced past the teardown VMMCALL)
;    into [regs-10h] before returning the VMXOFF token.
; ---------------------------------------------------------------------------
VmxExitTeardown:
        cli                                     ; freeze maskable interrupts
        mov     rbp, [rsp+VMX_FRAME_MIRROR_RSP] ; RBP = updated guest RSP (carrier)
        mov     rax, [rsp+VMX_FRAME_MIRROR_RIP]
        mov     [rbp-08h], rax                  ; stage resume RIP
        mov     rax, [rsp+VMX_FRAME_MIRROR_RFLAGS]
        mov     [rbp-18h], rax                  ; stage guest RFLAGS
        mov     rax, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RBP]
        mov     [rbp-10h], rax                  ; stage guest RBP

        ; Restore the 14 directly addressable guest GPRs from the frame.
        mov     rax, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RAX]
        mov     rcx, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RCX]
        mov     rdx, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RDX]
        mov     rbx, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RBX]
        mov     rsi, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RSI]
        mov     rdi, [rsp+VMX_FRAME_REGFILE+VMX_GPR_RDI]
        mov     r8,  [rsp+VMX_FRAME_REGFILE+VMX_GPR_R8]
        mov     r9,  [rsp+VMX_FRAME_REGFILE+VMX_GPR_R9]
        mov     r10, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R10]
        mov     r11, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R11]
        mov     r12, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R12]
        mov     r13, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R13]
        mov     r14, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R14]
        mov     r15, [rsp+VMX_FRAME_REGFILE+VMX_GPR_R15]

        ; Execute the staged restore chain on the guest stack.
        lea     rsp, [rbp-18h]                  ; RSP -> staged RFLAGS slot
        popfq                                   ; guest RFLAGS restored (IF)
        pop     rbp                             ; guest RBP restored; carrier gone
        ret                                     ; naked indirect JMP -> updated
                                                ; guest RIP; RSP = guest RSP
VmxVmExitEntry  endp

        end
