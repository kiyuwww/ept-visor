; ============================================================================
;  amd_svm_stub.asm — AMD-V SVM bare-metal execution stub (MASM x64 / WDK)
;
;  Architectural reference: AMD64 APM Vol 2, ch. 15 (SVM) and Appendix B
;  (VMCB layout / Host Save Area).
;
;  Engine mechanics implemented here:
;
;    LAUNCH   SvmLaunch receives the current core's PCPU_CONTEXT*, caches the
;             live host descriptor/MSR state into the Host Save Area page
;             (VMSAVE with Cpu->HostSavePa — VMRUN repeats the save implicitly
;             at entry, so this VMSAVE is a defensive pre-cache, not a
;             duplicate), loads the guest segment caches from the VMCB
;             (VMLOAD with Cpu->VmcbPa) and executes VMRUN. VMRUN carries the
;             VMCB physical address in RAX and — critically — auto-executes
;             CLGI: the Global Interrupt Flag drops to 0 for the entire
;             guest/virtualized epoch and stays 0 across every #VMEXIT until
;             the stub explicitly re-opens it with STGI.
;
;    EXIT     AMD #VMEXIT has no VMCS_HOST_RIP/HOST_RSP equivalent: the
;             hardware restores the host image (RIP/RSP/RFLAGS, FS/GS/TR/LDTR
;             caches, GDTR/IDTR, EFER, STAR/LSTAR/CSTAR/SFMASK,
;             KERNEL_GS_BASE, SYSENTER_*) from the Host Save Area captured by
;             the last VMRUN. The exit therefore lands at the instruction
;             immediately following VMRUN — SvmVmExitEntry is that landing
;             zone (SvmLaunch jumps into it; every resume VMRUN re-enters it).
;             Guest RAX/RSP/RIP/RFLAGS were archived by hardware into the
;             VMCB save area; the remaining GPRs are still live in the
;             physical register file at the first stub instruction. The stub
;             spills the full register file into the GUEST_REGS linear array
;             (18 quadwords) expected by SvmVmExitHandlerC (vmexit.cpp),
;             re-opens GIF with STGI, and calls the C++ dispatcher through
;             the MS x64 calling convention (16-byte alignment, 32-byte
;             shadow space, DF=0).
;
;             VMSAVE into the VMCB is deliberately NOT executed here: at
;             #VMEXIT the machine segment/system-MSR state has already been
;             replaced by the HSAVE host image, so a VMSAVE would write the
;             HOST FS/GS/TR/LDTR/KERNEL_GS_BASE values over the guest save
;             area (host-state overwrite vector — the same hazard documented
;             in SvmHandleTeardownVmcall, amd_svm.cpp). The guest segment and
;             system-MSR state is already frozen inside the VMCB save area by
;             the VMRUN/VMLOAD pair and is preserved there by the hardware
;             across #VMEXIT; VMLOAD re-arms it at every re-entry.
;
;    RESUME   On the normal path the stub mirrors handler-updated resume
;             state (RAX/RSP/RFLAGS/RIP slots of the GUEST_REGS array) back
;             into the VMCB save area — VMRUN samples guest RAX, RSP, RIP and
;             RFLAGS exclusively from the VMCB, so this sync is the only
;             channel through which the dispatcher can alter them — reloads
;             all register-file GPRs, re-loads the guest segment caches via
;             VMLOAD(VmcbPa) and re-executes VMRUN. A VMRUN consistency-check
;             failure on a resume round (CF/ZF set) means the VMCB has been
;             corrupted behind the stub's back: fatal ud2 trap.
;
;    TEARDOWN When the dispatcher completed the teardown hypercall (guest RAX
;             carried 'HVmx' into VMCB->Save.Rax; EFER.SVME cleared and the
;             HSAVE pointer unregistered inside the C++ context), the core
;             has been dropped to bare metal: another VMRUN would raise an
;             unresolvable #UD outside SVM. The stub instead STGIs the core
;             back open, rebuilds the guest context natively — staged restore
;             chain on the guest stack, all GPRs restored, updated guest RSP
;             loaded — and executes a naked indirect long-mode jump to the
;             updated guest RIP (NextRip-preferring, past the committed
;             VMMCALL), returning control seamlessly to the native kernel.
;
;  Dispatcher contract (vmexit.cpp):
;    SvmVmExitHandlerC(UINT64* GuestRegs /*RCX*/, PPCPU_CONTEXT Cpu /*RDX*/)
;      returns 0     -> resume guest through VMRUN
;      returns != 0  -> teardown completed (SVME cleared): native resume path
;    amd_svm.cpp's SvmHandleTeardownVmcall(GuestRegs, Cpu) matches this ABI.
;
;  VmxReadTr — the vendor-neutral TR-selector read consumed by
;  amd_svm.cpp — is implemented once in the shared Intel stub
;  (intel_vmm_stub.asm) and is deliberately NOT redefined here to avoid a
;  duplicate symbol at link time.
; ============================================================================
        OPTION CASEMAP:NONE

; ----------------------------------------------------------------------------
;  VMCB state-save-area offsets (absolute from the mapped VMCB base). These
;  mirror the static_assert-guarded layout in amd_svm.cpp:
;      Save.Rflags = 0x400 + 0x170, Save.Rip = 0x400 + 0x178,
;      Save.Rsp    = 0x400 + 0x1D8, Save.Rax = 0x400 + 0x1F8.
;  VMRUN samples guest RAX/RSP/RIP/RFLAGS from exactly these fields.
; ----------------------------------------------------------------------------
VMCB_SAVE_RFLAGS        EQU 00570h
VMCB_SAVE_RIP           EQU 00578h
VMCB_SAVE_RSP           EQU 005D8h
VMCB_SAVE_RAX           EQU 005F8h

; ----------------------------------------------------------------------------
;  GUEST_REGS — the linear register-file contract shared with common.h and
;  amd_svm.cpp (HV_GUEST_REG_RAX = 0, HV_GUEST_REG_RSP = 4,
;  HV_GUEST_REG_RIP = 17). This is the exact memory layout that
;  SvmVmExitHandlerC indexes through its RCX argument and that
;  SvmHandleTeardownVmcall publishes the native resume context into.
; ----------------------------------------------------------------------------
SVM_GPR_RAX             EQU 000h        ; index 0  — guest RAX / hypercall input
SVM_GPR_RCX             EQU 008h        ; index 1
SVM_GPR_RDX             EQU 010h        ; index 2
SVM_GPR_RBX             EQU 018h        ; index 3
SVM_GPR_RSP             EQU 020h        ; index 4  — guest RSP (HV_GUEST_REG_RSP)
SVM_GPR_RBP             EQU 028h        ; index 5
SVM_GPR_RSI             EQU 030h        ; index 6
SVM_GPR_RDI             EQU 038h        ; index 7
SVM_GPR_R8              EQU 040h        ; index 8
SVM_GPR_R9              EQU 048h        ; index 9
SVM_GPR_R10             EQU 050h        ; index 10
SVM_GPR_R11             EQU 058h        ; index 11
SVM_GPR_R12             EQU 060h        ; index 12
SVM_GPR_R13             EQU 068h        ; index 13
SVM_GPR_R14             EQU 070h        ; index 14
SVM_GPR_R15             EQU 078h        ; index 15
SVM_GPR_RFLAGS          EQU 080h        ; index 16 — guest RFLAGS mirror
SVM_GPR_RIP             EQU 088h        ; index 17 — guest RIP (HV_GUEST_REG_RIP)
GUEST_REGS_SIZE         EQU 090h        ; 18 quadwords

; ----------------------------------------------------------------------------
;  Stub frame layout. F = RSP at the VMRUN instruction = RSP restored by
;  every #VMEXIT (HSAVE host image), kept 16-byte aligned:
;
;    F+000h  guest RFLAGS slot of the register file (array tail)
;    F+008h  guest RIP    slot of the register file (array tail)
;    F+010h  PCPU_CONTEXT* home written once by SvmLaunch — the exit path's
;            only channel back to the per-core state (register contents do
;            not survive a guest epoch; only the HSAVE-restored RSP does)
;    F+018h..F+030h  SvmLaunch nonvolatile saves (rbp/rdi/rsi/rbx) — read
;                    back only on the VMRUN-failure return path
;    F+038h  SvmLaunch return address
;
;  During exit handling the register file is spilled BELOW F:
;    16 pushes = 080h  -> B = F-080h (GUEST_REGS base)
;    sub  020h         -> shadow space; RSP = F-0A0h
;    080h mod 16 = 0, 020h mod 16 = 0, F mod 16 = 0
;    => RSP is exactly 16-byte aligned at the dispatcher CALL.
; ----------------------------------------------------------------------------
SVM_FRAME_HOME_CPU      EQU 010h        ; F+010h — PCPU_CONTEXT* home
SVM_LAUNCH_RESERVE      EQU 018h        ; SvmLaunch scratch reservation
SVM_FRAME_REGFILE       EQU 020h        ; B = rsp+20h after shadow reservation
SVM_FRAME_CPU_HOME      EQU 0B0h        ; rsp+B0h = F+10h after reservation
SVM_EXIT_UNWIND         EQU 0A0h        ; 16 pushes (080h) + shadow (020h)

; ----------------------------------------------------------------------------
;  PCPU_CONTEXT field offsets consumed by this stub — the ONLY build-time
;  contract shared with common.h. Keep them mirrored in common.h:
;      C_ASSERT(offsetof(PCPU_CONTEXT, VmcbVa)     == 0x010);
;      C_ASSERT(offsetof(PCPU_CONTEXT, VmcbPa)     == 0x018);
;      C_ASSERT(offsetof(PCPU_CONTEXT, HostSavePa) == 0x038);
;  Each offset can be overridden from the build line, e.g.:
;      ml64 /D"PCPU_CTX_OFF_VMCB_PA=0x20" ...
; ----------------------------------------------------------------------------
IFNDEF PCPU_CTX_OFF_VMCB_VA
PCPU_CTX_OFF_VMCB_VA    EQU 0010h       ; mapped VMCB virtual address
ENDIF
IFNDEF PCPU_CTX_OFF_VMCB_PA
PCPU_CTX_OFF_VMCB_PA    EQU 0018h       ; VMCB physical address (VMRUN/VMLOAD operand)
ENDIF
IFNDEF PCPU_CTX_OFF_HOST_SAVE_PA
PCPU_CTX_OFF_HOST_SAVE_PA EQU 0038h     ; Host Save Area physical address (VMSAVE operand)
ENDIF

; VMRUN failure byte code reported to SvmLaunchCurrentCpu (amd_svm.cpp logs
; 0xFF as VMEXIT_INVALID).
SVM_ERR_VMEXIT_INVALID  EQU 0FFh

        PUBLIC  SvmLaunch
        PUBLIC  SvmVmExitEntry

        EXTERN  SvmVmExitHandlerC:proc

.code
; ============================================================================
;  SvmLaunch — capture the host continuation context and enter the guest.
;
;  RCX (arg1) = PCPU_CONTEXT* of the current core. The frame built here is
;  the permanent VM-exit host frame: VMRUN archives the live RSP/RIP into
;  the Host Save Area, and every #VMEXIT restores them, so all exit
;  handling below runs on this exact frame (RSP = F) for the core's
;  lifetime. On the success path this PROC never returns — the calling
;  thread becomes the VMM continuation parked at VMRUN.
;
;  Return value (RAX), failure path only:
;    0FFh  VMRUN consistency check failed (VMEXIT_INVALID); C++ disables
;          SVM, unregisters HSAVE and leaves the core unlaunched.
; ============================================================================
        align   16
SvmLaunch       proc
        ; ---- Stage 1: preserve the C++ caller's nonvolatile state; build F ----
        ; Entry RSP = E (RSP mod 16 == 8 per the MS x64 ABI). Four pushes plus
        ; an 018h reservation land RSP on F with F mod 16 == 0.
        push    rbx                             ; [F+030h]
        push    rsi                             ; [F+028h]
        push    rdi                             ; [F+020h]
        push    rbp                             ; [F+018h]
        sub     rsp, SVM_LAUNCH_RESERVE         ; RSP = F (mod 16 == 0)

        mov     rbx, rcx                        ; RBX = PCPU_CONTEXT*
        mov     [rsp+SVM_FRAME_HOME_CPU], rbx   ; home Cpu at F+010h — the
                                                ; register file does not survive
                                                ; a guest epoch, only this slot
                                                ; (reached via HSAVE-restored
                                                ; RSP) does

        ; ---- Stage 2: cache host descriptor state (VMSAVE -> Host Save Area) --
        ; VMSAVE stores the live host FS/GS/TR/LDTR caches, GDTR/IDTR and the
        ; system MSRs (EFER, STAR/LSTAR/CSTAR/SFMASK, KERNEL_GS_BASE,
        ; SYSENTER_*) into the 4KB Host Save Area page. VMRUN re-executes this
        ; save implicitly as its first action, so this explicit pre-cache is a
        ; defensive guarantee that the HSAVE image is complete before the core
        ; ever leaves host mode. VMSAVE consumes the save-area physical
        ; address through RAX.
        mov     rax, [rbx+PCPU_CTX_OFF_HOST_SAVE_PA]
        vmsave                                  ; host state -> HSAVE page

        ; ---- Stage 3: load guest segment state (VMLOAD <- VMCB) ---------------
        ; VMRUN does NOT load segment state; VMLOAD is the only channel that
        ; pulls FS/GS/TR/LDTR caches and GDTR/IDTR from the VMCB save area
        ; (seeded by SvmSetupSegment). Without it the core would enter the
        ; guest with whatever caches the host epoch left live.
        mov     rax, [rbx+PCPU_CTX_OFF_VMCB_PA]
        vmload                                  ; guest seg caches <- VMCB

        ; ---- Stage 4: guest RAX parameter -------------------------------------
        ; The guest's starting RAX lives in Vmcb->Save.Rax (0x5F8) and VMRUN
        ; architecturally transfers it into the active register state while
        ; performing its state load — that hardware load IS the requested
        ; "move of the guest RAX parameter". The machine RAX itself must hold
        ; the VMCB physical address at the VMRUN instruction (VMRUN's implicit
        ; operand); loading the guest value into RAX here would corrupt the
        ; operand and fail the launch.
        mov     rax, [rbx+PCPU_CTX_OFF_VMCB_PA]

        ; ---- Stage 5: VMRUN ----------------------------------------------------
        ; add rsp,0 sanitizes CF/ZF/SF: the pre-VMRUN RFLAGS is archived into
        ; the HSAVE as the host image and restored on every #VMEXIT, so the
        ; post-VMRUN failure check below (which reads exactly those flags)
        ; must see a clean baseline. VMRUN also auto-executes CLGI — from this
        ; point the Global Interrupt Flag is 0 and ALL interrupt delivery
        ; (maskable, NMI, SMI, INIT) is blocked until an explicit STGI.
        add     rsp, 00h                        ; flag sanitize
        vmrun                                   ; RAX = VmcbPa; enter guest

        ; ---- #VMEXIT landing (RSP = F, RAX = exit code, GIF = 0) or failure ---
        ; CF=1 / ZF=1 -> VMRUN consistency check failed before guest entry.
        jc      LaunchFail
        jz      LaunchFail

        ; Real #VMEXIT: the hardware has already restored the host image from
        ; HSAVE (RSP = F, host RIP = this return site, host segment caches and
        ; system MSRs live again). Hand control to the public exit frame.
        jmp     SvmVmExitEntry

LaunchFail:
        mov     eax, SVM_ERR_VMEXIT_INVALID     ; VMEXIT_INVALID byte code
        add     rsp, SVM_LAUNCH_RESERVE         ; RSP = F+018h
        pop     rbp                             ; restore C++ caller state
        pop     rdi
        pop     rsi
        pop     rbx
        ret
SvmLaunch       endp

; ============================================================================
;  VmxReadTr note: implemented once in intel_vmm_stub.asm (vendor-neutral
;  shared stub); amd_svm.cpp binds it from there. Not redefined here.
; ============================================================================

; ============================================================================
;  VmxVmExitEntry — AMD #VMEXIT landing zone and resume/teardown engine.
;
;  Entry state (established by the hardware's HSAVE restore at #VMEXIT):
;    GPRs     : guest values still live in the register file — EXCEPT RAX,
;               which the hardware replaced with the #VMEXIT exit code (the
;               guest's real RAX is in Vmcb->Save.Rax)
;    RSP      : F (host image archived by the last VMRUN)
;    RIP      : the instruction following VMRUN (this landing zone)
;    RFLAGS   : host image from HSAVE (CF/ZF clean — see flag sanitize)
;    GIF      : 0 — VMRUN's implicit CLGI is still in force; interrupts are
;               architecturally blocked until the explicit STGI below
;    Segments : host FS/GS/TR/LDTR caches and GDTR/IDTR restored from HSAVE,
;               so GS points at the KPCR and the C++ dispatcher runs in a
;               normal Windows kernel environment
;
;  Register-file spill order (first push = highest address = array tail):
;    r15,r14,r13,r12,r11,r10,r9,r8,rdi,rsi,rbp,rbp*,rbx,rdx,rcx,rax
;    (* duplicate RBP push reserves the GUEST_REGS slot 4 — the guest RSP —
;       which is filled from Vmcb->Save.Rsp immediately after)
;    => B = F-080h; [B+i*8] matches the GUEST_REGS index contract exactly.
; ============================================================================
        align   16
SvmVmExitEntry  proc
        ; ---- Stage 1: spill the live guest register file (GIF = 0 window) ----
        ; Every guest GPR except RAX is live here; RAX carries the exit code
        ; and is spilled first-in-order so the value cannot be lost once the
        ; VMCB walk begins. The duplicate RBP push is a placeholder for the
        ; RSP slot.
        push    r15                             ; [B+078h]
        push    r14                             ; [B+070h]
        push    r13                             ; [B+068h]
        push    r12                             ; [B+060h]
        push    r11                             ; [B+058h]
        push    r10                             ; [B+050h]
        push    r9                              ; [B+048h]
        push    r8                              ; [B+040h]
        push    rdi                             ; [B+038h]
        push    rsi                             ; [B+030h]
        push    rbp                             ; [B+028h] — guest RBP
        push    rbp                             ; [B+020h] — RSP slot placeholder
        push    rbx                             ; [B+018h]
        push    rdx                             ; [B+010h]
        push    rcx                             ; [B+008h]
        push    rax                             ; [B+000h] — exit code; guest RAX
                                                ; overwrites it from the VMCB

        ; ---- Stage 2: shadow space (B stays 16-byte aligned) ------------------
        sub     rsp, SVM_FRAME_REGFILE          ; RSP = F-0A0h (mod 16 == 0)

        ; ---- Stage 3: archive VMCB-resident guest state into the array -------
        ; R10/R11/RAX are already safe in the file -> free scratch. The Cpu
        ; pointer is recovered from its home slot — the only per-core state
        ; that survives the guest epoch (HSAVE restores nothing but RSP/RIP
        ; and the fixed host register image).
        mov     r10, qword ptr [rsp+SVM_FRAME_CPU_HOME]     ; PCPU_CONTEXT*
        mov     r11, [r10+PCPU_CTX_OFF_VMCB_VA]             ; mapped VMCB

        ; Guest RAX: at #VMEXIT the hardware parked it in Vmcb->Save.Rax and
        ; loaded the machine RAX with the exit code. This field carries the
        ; live exit-state inputs (e.g. the 'HVmx' teardown hypercall code) and
        ; MUST reach the dispatcher untouched.
        mov     rax, [r11+VMCB_SAVE_RAX]
        mov     [rsp+SVM_FRAME_REGFILE+SVM_GPR_RAX], rax
        mov     rax, [r11+VMCB_SAVE_RSP]
        mov     [rsp+SVM_FRAME_REGFILE+SVM_GPR_RSP], rax
        mov     rax, [r11+VMCB_SAVE_RFLAGS]                 ; RFLAGS mirror
        mov     [rsp+SVM_FRAME_REGFILE+SVM_GPR_RFLAGS], rax
        mov     rax, [r11+VMCB_SAVE_RIP]
        mov     [rsp+SVM_FRAME_REGFILE+SVM_GPR_RIP], rax

        ; ---- Stage 4: GIF transition — re-open the core ------------------------
        ; The Global Interrupt Flag has been 0 since VMRUN's implicit CLGI.
        ; STGI must precede the dispatcher call: with GIF=0 every interrupt,
        ; NMI and SMI is blocked, and IPI-driven barriers such as the
        ; KeGenericCallDpc fence inside SvmInvalidateTlbAll would deadlock
        ; against this core. After STGI the VMM context behaves as an
        ; interruptible kernel context; intercepted instructions executed by
        ; interrupt handlers run NATIVELY here (the CPU is in host mode), so
        ; no nested #VMEXIT can occur before the next VMRUN.
        stgi

        ; ---- Stage 5: dispatch the C++ VM-exit dispatcher ----------------------
        cld                                     ; MS x64 ABI: DF=0 on foreign calls
        lea     rcx, [rsp+SVM_FRAME_REGFILE]    ; arg1 = GuestRegs (base B)
        mov     rdx, r10                        ; arg2 = PCPU_CONTEXT*
        call    SvmVmExitHandlerC               ; lifecycle status -> RAX
        ; RSP is unchanged: the callee restored its own frame per the ABI and
        ; the shadow space below stays reserved for the next round.

        ; ---- Stage 6: interrogate the core lifecycle status --------------------
        test    rax, rax
        jnz     SvmExitTeardown                 ; != 0: teardown hypercall done,
                                                ; SVME cleared — never VMRUN again

; ---------------------------------------------------------------------------
;  Normal path — resume guest flight through VMRUN.
; ---------------------------------------------------------------------------
SvmExitResume:
        ; ---- Stage 7: publish handler-updated resume state into the VMCB ------
        ; VMRUN samples guest RAX/RSP/RIP/RFLAGS exclusively from the VMCB
        ; save area, so these four stores are the ONLY channel through which
        ; the dispatcher's decisions (advanced RIP, redirected RSP, injected
        ; RAX) reach the guest. All other array slots are restored physically.
        mov     r10, qword ptr [rsp+SVM_FRAME_CPU_HOME]     ; PCPU_CONTEXT*
        mov     r11, [r10+PCPU_CTX_OFF_VMCB_VA]

        mov     rax, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RAX]
        mov     [r11+VMCB_SAVE_RAX], rax
        mov     rax, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RSP]
        mov     [r11+VMCB_SAVE_RSP], rax
        mov     rax, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RFLAGS]
        mov     [r11+VMCB_SAVE_RFLAGS], rax
        mov     rax, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RIP]
        mov     [r11+VMCB_SAVE_RIP], rax

        ; VMCB physical address rides in RAX — the one register that is NOT
        ; restored physically (VMRUN consumes it as its operand and the guest
        ; RAX version enters through Save.Rax above).
        mov     rax, [r10+PCPU_CTX_OFF_VMCB_PA]

        ; ---- Stage 8: restore the register-file GPRs ---------------------------
        mov     rcx, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RCX]
        mov     rdx, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RDX]
        mov     rbx, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RBX]
        mov     rbp, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RBP]
        mov     rsi, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RSI]
        mov     rdi, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RDI]
        mov     r8,  [rsp+SVM_FRAME_REGFILE+SVM_GPR_R8]
        mov     r9,  [rsp+SVM_FRAME_REGFILE+SVM_GPR_R9]
        mov     r10, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R10]
        mov     r11, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R11]
        mov     r12, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R12]
        mov     r13, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R13]
        mov     r14, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R14]
        mov     r15, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R15]

        ; ---- Stage 9: unwind to F and re-arm the guest segment caches ---------
        ; lea is flag-neutral: the flags present at VMRUN are archived into
        ; the HSAVE host image and reappear at the next #VMEXIT, where the
        ; CF/ZF failure discrimination depends on them being clean.
        lea     rsp, [rsp+SVM_EXIT_UNWIND]      ; RSP = F (frame invariant:
                                                ; every VMRUN executes at RSP=F,
                                                ; so every #VMEXIT lands at F)
        vmload                                  ; RAX = VmcbPa — reload guest
                                                ; FS/GS/TR/LDTR caches and
                                                ; GDTR/IDTR (the caches have
                                                ; held HSAVE host values since
                                                ; the exit)
        add     rsp, 00h                        ; flag sanitize: CF=ZF=SF=0
        vmrun                                   ; RAX = VmcbPa; back to guest

        ; A resume-round consistency failure (CF/ZF set) means the VMCB was
        ; corrupted behind the stub's back — no defined recovery exists.
        jc      SvmExitCorrupt
        jz      SvmExitCorrupt
        ; Next #VMEXIT lands at the spill stage above (RSP = F invariant).

; ---------------------------------------------------------------------------
;  Teardown path — the dispatcher completed the teardown hypercall inside the
;  C++ context: EFER.SVME is cleared, MSR_AMD_VM_HSAVE_PA is unregistered and
;  the VMCB is no longer consumed by VMRUN. The core is bare metal; another
;  VMRUN would raise an unresolvable #UD outside SVM. The guest context is
;  rebuilt natively:
;
;    Staged restore chain, built just below the updated guest RSP:
;      [guest_rsp-18h]  guest RFLAGS -> POPFQ  (guest IF re-armed)
;      [guest_rsp-10h]  guest RBP    -> POP RBP (carrier register released)
;      [guest_rsp-08h]  updated RIP  -> RET     (naked indirect long-mode JMP;
;                                        simultaneously finalizes RSP to the
;                                        exact guest RSP in one step)
;
;  The dispatcher must have published the updated resume context into the
;  GuestRegs block before returning non-zero: GuestRegs[17] = resume RIP
;  (NextRip-preferring — the teardown VMMCALL has architecturally committed
;  and re-executing it natively with SVME=0 would raise #UD), GuestRegs[4] =
;  updated RSP, GuestRegs[16] = guest RFLAGS, GuestRegs[0] = real guest RAX.
;
;  Interrupt-atomicity of the staging window: STGI re-opens the Global
;  Interrupt Flag (mandatory — with no further VMRUN the implicit CLGI would
;  otherwise block interrupts on this core forever) and is idempotent here
;  because GIF was already opened before the dispatcher ran. CLI then masks
;  maskable interrupts while the chain is built. POPFQ re-arms IF, but from
;  that point every staged slot still needed sits AT or ABOVE RSP — interrupt
;  and NMI frames are pushed strictly BELOW RSP and can only overwrite slots
;  already consumed. The staged slots themselves live on the guest's own
;  stack, which nothing else can touch while this core is held. The transfer
;  therefore has no clobber window.
; ---------------------------------------------------------------------------
SvmExitTeardown:
        stgi                                    ; GIF 0 -> 1 (idempotent re-arm)
        cli                                     ; IF: freeze maskable interrupts

        mov     rbp, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RSP]    ; guest RSP (carrier)
        mov     rax, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RIP]
        mov     [rbp-08h], rax                  ; stage resume RIP
        mov     rax, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RBP]
        mov     [rbp-10h], rax                  ; stage guest RBP
        mov     rax, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RFLAGS]
        mov     [rbp-18h], rax                  ; stage guest RFLAGS

        ; Restore the register-file guest GPRs (RAX = real guest RAX — the
        ; hypercall input — not the exit code).
        mov     rax, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RAX]
        mov     rcx, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RCX]
        mov     rdx, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RDX]
        mov     rbx, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RBX]
        mov     rsi, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RSI]
        mov     rdi, [rsp+SVM_FRAME_REGFILE+SVM_GPR_RDI]
        mov     r8,  [rsp+SVM_FRAME_REGFILE+SVM_GPR_R8]
        mov     r9,  [rsp+SVM_FRAME_REGFILE+SVM_GPR_R9]
        mov     r10, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R10]
        mov     r11, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R11]
        mov     r12, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R12]
        mov     r13, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R13]
        mov     r14, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R14]
        mov     r15, [rsp+SVM_FRAME_REGFILE+SVM_GPR_R15]

        ; Execute the staged restore chain on the guest stack.
        lea     rsp, [rbp-18h]                  ; RSP -> staged RFLAGS slot
        popfq                                   ; guest RFLAGS restored (IF)
        pop     rbp                             ; guest RBP restored; carrier gone
        ret                                     ; naked indirect JMP -> updated
                                                ; guest RIP; RSP = guest RSP

; ---------------------------------------------------------------------------
;  Fatal path — resume-round VMRUN consistency check failed.
; ---------------------------------------------------------------------------
SvmExitCorrupt:
        ud2                                     ; VMCB consistency corruption:
                                                ; the machine cannot continue
                                                ; safely — fatal trap
SvmVmExitEntry  endp

        end
