<div align="center">

```
             _       _            
 _   _  ___ (_)   __| | _____   __
| | | |/ _ \| |  / _` |/ _ \ \ / /
| |_| | (_) | | | (_| |  __/\ V / 
 \__, |\___/|_|  \__,_|\___| \_/  
 |___/                            

   L O W - L E V E L   R I N G   H Y P E R V I S O R
```

### **Bare-Metal x86-64 Hardware Virtualization Framework**

*A low-level research hypervisor implementing Intel VT-x and AMD-V virtualization primitives.*

[![C++20](https://img.shields.io/badge/Language-C%2B%2B20%20%2F%20ASM-00599C.svg?style=for-the-badge&logo=cplusplus)](https://isocpp.org/)
[![Arch](https://img.shields.io/badge/Architecture-x86__64-red.svg?style=for-the-badge)](https://en.wikipedia.org/wiki/X86-64)
[![Status](https://img.shields.io/badge/Status-In_Active_Development-orange.svg?style=for-the-badge)](#-project-status)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

---

</div>

> [!CAUTION]
> **DEVELOPMENT STAGE (WIP)**
> This codebase contains experimental, ring--1 kernel-level hypervisor code. It is currently under **heavy active development** (`lowest-level-dev`) and is not yet production-ready. Features may change rapidly.

---

## ⚡ Overview

This project is a lightweight, high-performance C++ and Assembly hypervisor engine designed for low-level research into hardware-assisted virtualization. By interfacing directly with host hardware extensions (**Intel VT-x** and **AMD-V**), it creates a transparent virtualization layer underneath the operating system.

```
       +-------------------------------------------------------+
       |                  GUEST OS / USER SPACE                |
       +-------------------------------------------------------+
                                  |
                           ( VM-Exit / VM-Entry )
                                  v
+---------------------------------------------------------------------+
|                      KLEHypervisor Core                             |
|  +--------------------------------+  +---------------------------+  |
|  |     Intel VMX Subsystem        |  |    AMD SVM Subsystem      |  |
|  |  - EPT Page Tables             |  |  - NPT Page Tables        |  |
|  |  - VMCS Execution Control      |  |  - VMCB State Control     |  |
|  +--------------------------------+  +---------------------------+  |
|                                                                     |
|                  VM-Exit Dispatcher & Handler Pipeline              |
+---------------------------------------------------------------------+
                                  |
                                  v
       +-------------------------------------------------------+
       |                  HOST HARDWARE (x86-64)               |
       +-------------------------------------------------------+
```

---

## ✨ Core Architectures Supported

### 🔷 Intel VT-x Subsystem
* **VMX Initialization (`intel_vmm.cpp`)**: Full control structure setup, VMXON region activation, and VMCS configuration.
* **Extended Page Tables (`ept_common.cpp`)**: Memory translation virtualization via 4-level nested identity maps.
* **Low-Level Assembly Stubs (`intel_vmm_stub.asm`)**: Host context preservation, VMLANCH / VMRESUME primitives, and low-overhead context switches.

### 🔴 AMD-V Subsystem
* **SVM Engine (`amd_svm.cpp`)**: Host state save area layout, MSRPM setup, and VMCB construction.
* **Nested Page Tables (`amd_npt.cpp`)**: Hardware-accelerated memory virtualization for AMD processor nodes.
* **SVM Assembly Stubs (`amd_svm_stub.asm`)**: High-speed VMRUN loops and host register state save/restore routines.

### 🛡️ VM-Exit Handling Core
* **Event Dispatcher (`vmexit.cpp`)**: Intercepts CPU execution events (MSR access, CPUID queries, CR3 loads, EPT/NPT faults) and safely dispatches or passes through context state.

---

## 📁 Repository Structure

```tree
lowest-level-dev/
├── 🔷 Intel Subsystem
│   ├── intel_vmm.cpp        # VMX Virtual Machine Monitor initialization
│   ├── intel_vmm_stub.asm   # Intel context switch & VMLAUNCH assembly stubs
│   └── ept_common.cpp       # Extended Page Table (EPT) memory handlers
│
├── 🔴 AMD Subsystem
│   ├── amd_svm.cpp          # AMD SVM VMCB configuration & runtime setup
│   ├── amd_svm_stub.asm     # AMD low-level VMRUN assembly primitives
│   └── amd_npt.cpp          # AMD Nested Page Tables (NPT) implementation
│
├── ⚙️ Shared Core
│   ├── vmexit.cpp           # Centralized VM-Exit handler & event pipeline
│   └── common.h             # Shared type definitions, registers, & structures
```

---

## 🛠️ Prerequisites & Building

### Requirements
* **Compiler**: Modern C++ compiler with C++20 support (`GCC >= 10`, `Clang >= 12`, or `MSVC 2022`)
* **Assembler**: NASM / MASM for `.asm` context-switching stubs
* **Target OS**: x86-64 System with CPU Virtualization enabled in BIOS/UEFI (VT-x or AMD-V)

---

## 🚧 Active Development Roadmap

The framework is actively being built and refined. Current milestones include:

- [x] Basic Intel VMXON & VMLAUNCH pipelines
- [x] AMD SVM VMCB control setup & VMRUN loop
- [ ] Complete EPT / NPT page fault hook resolution
- [ ] Custom MSR & CPUID interception handlers
- [ ] Multi-core hypervisor initialization (SMP support)
- [ ] Stability testing across bare-metal environments

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
