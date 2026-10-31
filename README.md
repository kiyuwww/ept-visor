<div align="center">

# ⚡ Lowest Level Dev: Bare-Metal Virtualization & Hypervisor Framework

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Kernel--Mode%20%2F%20Bare--Metal-red.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

*Высокопроизводительный низкоуровневый фреймворк гипервизора типа 1/1.5 для архитектур x86-64, разработанный для исследований в области безопасности ядра, анализа виртуализации и разработки собственного Virtual Machine Monitor (VMM).*

</div>

---

## 📑 Содержание

- [Обзоры и Архитектура](#-обзор-и-архитектура)
- [Ключевые Возможности](#-ключевые-возможности)
- [Структура Репозитория](#-структура-репозитория)
- [Детали Реализации](#-детали-реализации)
  - [Intel VT-x & EPT](#1-intel-vt-x--ept-extended-page-tables)
  - [AMD-V & NPT](#2-amd-v--npt-nested-page-tables)
  - [Диспетчер VM-Exit](#3-диспетчер-перехватов-vm-exit)
- [Требования и Сборка](#-требования-и-сборка)
- [Сценарии Применения](#-сценарии-применения)
- [Дисклеймер](#-отказ-от-ответственности)

---

## 🔬 Обзор и Архитектура

Проект **Lowest Level Dev** представляет собой модульную программную платформу, реализующую аппаратную виртуализацию на уровне ring -1 / VMX Root Operation. Фреймворк предоставляет базовую инфраструктуру для инициализации гипервизора, настройки трансляции страниц второго уровня (SLAT) и перехвата событий операционной системы с минимальными накладными расходами (overhead).

Проект сфокусирован на прозрачной виртуализации уже запущенной операционной системы (Late Launch / Dynamic Hypervisor Elevation).

```
                      +-------------------------------+
                      |      Guest OS / Ring 0-3      |
                      +-------------------------------+
                                      |
                         (VM-Exit / Intercept)
                                      v
   +---------------------------------------------------------------------+
   |                      LOWEST LEVEL DEV HYPERVISOR                    |
   |                                                                     |
   |   +--------------------------+         +------------------------+   |
   |   |    Intel VMX Subsystem   |         |   AMD SVM Subsystem    |   |
   |   |   (intel_vmm.cpp / asm)  |         |     (amd_svm.cpp)      |   |
   |   +--------------------------+         +------------------------+   |
   |                |                                    |               |
   |                v                                    v               |
   |   +--------------------------+         +------------------------+   |
   |   |   Extended Page Tables   |         |   Nested Page Tables   |   |
   |   |    (ept_common.cpp)      |         |     (amd_npt.cpp)      |   |
   |   +--------------------------+         +------------------------+   |
   |                                                                     |
   |                  +--------------------------------+                 |
   |                  |   VM-Exit Handler (vmexit.cpp) |                 |
   |                  +--------------------------------+                 |
   +---------------------------------------------------------------------+
                                      |
                                      v
                      +-------------------------------+
                      |       Hardware (x86_64)       |
                      +-------------------------------+
```

---

## ✨ Ключевые Возможности

* **Dual-Vendor Support**: Полная поддержка аппаратных технологий виртуализации **Intel VT-x** и **AMD-V (SVM)**.
* **SLAT (Second Level Address Translation)**:
  * Реализация **EPT (Extended Page Tables)** для процессоров Intel.
  * Реализация **NPT (Nested Page Tables)** для процессоров AMD.
  * Возможность изоляции, подмены и мониторинга страниц физической памяти.
* **Высокооптимизированный Context Switching**:
  * Ассемблерные заглушки (`intel_vmm_stub.asm`) для мгновенного сохранения и восстановления регистров процессора при переходах `VM-Exit` $\rightarrow$ `VM-Resume`.
* **Гибкий Диспетчер Перехватов**:
  * Перехват и обработка инструкций `CPUID`, `CR3/CR0/CR4 Access`, `MSR Read/Write`, `INVD`, `VMCALL / VMMCALL` и др.
* **Модульная Низкоуровневая Архитектура**:
  * Минимальное количество внешних зависимостей, идеальный выбор для работы в среде ядра (Kernel-mode) или Bare-Metal.

---

## 📁 Структура Репозитория

| Файл | Назначение |
| :--- | :--- |
| `intel_vmm.cpp` | Логика входа в режим VMX, инициализация VMCS (Virtual Machine Control Structure), настройка контрольных регистров Intel. |
| `intel_vmm_stub.asm` | Ассемблерные точки входа для обработки переходов `VMLAUNCH`, `VMRESUME` и низкоуровневого сохранения контекста. |
| `ept_common.cpp` | Создание и управление иерархией таблиц страниц EPT (PML4, PDPT, PD, PT), настройка разрешений (Read/Write/Execute). |
| `amd_svm.cpp` | Подготовка структуры VMCB (Virtual Machine Control Block), инициализация SVM и переключение процессоров AMD в режим виртуализации. |
| `amd_npt.cpp` | Построение и обслуживание двухэтапной адресации NPT для архитектуры AMD. |
| `vmexit.cpp` | Главный диспетчер обработки событий выходов из виртуального режима (VM-Exit dispatcher). |
| `common.h` | Общие структуры данных, определения MSR-регистров, флаги CPUID, макросы и утилиты. |

---

## 🔍 Детали Реализации

### 1. Intel VT-x & EPT (`intel_vmm.cpp`, `ept_common.cpp`)
Инициализация включает в себя проверку флагов `CPUID.1:ECX.VMX[bit 5]`, включение `CR4.VMXE`, настройку MSR-регистров (`IA32_FEATURE_CONTROL`, `IA32_VMX_BASIC`) и выделение физически непрерывной памяти под `VMXON` и `VMCS` области. Таблицы EPT формируют прямую (identity) карту памяти с возможностью настройки флагов доступа $R/W/X$ для каждой страницы 4KB/2MB.

### 2. AMD-V & NPT (`amd_svm.cpp`, `amd_npt.cpp`)
Для процессоров AMD выполняется проверка `CPUID.80000001h:ECX.SVM[bit 2]`, настройка `EFER.SVME` и инициализация `VMCB`. Управление памятью осуществляется через вложенные таблицы NPT, обеспечивая аппаратный проброс адресов и контроль за обращениями к памяти.

### 3. Диспетчер Перехватов (`vmexit.cpp`)
При возникновении события перехвата управление передается в ассемблерный стаб, который сохраняет регистры общего назначения ($RAX, RBX, RCX, RDX, RSI, RDI, RBP, R8-R15$) и вызывает C++ функцию `VmExitHandler`. 

Пример логики обработки:
```cpp
// Концептуальный пример обработки VM-Exit
extern "C" void MainVmExitHandler(GuestContext* context) {
    auto exitReason = ReadVmcs(VM_EXIT_REASON);

    switch (exitReason) {
        case EXIT_REASON_CPUID:
            HandleCpuid(context);
            AdvanceInstructionPointer();
            break;
        case EXIT_REASON_MSR_READ:
            HandleMsrRead(context);
            AdvanceInstructionPointer();
            break;
        case EXIT_REASON_EPT_VIOLATION:
            HandleEptViolation(context);
            break;
        default:
            // Неизвестное или необрабатываемое событие
            InjectGeneralProtectionFault(context);
            break;
    }
}
```

---

## 🛠 Требования и Сборка

### Системные требования
* **Процессор**: x86-64 Intel (с поддержкой VT-x & EPT) или AMD (с поддержкой AMD-V & NPT).
* **Включенная виртуализация** в BIOS/UEFI (SVM / Intel Virtualization Technology).

### Инструменты сборки
* **Компилятор**: Visual Studio (MSVC 2019/2022) с установленным WDK (если сборка идет под драйвер ядра) или Clang/GCC.
* **Ассемблер**: Microsoft Macro Assembler (MASM / `ml64.exe`) или NASM для сборки `intel_vmm_stub.asm`.
* **Стандарт C++**: C++17 или новее.

---

## 🎯 Сценарии Применения

1. **Исследования в области безопасности**: Анализ поведения вредоносного ПО (Malware Analysis) в изолированной гипервизором среде.
2. **Разработка Hypervisor-based Anti-Cheat / Security Agents**: Мониторинг целостности памяти ядра и защиты критических структур данных OS.
3. **Образовательные цели**: Изучение внутреннего устройства низкоуровневой виртуализации, спецификаций Intel SDM (Volume 3C) и AMD Architecture Programmer's Manual (Volume 2).

---

## ⚠️ Отказ от ответственности

*Данный проект создан исключительно в образовательных и исследовательских целях. Неправильное использование низкоуровневых инструкций виртуализации или неверная работа с физической памятью может привести к сбою системы (BSOD / Kernel Panic).*
