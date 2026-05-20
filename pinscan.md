# **PinScan: Advanced Event-Triggered Lookback & DBI Analysis Engine**

## **Architectural System Documentation for LLM Context Contextualisation**

This document provides a comprehensive structural and functional blueprint of the **PinScan** framework. It is explicitly designed to serve as a high-fidelity context injection vector for future language models assisting in the maintenance, modification, or expansion of this instrumentation toolchain.

## **1\. System Overview & Architectural Purpose**

**PinScan** is a high-performance Dynamic Binary Instrumentation (DBI) tool compiled against the Intel Pin API, optimized for x86\_64 Windows environments. Its primary design objective is the extraction of gapless, instruction-level trace metrics, dynamic control flow variants, dynamic taint propagation states, and anti-analysis profiling data from heavily obfuscated commercial targets (such as software protected by VMProtect, Denuvo, or custom virtualized packers).

### **The Anti-Hypervisor Isolation Paradigm**

Traditional trace capture mechanisms running inside ring-3 debuggers (such as x64dbg) rely on the hardware Trap Flag (EFLAGS.TF) to single-step the target processor. In modern Windows environments operating Virtualization-Based Security (VBS), Hyper-V silently intercepts execution via compulsory VM Exits during sensitive instructions (e.g., cpuid). A known flaw/artifact in Hyper-V's state re-injection logic suppresses the Single-Step Exception (\#DB) on the instruction immediately succeeding a cpuid VM Exit. This blinds standard debuggers, corrupting dynamic taint histories and generating silent trace gaps.  
**PinScan completely circumvents this vector.** Because Intel Pin uses a software Just-In-Time (JIT) compiler to lift basic blocks into memory cache, instrument them, and execute them natively, it **never modifies the hardware Trap Flag**. Consequently, PinScan is entirely immune to hypervisor re-injection anomalies, ensuring a 100% accurate, instruction-by-instruction execution sequence.

## **2\. File Architecture Matrix**

The core implementation codebase is structured across four primary source boundaries:

pinscan/  
├── pinscan\_globals.h  \<- Central layout registry, global configuration definitions, state definitions.  
├── pinscan.cpp        \<- Core JIT instrumentation loop, lifecycle callbacks, command-line Knobs, Windows API imports.  
├── exec\_tracker.h     \<- Prototypes for tracking structural memory transformations, JIT compilation, and SMC page states.  
└── telemetry.h        \<- Prototypes for highly optimized, zero-allocation serialization schemas and JSONL outputs.

### **File-by-File Breakdown**

### **A. pinscan\_globals.h**

Acts as the global data orchestration layer. It completely encapsulates the abstract data definitions, thread-local shadow buffers, global thread locks (PIN\_LOCK), and atomic step sequence counters (std::atomic\<uint64\_t\>). This header establishes the shared state vocabulary utilized across all compilation units without importing heavy Windows headers that conflict with Pin's customized C Runtime (CRT).

### **B. pinscan.cpp**

The core engine entry point. It implements:

* Manual internal linkage to internal NT/Kernel32 primitives (VirtualQuery, CreateFileA) for thread-safe unmanaged I/O.  
* Command-line option registration (KNOB).  
* The central JIT compilation handler (InstrumentInstruction).  
* Thread-Local Storage (TLS) lifecycle tracking (ThreadStart, ThreadFini).  
* Operating system exception hooks (OnContextChange) and multi-process fork-tracking logic (FollowChild).

### **C. exec\_tracker.h / exec\_tracker.cpp**

Governs memory space taxonomy. It monitors structural memory modifications, detects Self-Modifying Code (SMC), and handles Just-In-Time unpacker detection. It flags memory configuration updates by tracking virtual allocation routines via API hook definitions on NtAllocateVirtualMemory.

### **D. telemetry.h / telemetry.cpp**

The high-speed serialization pipeline. It avoids runtime string heap allocations by streaming formatted binary metadata and layout arrays directly into optimized disk outputs. It exports specialized, machine-readable JSONL witnesses specifically structured for consumption by downstream symbolic execution or data-flow slicing tools (such as trace\_viewer.py or Triton-based frameworks).

## **3\. Core Data Structures & State Management**

To safely profile highly parallel applications without introducing lock contention bottlenecks during JIT analysis, PinScan implements thread-segregated state machines wrapped inside Pin's TLS abstraction layer (TLS\_KEY).

### **InstEntry**

Represents the unified dynamic payload frame for a singular executed instruction.

C++  
struct InstEntry {  
    uint64\_t seq{ 0 };                 // Globally synchronized absolute timeline sequence number  
    THREADID tid{ 0 };                 // Thread identity  
    ADDRINT rip{ 0 };                  // Absolute instruction pointer  
    std::string mod;                   // Executing module name or dynamic allocation marker  
    ADDRINT rva{ 0 };                  // Relative Virtual Address from module base  
    std::string dis;                   // Disassembly text string  
    std::string bytes;                 // Raw instruction machine code opcodes  
    std::string reason;                // Multi-tiered semantic tag or hit justification  
    std::vector\<std::string\> regLines; // Legacy context fields  
    std::vector\<std::string\> memLines; // Legacy context fields  
    std::string regJson;               // Target-specific mutation signatures  
    std::string memJson;               // Target-specific mutation signatures  
};

### **ThreadState**

The primary state workspace for tracking thread execution. Every thread owns an independent allocation of this object.

* **Lookback Ring Buffers:** Maps a fixed-size ring (std::vector\<InstEntry\> ring) to support lookback trace generation upon encountering security alerts or access violations.  
* **CPUID Cache Stores:** Holds state registers (cpuidLeaf, cpuidSubleaf, etc.) to intercept environmental probing.  
* **Heuristic Exception Contexts:** Tracks recursive exception dispatches, tracking transitions across KiUserExceptionDispatcher to isolate anti-debug SEH traps.  
* **Shadow Call Stacks:** An internal call tracker (std::vector\<ADDRINT\> shadowCallStack) that captures mismatched return structures (RET target divergence) caused by anti-tamper control-flow obfuscation.

### **PageMetadata & ExecPageState**

Used to continuously profile memory layout attributes. They differentiate between static, file-backed PE image pages and dynamic, unbacked, or newly generated executable memory blocks (such as JIT structures or decrypted unpacking layers).

## **4\. Architectural Subsystems & Operational Pipelines**

### **A. Marker-Based Loop Squelching Engine**

To prevent infinite disk consumption when executing long virtualization traces, PinScan contains a highly specialized **Loop Suppressor state machine** (ManageLoopState).

#### **The Lifecycle Pipeline**

 \[Burn-In Phase\] ──(Window Full)──\> \[Lock-On Phase\] ──(5 Counter Matches)──\> \[Observation Phase\]  
                                                                                   │  
 \[Exit & Commit\] \<──(Out of Working Set)── \[Squelch Active\] \<──(4th Iteration) ────┘

1. **Burn-In Phase:** Execution addresses populate a sliding deque buffer (lookbackBuffer) up to gLoopWindowSize.  
2. **Lock-On Phase:** PinScan evaluates whether the current RIP exists within the active history. If detected, a hit marker initializes a candidate loop head pointer (loopHeadRip).  
3. **Observation/Squelch Phase:** Once 5 consecutive workspace cycles match, loopConfirmed sets to true. Upon completing the 4th full loop iteration, loopSquelchActive transitions to true. Full textual logging is suspended; all execution iterations are silently routed into a compact memory cache (shadowBuffer) while a dedicated tick counter increments.  
4. **Exit & Commit Phase:** The moment the processor jumps outside the tracked loop window boundaries, the suppression block terminates. PinScan flushes the loop boundary records to disk alongside an summary marker: \=== \[LOOP EXITED: Executed N times\] \===.

### **B. High-Performance Concrete Trace Generator**

When \-concrete 1 is supplied, PinScan leverages JIT-time observation matrices to track exact register state mutations without triggering full context spills:

1. **Static Analysis (JIT Phase):** When compiling an instruction, PinScan interrogates the architecture structure via BuildGprReadMask and BuildGprWriteMask. It registers exactly which Registers are modified.  
2. **Tailored Injection (RecordConcreteBefore / RecordConcreteAfter):** Instead of dumping all general-purpose registers (IARG\_CONTEXT), it constructs an optimized argument list (IARGLIST). It instructs Pin to snapshot *only* the specific registers that participate in that instruction's execution path.  
3. **RIP-Relative Displacement Normalisation:** To ensure that offline symbolic tracking tools can effortlessly map static control-flow edges, PinScan automatically parses relative pointer addressing arrays (rip+0x... or rip-0x...) during the disassembly phase, translating them into canonical absolute target hex strings.

### **C. Dynamic Control Flow & JIT Dump Subsystem**

When \-cf\_dump 1 or \-ps\_profile provenance is active, PinScan tracks code generation dynamically.  
If an indirect call, jump, or return lands inside non-image unbacked memory space, PinScan invokes a low-level VirtualQuery call. It checks if the space is marked as private allocation with an active execution bit. If verified, the engine maps the exact base boundary addresses, reads the memory region safely via PIN\_SafeCopy, and exports a standalone physical binary mirror file (payload\_jit\_\[AllocationBase\].bin) immediately upon entry.

### **D. Multi-Process Fork Interception**

Obfuscated target scripts often spin out temporary watchdog child tasks to clear profiling configurations. PinScan overrides this behavior natively through the FollowChild pipeline:

C++  
static BOOL FollowChild(CHILD\_PROCESS cProcess, VOID\* userData) { ... return TRUE; }

By binding to PIN\_AddFollowChildProcessFunction and returning TRUE, PinScan intercepts child process creation. It forces the operating system shell to pass down the exact instrumentation command string to the newly spawned target PID, seamlessly propagating all tracking configurations and output options into the fork.

## **5\. Command-Line Configuration (Knobs Reference)**

When instructing an LLM to script test harnesses, generate automation wrappers, or extend runtime properties, use these precise configuration flags:

| Option Category | Knob String | Acceptable Values | Core Functional Action |
| :---- | :---- | :---- | :---- |
| **Output** | \-o | \[filename.txt\] | Primary destination for the human-readable text log. |
| **Output** | \-ps\_concrete\_jsonl | \[filename.jsonl\] | High-speed stream layout for structured register/memory changes. |
| **Mode** | \-ps\_mode | trigger, ring, stream | trigger: Wait for event. ring: Circular history. stream: Log all lines. |
| **Optimization** | \-loop\_window | 0 to 256 | Sets the size of the loop squelching cache window (0 disables). |
| **Granularity** | \-ps\_log\_level | 0, 1, 2 | 0 \= Concise (no disasm), 1 \= Standard, 2 \= Verbose tracking. |
| **Scope** | \-ps\_scope | main, all, \[name.dll\] | Restricts instrumentation boundaries to minimize execution overhead. |
| **Triggers** | \-timing | 0, 1 | Forces a lookback trace generation or alert on RDTSC/RDTSCP instructions. |
| **Triggers** | \-peb | 0, 1 | Intercepts memory pointer reads targeting the Process Environment Block. |
| **Mitigation** | \-spoof\_time | 0, 1 | Dynamically intercepts and rewrites hardware timing fields to counter anti-DBI checks. |
| **Profiling** | \-ps\_profile | triage, provenance, all | Configures presets for anti-analysis tracking or control-flow analysis. |
| **Gateways** | \-start / \-stop | \[Hex Address\] | Limits tracing exclusively to a specific address execution window. |

## **6\. Engineering Extension Guidelines for Future Models**

When editing or extending the logic inside pinscan.cpp or its helper files, adhere strictly to the following programmatic constraints to maintain performance and prevent runtime memory faults:

1. **Maintain Confined Context Queries:** Never blindly inject IARG\_CONTEXT into general instruction loops. Every context snapshot causes Pin to spill all general-purpose registers to the stack, heavily degrading execution performance. Use targeted bitmasks and localized register trackers (INS\_RegR, INS\_RegW) during the JIT phase.  
2. **Enforce Lock Order Dominance:** PinScan runs multi-threaded. To avoid deadlock traps, adhere to strict lock hierarchies. Acquire specialized memory subsystem locks (g\_ExecPageLock, g\_PageMetaLock) *before* acquiring the global tracking lock (gLock). Always release locks in the exact inverse order of acquisition.  
3. **Use Safe I/O Primitives:** Avoid using standard C++ streams (std::ofstream) inside highly active runtime callbacks. Use low-level buffered descriptors (std::setvbuf set to \_IONBF) or access raw OS structures directly via internal platform routines. This guarantees data preservation on disk if the target program triggers an intentional hard crash.  
4. **Preserve System Boundaries:** Standard Windows library includes (windows.h) pollute the translation unit namespaces and introduce deep linkage conflicts with Pin's specialized C Runtime wrapper library. Any necessary system structures or native functions (e.g., PINSCAN\_MBI) must be explicitly declared and imported via clean, C-style external linkage blocks (extern "C").