#include "pinscan_globals.h"
#include "cpu_context.h"
#include <sstream>
#include <iomanip>

// --- External Dependencies (Currently living in pinscan.cpp) ---
extern ThreadState* GetToolThreadState(THREADID tid);
extern void DispatchEntry(ThreadState* st, const InstEntry& e);
// ---------------------------------------------------------------

static const ADDRINT kKuserSharedBase = 0x7ffe0000;

void CaptureReadTarget(THREADID tid, ADDRINT addr) {
    if (ThreadState* st = GetToolThreadState(tid)) {
        st->pendingReadAddr = addr;
    }
}

void SpoofSystemTime(THREADID tid, UINT32 regIdx, CONTEXT* ctxt) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || st->pendingReadAddr == 0) return;

    ADDRINT readAddr = st->pendingReadAddr;

    // Check if the read was from InterruptTime (0x08) or TickCount (0x320)
    if (readAddr != (kKuserSharedBase + 0x08) && readAddr != (kKuserSharedBase + 0x320)) {
        st->pendingReadAddr = 0;
        return;
    }

    UINT64 spoofVal = 0;

    if (readAddr == (kKuserSharedBase + 0x08)) {
        // Target: 0x7FFE0008 (InterruptTime.LowPart) - 100ns units
        // 200 instructions = 100ns at 2 GHz
        spoofVal = (gSeqCounter.load() / 200) + 600000000;
    }
    else if (readAddr == (kKuserSharedBase + 0x320)) {
        // Target: 0x7FFE0320 (TickCount.LowPart) - 1ms units
        // 2,000,000 instructions = 1 millisecond at 2 GHz
        spoofVal = (gSeqCounter.load() / 2000000) + 60000;
    }

    // Apply the synchronized spoofed value to the destination register
    REG targetReg = (REG)regIdx;
    REG fullReg = REG_FullRegName(targetReg);
    PIN_SetContextReg(ctxt, fullReg, spoofVal);
    st->pendingReadAddr = 0;
}

void HandleRdtsc(THREADID tid, ADDRINT rip, CONTEXT* ctxt) {
    ThreadState* st = GetToolThreadState(tid);
    NoteTimingProbe(tid, rip, "rdtsc");

    // Increment by 2 cycles per instruction to simulate a realistic 2 GHz pipeline execution
    UINT64 spoofVal = (gSeqCounter.load() * 2) + 120000000000ULL;

    // Overwrite result (EAX/EDX)
    PIN_SetContextReg(ctxt, REG_RAX, spoofVal & 0xFFFFFFFF);
    PIN_SetContextReg(ctxt, REG_RDX, (spoofVal >> 32) & 0xFFFFFFFF);

    // Log
    if (st && st->gateOpen) {
        InstEntry te;
        te.seq = ++gSeqCounter;
        te.tid = tid;
        te.rip = rip;

        // Disassembly lookup
        auto it = gStaticByRip.find(rip);
        if (it != gStaticByRip.end()) {
            te.dis = it->second.dis; te.mod = it->second.mod; te.rva = it->second.rva;
        }

        if (gTimingEnabled) {
            std::ostringstream oss;
            oss << "rdtsc <output: "
                << std::hex << std::setw(8) << std::setfill('0') << ((spoofVal >> 32) & 0xFFFFFFFF) << ":"
                << std::hex << std::setw(8) << std::setfill('0') << (spoofVal & 0xFFFFFFFF) << ">";
            te.reason = oss.str();

            DispatchEntry(st, te);
        }

        if (gUseRing) { DumpWindow(st); st->dumping = true; st->postRemaining = gPostFollow; }
    }
}

void RecordRdtscAfter(THREADID tid, ADDRINT rip, const CONTEXT* ctxt) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->gateOpen) return;
    NoteTimingProbe(tid, rip, "rdtsc");

    ADDRINT rax = PIN_GetContextReg(ctxt, REG_GAX);
    ADDRINT rdx = PIN_GetContextReg(ctxt, REG_GDX);

    InstEntry te; te.seq = ++gSeqCounter; te.tid = tid; te.rip = rip;
    auto it = gStaticByRip.find(rip);
    if (it != gStaticByRip.end()) { te.dis = it->second.dis; te.mod = it->second.mod; te.rva = it->second.rva; }

    if (gTimingEnabled) {
        std::ostringstream oss;
        oss << "rdtsc <output: " << std::hex << std::setw(8) << std::setfill('0') << (rdx & 0xFFFFFFFF) << ":"
            << std::hex << std::setw(8) << std::setfill('0') << (rax & 0xFFFFFFFF) << ">";
        te.reason = oss.str();

        DispatchEntry(st, te);
    }
    if (gUseRing) { DumpWindow(st); st->dumping = true; st->postRemaining = gPostFollow; }
}

void SaveCpuidInputs(THREADID tid, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx) {
    if (ThreadState* st = GetToolThreadState(tid)) {
        st->cpuidLeaf = eax;
        st->cpuidSubleaf = ecx;
        st->cpuidInRax = eax;
        st->cpuidInRbx = ebx;
        st->cpuidInRcx = ecx;
        st->cpuidInRdx = edx;
    }
}

static UINT32 ChangedCpuidOutputMask(const ThreadState* st, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx) {
    if (!st) return CPUID_REG_NONE;
    UINT32 mask = CPUID_REG_NONE;
    if ((UINT32)st->cpuidInRax != (UINT32)eax) mask |= CPUID_REG_RAX;
    if ((UINT32)st->cpuidInRbx != (UINT32)ebx) mask |= CPUID_REG_RBX;
    if ((UINT32)st->cpuidInRcx != (UINT32)ecx) mask |= CPUID_REG_RCX;
    if ((UINT32)st->cpuidInRdx != (UINT32)edx) mask |= CPUID_REG_RDX;
    return mask;
}

static UINT32 GetCpuidRelevantOutputMask(UINT32 leaf, UINT32 subleaf) {
    switch (leaf) {
    case 0x00000000:
    case 0x00000001:
    case 0x00000002:
    case 0x00000004:
    case 0x00000007:
    case 0x0000000A:
    case 0x0000000B:
    case 0x0000000D:
    case 0x0000000F:
    case 0x00000010:
    case 0x00000012:
    case 0x00000014:
    case 0x00000015:
    case 0x00000017:
    case 0x00000018:
    case 0x0000001F:
    case 0x40000000:
    case 0x40000001:
    case 0x80000001:
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
    case 0x80000005:
        return CPUID_REG_ALL;
    case 0x00000016:
        return CPUID_REG_RAX | CPUID_REG_RBX | CPUID_REG_RCX;
    case 0x80000000:
        return CPUID_REG_RAX;
    case 0x80000006:
        return CPUID_REG_RCX | CPUID_REG_RDX;
    case 0x80000007:
        return CPUID_REG_RDX;
    case 0x80000008:
        return CPUID_REG_RAX | CPUID_REG_RBX | CPUID_REG_RCX;
    default:
        (void)subleaf;
        return CPUID_REG_NONE;
    }
}

void RecordCpuidAfter(THREADID tid, ADDRINT rip, const CONTEXT* ctxt) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->gateOpen) return;

    ++cpuidCount;

    ADDRINT eax = PIN_GetContextReg(ctxt, REG_GAX);
    ADDRINT ebx = PIN_GetContextReg(ctxt, REG_GBX);
    ADDRINT ecx = PIN_GetContextReg(ctxt, REG_GCX);
    ADDRINT edx = PIN_GetContextReg(ctxt, REG_GDX);

    UINT32 relevantMask = GetCpuidRelevantOutputMask((UINT32)st->cpuidLeaf, (UINT32)st->cpuidSubleaf);
    if (relevantMask == CPUID_REG_NONE) {
        relevantMask = ChangedCpuidOutputMask(st, eax, ebx, ecx, edx);
    }

    // if (gCpuidTaintWindow > 0 && relevantMask != CPUID_REG_NONE) {
    //     ActivateCpuidTritonWindow(st);
    //     if (relevantMask & CPUID_REG_RAX) SendIpcTaintRegister(tid, IPC_RAX);
    //     if (relevantMask & CPUID_REG_RBX) SendIpcTaintRegister(tid, IPC_RBX);
    //     if (relevantMask & CPUID_REG_RCX) SendIpcTaintRegister(tid, IPC_RCX);
    //     if (relevantMask & CPUID_REG_RDX) SendIpcTaintRegister(tid, IPC_RDX);
    // }

    InstEntry ce; ce.seq = ++gSeqCounter; ce.tid = tid; ce.rip = rip;
    auto it = gStaticByRip.find(rip);
    if (it != gStaticByRip.end()) { ce.dis = it->second.dis; ce.mod = it->second.mod; ce.rva = it->second.rva; }

    std::ostringstream oss;
    oss << "cpuid leaf 0x" << std::hex << std::setw(8) << std::setfill('0') << (st->cpuidLeaf & 0xFFFFFFFF)
        << " subleaf 0x" << std::hex << std::setw(8) << std::setfill('0') << (st->cpuidSubleaf & 0xFFFFFFFF)
        << " <output: " << std::hex << std::setw(8) << std::setfill('0') << (eax & 0xFFFFFFFF) << ":"
        << std::hex << std::setw(8) << std::setfill('0') << (ebx & 0xFFFFFFFF) << ":"
        << std::hex << std::setw(8) << std::setfill('0') << (ecx & 0xFFFFFFFF) << ":"
        << std::hex << std::setw(8) << std::setfill('0') << (edx & 0xFFFFFFFF) << ">"
        << " taint_mask: 0x" << std::hex << relevantMask
        << " count: ";
    oss << cpuidCount;

    ce.reason = oss.str();

    DispatchEntry(st, ce);
    if (gUseRing) { DumpWindow(st); st->dumping = true; st->postRemaining = gPostFollow; }
}