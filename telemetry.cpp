#include "telemetry.h"
#include "pinscan_globals.h"
#include "utils.h"
#include <sstream>
#include <fstream>
#include <iomanip>

// --- External Dependencies (Currently living in pinscan.cpp) ---
extern ThreadState* GetToolThreadState(THREADID tid);
extern void DispatchEntry(ThreadState* st, const InstEntry& e);
// ---------------------------------------------------------------

static void AppendJsonlLine(const std::string& path, const std::string& line) {
    if (path.empty()) return;
    PIN_GetLock(&gLock, 1);
    std::ofstream out(path, std::ios::app | std::ios::binary);
    if (out) {
        out << line << "\n";
    }
    PIN_ReleaseLock(&gLock);
}

static std::string BuildMemObservationsJson(ADDRINT r1, UINT32 r1Size, ADDRINT r2, UINT32 r2Size, ADDRINT w1, UINT32 w1Size) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"reads\":[";
    bool first = true;
    auto append_mem = [&](ADDRINT addr, UINT32 size) {
        if (addr == 0 || size == 0) return;
        if (!first) oss << ",";
        first = false;
        oss << "{\"addr\":\"" << Hex(addr) << "\",\"size\":" << size << ",\"value\":\"" << JsonEscape(ReadMemHex(addr, size)) << "\"}";
        };
    append_mem(r1, r1Size);
    append_mem(r2, r2Size);
    oss << "],\"writes\":[";
    first = true;
    append_mem(w1, w1Size);
    oss << "]}";
    return oss.str();
}
static void ExportTriggerWitness(const InstEntry& e, ADDRINT r1, UINT32 r1Size, ADDRINT r2, UINT32 r2Size, ADDRINT w1, UINT32 w1Size) {
    if (gTriggerJsonlPath.empty()) return;
    std::ostringstream oss;
    oss << "{"
        << "\"kind\":\"trigger\","
        << "\"seq\":" << e.seq << ","
        << "\"tid\":" << static_cast<unsigned>(e.tid) << ","
        << "\"rip\":\"" << Hex(e.rip) << "\","
        << "\"mod\":\"" << JsonEscape(e.mod) << "\","
        << "\"rva\":\"" << Hex(e.rva) << "\","
        << "\"dis\":\"" << JsonEscape(e.dis) << "\","
        << "\"reason\":\"" << JsonEscape(e.reason) << "\","
        << "\"memory\":" << BuildMemObservationsJson(r1, r1Size, r2, r2Size, w1, w1Size)
        << "}";
    AppendJsonlLine(gTriggerJsonlPath, oss.str());
}
static void ExportControlFlowWitness(THREADID tid, ADDRINT rip, ADDRINT target, ADDRINT rsp, const CONTEXT* ctxt, const std::string& provenance) {
    if (gTargetJsonlPath.empty() && gSnapshotJsonlPath.empty()) return;
    ADDRINT rspVal = 0;
    PIN_SafeCopy(&rspVal, reinterpret_cast<void*>(rsp), sizeof(ADDRINT));
    if (!gTargetJsonlPath.empty()) {
        std::ostringstream oss;
        oss << "{"
            << "\"kind\":\"indirect-target\","
            << "\"tid\":" << static_cast<unsigned>(tid) << ","
            << "\"rip\":\"" << Hex(rip) << "\","
            << "\"target\":\"" << Hex(target) << "\","
            << "\"rsp\":\"" << Hex(rsp) << "\","
            << "\"rsp_top\":\"" << Hex(rspVal) << "\","
            << "\"provenance\":\"" << JsonEscape(provenance) << "\""
            << "}";
        AppendJsonlLine(gTargetJsonlPath, oss.str());
    }
    if (!gSnapshotJsonlPath.empty() && ctxt) {
        std::ostringstream oss;
        oss << "{"
            << "\"kind\":\"snapshot\","
            << "\"tid\":" << static_cast<unsigned>(tid) << ","
            << "\"rip\":\"" << Hex(rip) << "\","
            << "\"target\":\"" << Hex(target) << "\","
            << "\"registers\":" << ContextRegsJson(ctxt) << ","
            << "\"stack_base\":\"" << Hex(rsp) << "\","
            << "\"stack_bytes\":\"" << ReadBytesHex(rsp, 0x100) << "\""
            << "}";
        AppendJsonlLine(gSnapshotJsonlPath, oss.str());
    }
}
static void ExportStartupSnapshot(THREADID tid, const CONTEXT* ctxt, ADDRINT tebBase, ADDRINT pebBase) {
    if (gStartupJsonlPath.empty() || !ctxt) return;
    ADDRINT rsp = PIN_GetContextReg(const_cast<CONTEXT*>(ctxt), REG_STACK_PTR);
    std::ostringstream oss;
    oss << "{"
        << "\"kind\":\"startup\","
        << "\"tid\":" << static_cast<unsigned>(tid) << ","
        << "\"rip\":\"" << Hex(PIN_GetContextReg(const_cast<CONTEXT*>(ctxt), REG_INST_PTR)) << "\","
        << "\"teb\":\"" << Hex(tebBase) << "\","
        << "\"peb\":\"" << Hex(pebBase) << "\","
        << "\"registers\":" << ContextRegsJson(ctxt) << ","
        << "\"stack_base\":\"" << Hex(rsp) << "\","
        << "\"stack_bytes\":\"" << ReadBytesHex(rsp, 0x200) << "\""
        << "}";
    AppendJsonlLine(gStartupJsonlPath, oss.str());
}
static void ExportMemoryEvent(const char* api, ADDRINT sourceRip, ADDRINT base, ADDRINT size, ADDRINT protect, const std::string& details) {
    if (gMemoryEventJsonlPath.empty()) return;
    std::ostringstream oss;
    oss << "{"
        << "\"kind\":\"memory-event\","
        << "\"api\":\"" << JsonEscape(api ? api : "") << "\","
        << "\"rip\":\"" << Hex(sourceRip) << "\","
        << "\"base\":\"" << Hex(base) << "\","
        << "\"size\":\"" << Hex(size) << "\","
        << "\"protect\":\"" << Hex(protect) << "\","
        << "\"details\":\"" << JsonEscape(details) << "\"";
    if (base != 0 && size != 0 && size <= 0x1000) {
        oss << ",\"bytes\":\"" << ReadBytesHex(base, static_cast<UINT32>(size)) << "\"";
    }
    oss << "}";
    AppendJsonlLine(gMemoryEventJsonlPath, oss.str());
}
static void ExportAntiAnalysisWitness(THREADID tid, ADDRINT rip, const std::string& reason) {
    if (gAntiAnalysisJsonlPath.empty()) return;
    std::ostringstream oss;
    oss << "{"
        << "\"kind\":\"anti-analysis\","
        << "\"tid\":" << static_cast<unsigned>(tid) << ","
        << "\"rip\":\"" << Hex(rip) << "\","
        << "\"reason\":\"" << JsonEscape(reason) << "\""
        << "}";
    AppendJsonlLine(gAntiAnalysisJsonlPath, oss.str());
}

static void WriteEntry(const InstEntry& e) {
    std::string modEsc = JsonEscape(e.mod);
    std::string disEsc = JsonEscape(e.dis);
    std::string reasonEsc = JsonEscape(e.reason);
    ThreadState* st = GetToolThreadState(e.tid);
    UINT64 currentLine = ++gLinesPrinted;

    if (gMaxLinesPrinted != 0 && currentLine > gMaxLinesPrinted) {
        if (st && st->gateOpen) {
            // ONLY execute this block once per thread when it first hits the wall
            st->gateOpen = false;

            // 1. Flush any trapped loop instructions
            PIN_GetLock(&gLock, 1);
            if (gOut && st->loopSquelchActive && !st->shadowBuffer.empty()) {
                std::fprintf(gOut, "=== [MAX LINES REACHED: Flushing orphaned shadow buffer...] ===\n");
                for (const auto& shadowEntry : st->shadowBuffer) {
                    // Bypass WriteEntry and write directly to avoid the atomic counter
                    std::fprintf(gOut, "tid=%d seq=%llu mod=%s %s | %s\n",
                        shadowEntry.tid, shadowEntry.seq, shadowEntry.mod.c_str(),
                        shadowEntry.dis.c_str(), shadowEntry.reason.c_str());
                }
                st->shadowBuffer.clear();
            }

            // 2. Write the final terminal marker
            if (gOut) {
                std::fprintf(gOut, "=== [TRACE HALTED: max_lines limit (%llu) reached for Thread %d] ===\n", gMaxLinesPrinted, st->tid);
                std::fflush(gOut); // Force it to the disk immediately
            }
            PIN_ReleaseLock(&gLock);
        }
        return; // Abort all future tracing for this thread
    }
    PIN_GetLock(&gLock, 1);
    if (gOut)
    {
        // If in concise let's get rid of the disassembly.
        if (gConciseEnabled)
        {
            std::fprintf(gOut, "tid=%u seq=%llu mod=%s %s | %s\n",
                (unsigned)e.tid, (unsigned long long)e.seq, e.mod.c_str(), Hex(e.rip).c_str(), e.reason.c_str());
        }
        if (!gConciseEnabled)
        {
            std::fprintf(gOut, "tid=%u seq=%llu mod=%s %s %s | %s\n",
                (unsigned)e.tid, (unsigned long long)e.seq, e.mod.c_str(), Hex(e.rip).c_str(), e.dis.c_str(), e.reason.c_str());
        }
    }
    // For JSON output everything goes.
    if (gOutJson) {
        std::fprintf(gOutJson, "{\"kind\":\"trigger\",\"seq\":%llu,\"tid\":%u,\"rip\":\"%s\",\"mod\":\"%s\",\"rva\":\"%s\",\"dis\":\"%s\",\"reason\":\"%s\"}\n",
            (unsigned long long)e.seq, (unsigned)e.tid, Hex(e.rip).c_str(), modEsc.c_str(), Hex(e.rva).c_str(), disEsc.c_str(), reasonEsc.c_str());
    }
    PIN_ReleaseLock(&gLock);
}

static void DumpWindow(ThreadState* st) {
    if (!st || !gUseRing) return;
    UINT32 count = st->filled ? gRingSize : st->next;
    UINT32 start = st->filled ? st->next : 0;
    for (UINT32 i = 0; i < count; ++i) {
        WriteEntry(st->ring[(start + i) % gRingSize]);
    }
}

static void LogSemanticAlert(THREADID tid, ADDRINT rip, const std::string& reason) {
    ThreadState* st = GetToolThreadState(tid);
    InstEntry e;
    e.seq = ++gSeqCounter;
    e.tid = tid;
    e.rip = rip;
    e.reason = reason;
    auto it = gStaticByRip.find(rip);
    if (it != gStaticByRip.end()) {
        e.dis = it->second.dis;
        e.mod = it->second.mod;
        e.rva = it->second.rva;
    }
    ExportAntiAnalysisWitness(tid, rip, reason);
    DispatchEntry(st, e);
}

static void NoteTimingProbe(THREADID tid, ADDRINT rip, const std::string& source) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->gateOpen) return;

    if (st->lastTimingProbeRip == rip) st->timingProbeStreak++;
    else {
        st->lastTimingProbeRip = rip;
        st->timingProbeStreak = 1;
    }

    if (st->timingProbeStreak == 16 || (st->timingProbeStreak > 16 && (st->timingProbeStreak % 16) == 0)) {
        LogSemanticAlert(tid, rip, "ANTI_TIMING_LOOP <source: " + source +
            " streak: " + std::to_string(st->timingProbeStreak) + ">");
    }
}