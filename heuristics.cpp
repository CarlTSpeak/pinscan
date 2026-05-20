#include "pinscan_globals.h"
#include "heuristics.h"
#include <sstream>

int GprMaskIndex(REG reg) {
    REG full = REG_FullRegName(reg);
    switch (full) {
    case REG_GAX: return 0;
    case REG_GBX: return 1;
    case REG_GCX: return 2;
    case REG_GDX: return 3;
    case REG_GSI: return 4;
    case REG_GDI: return 5;
    case REG_GBP: return 6;
    case REG_R8:  return 7;
    case REG_R9:  return 8;
    case REG_R10: return 9;
    case REG_R11: return 10;
    case REG_R12: return 11;
    case REG_R13: return 12;
    case REG_R14: return 13;
    case REG_R15: return 14;
    case REG_STACK_PTR: return 15;
    default: return -1;
    }
}

UINT32 BuildGprReadMask(INS ins) {
    UINT32 mask = 0;
    for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); ++i) {
        int idx = GprMaskIndex(INS_RegR(ins, i));
        if (idx >= 0) mask |= (1u << idx);
    }
    return mask;
}

UINT32 BuildGprWriteMask(INS ins) {
    UINT32 mask = 0;
    for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); ++i) {
        int idx = GprMaskIndex(INS_RegW(ins, i));
        if (idx >= 0) mask |= (1u << idx);
    }
    return mask;
}

bool IsNearStackPointer(ADDRINT rsp, ADDRINT addr, UINT32 size) {
    if (addr == 0) return false;
    ADDRINT low = (rsp > 0x400) ? (rsp - 0x400) : 0;
    ADDRINT high = rsp + 0x800;
    ADDRINT end = addr + size;
    return end >= low && addr <= high;
}

void ManageLoopState(ThreadState* st, ADDRINT rip) {
    if (!st) return;

    if (!st->loopConfirmed) {
        if (st->lookbackBuffer.size() == gLoopWindowSize) {
            bool found = false;
            for (auto it = st->lookbackBuffer.begin(); it != st->lookbackBuffer.end(); ++it) {
                if (*it == rip) { found = true; break; }
            }

            if (found) {
                if (st->consecutiveMatches == 0) {
                    st->loopHeadRip = rip;
                }

                st->consecutiveMatches++;

                if (st->consecutiveMatches == 5) {
                    st->loopConfirmed = true;
                    st->iterationCount = 1;

                    InstEntry marker;
                    marker.seq = ++gSeqCounter; marker.tid = st->tid; marker.rip = rip;
                    marker.reason = "=== [LOOP LOCKED: Observation Phase Started] ===";
                    WriteEntry(marker);
                }
            }
            else {
                st->consecutiveMatches = 0;
            }
        }

        st->lookbackBuffer.push_back(rip);
        if (st->lookbackBuffer.size() > gLoopWindowSize) {
            st->lookbackBuffer.pop_front();
        }
    }
    else {
        bool inWorkingSet = false;
        for (auto it = st->lookbackBuffer.begin(); it != st->lookbackBuffer.end(); ++it) {
            if (*it == rip) { inWorkingSet = true; break; }
        }

        if (!inWorkingSet) {
            if (st->loopSquelchActive) {
                for (const auto& shadowEntry : st->shadowBuffer) {
                    WriteEntry(shadowEntry);
                }

                InstEntry marker;
                marker.seq = ++gSeqCounter; marker.tid = st->tid; marker.rip = rip;
                std::ostringstream oss;
                oss << "=== [LOOP EXITED: Executed " << std::dec << st->iterationCount << " times] ===";
                marker.reason = oss.str();
                WriteEntry(marker);
            }

            st->loopConfirmed = false;
            st->loopSquelchActive = false;
            st->consecutiveMatches = 0;
            st->iterationCount = 0;
            st->lookbackBuffer.clear();
            st->lookbackBuffer.push_back(rip); 
            st->shadowBuffer.clear();
        }
        else {
            if (rip == st->loopHeadRip) {
                st->iterationCount++;

                if (st->iterationCount == 4) {
                    st->loopSquelchActive = true;

                    InstEntry marker;
                    marker.seq = ++gSeqCounter; marker.tid = st->tid; marker.rip = rip;
                    marker.reason = "=== [LOOP SUPPRESSION ACTIVE: Silencing Middle Iterations] ===";
                    WriteEntry(marker);
                }

                if (st->loopSquelchActive) {
                    st->shadowBuffer.clear();
                }
            }
        }
    }
}