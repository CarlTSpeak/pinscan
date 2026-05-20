#ifndef PINSCAN_HEURISTICS_H
#define PINSCAN_HEURISTICS_H

void WriteEntry(const InstEntry& e); // Required external dependency for squelcher

void ManageLoopState(ThreadState* st, ADDRINT rip);

// Exposing internal helpers needed by the classifier
int GprMaskIndex(REG reg);
UINT32 BuildGprReadMask(INS ins);
UINT32 BuildGprWriteMask(INS ins);
bool IsNearStackPointer(ADDRINT rsp, ADDRINT addr, UINT32 size);

#endif // PINSCAN_HEURISTICS_H