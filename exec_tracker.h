#ifndef PINSCAN_EXEC_TRACKER_H
#define PINSCAN_EXEC_TRACKER_H

#include "utils.h"
#include "telemetry.h"
#include <string>

// Memory State & Identification
void InvalidatePageMetadataRange(ADDRINT base, ADDRINT size);
void GetMemInfo(ADDRINT rip, std::string& outType, ADDRINT& outBase);
bool CheckHiddenExecutableMzRegionCached(ADDRINT addr, std::string& outReason, bool allowRefresh);

// OS Allocations & Snapshots
VOID NtAllocateEntry(THREADID tid, ADDRINT* pBaseAddress, size_t* pRegionSize);
VOID NtAllocateExit(THREADID tid, ADDRINT status);
VOID ExecuteSnapshot(THREADID tid, const CONTEXT* ctxt, const char* prefix);

// SMC & Execution Tracking
void TrackExceptionResume(THREADID tid, ADDRINT rip);
void TrackExecutableWriteBefore(THREADID tid, ADDRINT rip, ADDRINT addr, UINT32 size);
void CheckFirstExecutionAfterWrite(THREADID tid, ADDRINT rip);
void NoteControlFlowIntoModifiedPage(THREADID tid, ADDRINT rip, ADDRINT target);

#endif // PINSCAN_EXEC_TRACKER_H