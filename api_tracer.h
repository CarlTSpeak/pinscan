#ifndef PINSCAN_API_TRACER_H
#define PINSCAN_API_TRACER_H

#include "pinscan_globals.h"
#include "utils.h"
#include <string>

// Handle Tracking
std::string LookupHandleType(ADDRINT handle);
void TrackHandleType(ADDRINT handle, const std::string& type);
void ForgetHandleType(ADDRINT handle);

// Analysis Helpers
std::string GetTriggerModule(ADDRINT addr);
std::string GetAntiAnalysisTag(const std::string& funcName, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3);

// Callbacks
void RecordDllMainEntry(ADDRINT rip, THREADID tid);
void RecordSyscallBefore(THREADID tid, ADDRINT rip, const CONTEXT* ctxt);
void OnApiCall(THREADID tid, ADDRINT sourceRip, ADDRINT targetAddr,
    ADDRINT srcLowAddr, ADDRINT srcHighAddr,
    ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT rsp, BOOL isRet);

#endif // PINSCAN_API_TRACER_H