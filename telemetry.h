#ifndef PINSCAN_TELEMETRY_H
#define PINSCAN_TELEMETRY_H

#include "pinscan_globals.h"
#include <string>

void AppendJsonlLine(const std::string& path, const std::string& line);
std::string BuildMemObservationsJson(ADDRINT r1, UINT32 r1Size, ADDRINT r2, UINT32 r2Size, ADDRINT w1, UINT32 w1Size);
void ExportTriggerWitness(const InstEntry& e, ADDRINT r1, UINT32 r1Size, ADDRINT r2, UINT32 r2Size, ADDRINT w1, UINT32 w1Size);
void ExportControlFlowWitness(THREADID tid, ADDRINT rip, ADDRINT target, ADDRINT rsp, const CONTEXT* ctxt, const std::string& provenance);
void ExportStartupSnapshot(THREADID tid, const CONTEXT* ctxt, ADDRINT tebBase, ADDRINT pebBase);
void ExportMemoryEvent(const char* api, ADDRINT sourceRip, ADDRINT base, ADDRINT size, ADDRINT protect, const std::string& details);
void ExportAntiAnalysisWitness(THREADID tid, ADDRINT rip, const std::string& reason);
void WriteEntry(const InstEntry& e);
void DumpWindow(ThreadState* st);
void NoteTimingProbe(THREADID tid, ADDRINT rip, const std::string& source);
void LogSemanticAlert(THREADID tid, ADDRINT rip, const std::string& reason);

#endif // PINSCAN_TELEMETRY_H