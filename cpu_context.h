#ifndef PINSCAN_CPU_CONTEXT_H
#define PINSCAN_CPU_CONTEXT_H

#include "telemetry.h"

// CPUID Context Tracking
enum CpuidRegMask : UINT32 {
    CPUID_REG_NONE = 0,
    CPUID_REG_RAX = 1u << 0,
    CPUID_REG_RBX = 1u << 1,
    CPUID_REG_RCX = 1u << 2,
    CPUID_REG_RDX = 1u << 3,
    CPUID_REG_ALL = CPUID_REG_RAX | CPUID_REG_RBX | CPUID_REG_RCX | CPUID_REG_RDX,
};

// Hardware and Timing Emulation
void CaptureReadTarget(THREADID tid, ADDRINT addr);
void SpoofSystemTime(THREADID tid, UINT32 regIdx, CONTEXT* ctxt);
void HandleRdtsc(THREADID tid, ADDRINT rip, CONTEXT* ctxt);
void RecordRdtscAfter(THREADID tid, ADDRINT rip, const CONTEXT* ctxt);

// CPUID Handling
void SaveCpuidInputs(THREADID tid, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx);
void ConfigureCpuidRewrite(bool enabled, UINT32 mask, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx);
void RecordCpuidAfter(THREADID tid, ADDRINT rip, UINT32 insSize, CONTEXT* ctxt);

#endif // PINSCAN_CPU_CONTEXT_H
