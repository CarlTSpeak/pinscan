#include "api_tracer.h"
#include <string>
#include <sstream>
#include <iomanip>

// --- External Dependencies (Currently living in pinscan.cpp) ---
extern void DispatchEntry(ThreadState* st, const InstEntry& e);
extern void DumpWindow(ThreadState* st);
extern void ExportMemoryEvent(const char* api, ADDRINT sourceRip, ADDRINT base, ADDRINT size, ADDRINT protect, const std::string& details);
extern void ExportAntiAnalysisWitness(THREADID tid, ADDRINT rip, const std::string& reason);
extern void InvalidatePageMetadataRange(ADDRINT base, ADDRINT size);
extern void NoteTimingProbe(THREADID tid, ADDRINT rip, const std::string& source);
extern ThreadState* GetToolThreadState(THREADID tid);
// ---------------------------------------------------------------

std::string LookupHandleType(ADDRINT handle) {
    if (handle == 0 || handle == (ADDRINT)-1) return "";
    PIN_GetLock(&g_HandleMapLock, 0);
    auto it = gHandleTypeMap.find(handle);
    std::string result = (it != gHandleTypeMap.end()) ? it->second : "";
    PIN_ReleaseLock(&g_HandleMapLock);
    return result;
}

void TrackHandleType(ADDRINT handle, const std::string& type) {
    if (handle == 0 || handle == (ADDRINT)-1 || type.empty()) return;
    PIN_GetLock(&g_HandleMapLock, 0);
    gHandleTypeMap[handle] = type;
    PIN_ReleaseLock(&g_HandleMapLock);
}

void ForgetHandleType(ADDRINT handle) {
    if (handle == 0 || handle == (ADDRINT)-1) return;
    PIN_GetLock(&g_HandleMapLock, 0);
    gHandleTypeMap.erase(handle);
    PIN_ReleaseLock(&g_HandleMapLock);
}

std::string GetTriggerModule(ADDRINT addr) {
    PIN_LockClient();
    IMG img = IMG_FindByAddress(addr);
    std::string result = "non_image";
    if (IMG_Valid(img)) {
        std::string full = IMG_Name(img);
        size_t slash = full.find_last_of("\\/");
        std::string modName = (slash != std::string::npos) ? full.substr(slash + 1) : full;
        ADDRINT rva = addr - IMG_StartAddress(img);
        std::string symName;
        RTN rtn = RTN_FindByAddress(addr);
        if (RTN_Valid(rtn)) {
            symName = RTN_Name(rtn);
            symName = PIN_UndecorateSymbolName(symName, UNDECORATION_NAME_ONLY);
            ADDRINT symOffset = addr - RTN_Address(rtn);
            if (symOffset > 0) { std::ostringstream oss; oss << "+" << std::hex << symOffset; symName += oss.str(); }
        }
        std::ostringstream oss; oss << modName << "+" << Hex(rva);
        if (!symName.empty()) oss << " (" << symName << ")";
        result = oss.str();
    }
    PIN_UnlockClient();
    return result;
}

std::string GetAntiAnalysisTag(const std::string& funcName, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3) {
    (void)arg2;
    (void)arg3;
    if (funcName.find("IsDebuggerPresent") != std::string::npos) return "DebuggerPresenceProbe";
    if (funcName.find("CheckRemoteDebuggerPresent") != std::string::npos) return "RemoteDebuggerProbe";
    if (funcName.find("OutputDebugString") != std::string::npos) return "OutputDebugProbe";
    if (funcName.find("FindWindow") != std::string::npos) return "WindowProbe";
    if (funcName.find("SetUnhandledExceptionFilter") != std::string::npos ||
        funcName.find("VectoredExceptionHandler") != std::string::npos) return "ExceptionHandlerManipulation";
    if (funcName.find("GetTickCount") != std::string::npos ||
        funcName.find("QueryPerformanceCounter") != std::string::npos ||
        funcName.find("GetSystemTimeAsFileTime") != std::string::npos ||
        funcName.find("timeGetTime") != std::string::npos) return "TimingProbe";
    if (funcName.find("NtSetInformationThread") != std::string::npos ||
        funcName.find("ZwSetInformationThread") != std::string::npos) {
        if (arg1 == 0x11) return "ThreadHideFromDebugger";
    }
    if (funcName.find("NtQueryInformationProcess") != std::string::npos) {
        if (arg1 == 7 || arg1 == 0x1E || arg1 == 0x1F) return "ProcessDebugProbe";
    }
    if (funcName.find("NtQuerySystemInformation") != std::string::npos ||
        funcName.find("ZwQuerySystemInformation") != std::string::npos) {
        if (arg0 == 0x23 || arg0 == 0x24 || arg0 == 0x67) return "KernelDebuggerProbe";
    }
    if (funcName.find("GetThreadContext") != std::string::npos ||
        funcName.find("Wow64GetThreadContext") != std::string::npos) return "ThreadContextProbe";
    if (funcName.find("SetThreadContext") != std::string::npos) return "ThreadContextWrite";
    if (funcName.find("CreateToolhelp32Snapshot") != std::string::npos ||
        funcName.find("Process32First") != std::string::npos ||
        funcName.find("Process32Next") != std::string::npos ||
        funcName.find("Thread32First") != std::string::npos ||
        funcName.find("Thread32Next") != std::string::npos ||
        funcName.find("Module32First") != std::string::npos ||
        funcName.find("Module32Next") != std::string::npos ||
        funcName.find("EnumProcesses") != std::string::npos) return "ProcessEnumerationProbe";
    if (funcName.find("VirtualQuery") != std::string::npos ||
        funcName.find("NtQueryVirtualMemory") != std::string::npos ||
        funcName.find("ZwQueryVirtualMemory") != std::string::npos) return "MemoryLayoutProbe";
    return "";
}

void RecordDllMainEntry(ADDRINT rip, THREADID tid) {
    std::string modName = "unknown";

    PIN_GetLock(&g_EpLock, 1);
    auto it = g_DllEntryPoints.find(rip);
    if (it != g_DllEntryPoints.end()) {
        modName = it->second;
    }
    PIN_ReleaseLock(&g_EpLock);

    if (gOut) {
        fprintf(gOut, "tid=%d mod=%s 0x%lx | PRE-DLLMAIN_START\n", tid, modName.c_str(), rip);
    }
}

void RecordSyscallBefore(THREADID tid, ADDRINT rip, const CONTEXT* ctxt) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->gateOpen) return;

    ADDRINT rax = PIN_GetContextReg(ctxt, REG_GAX);
    ADDRINT r10 = PIN_GetContextReg(ctxt, REG_R10);
    ADDRINT rdx = PIN_GetContextReg(ctxt, REG_GDX);
    ADDRINT r8 = PIN_GetContextReg(ctxt, REG_R8);
    ADDRINT r9 = PIN_GetContextReg(ctxt, REG_R9);

    ADDRINT rsp = PIN_GetContextReg(ctxt, REG_STACK_PTR);
    ADDRINT retAddr = 0;
    PIN_SafeCopy(&retAddr, (VOID*)rsp, sizeof(retAddr));
    std::string callerMod = GetTriggerModule(retAddr);

    std::string name = "unknown_syscall";
    auto it = gSyscallNames.find(rax);
    if (it != gSyscallNames.end()) name = it->second;

    InstEntry se; se.seq = ++gSeqCounter; se.tid = tid; se.rip = rip;
    auto sit = gStaticByRip.find(rip);
    if (sit != gStaticByRip.end()) { se.dis = sit->second.dis; se.mod = sit->second.mod; se.rva = sit->second.rva; }
    else { se.dis = "syscall"; se.mod = "ntdll"; }

    std::ostringstream oss;
    oss << "syscall " << name << " (0x" << std::hex << rax << ") <args: "
        << Hex(r10) << ", " << Hex(rdx) << ", " << Hex(r8) << ", " << Hex(r9) << "> caller: " << callerMod;
    se.reason = oss.str();

    DispatchEntry(st, se);
    if (gUseRing) { DumpWindow(st); st->dumping = true; st->postRemaining = gPostFollow; }
}

static void OnApiCall(THREADID tid, ADDRINT sourceRip, ADDRINT targetAddr,
    ADDRINT srcLowAddr, ADDRINT srcHighAddr,
    ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT rsp, BOOL isRet) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->gateOpen) return;

    // 1. FAST EXIT: Local calls
    if (srcLowAddr != 0 && targetAddr >= srcLowAddr && targetAddr <= srcHighAddr) {
        return;
    }

    std::fprintf(gOut, "API call passed fast exit at 0x%llx\n", targetAddr);

    // 2. Cache Lookup
    PIN_GetLock(&g_ApiCacheLock, (tid + 1));
    auto it = g_ApiCache.find(targetAddr);
    bool isNew = (it == g_ApiCache.end());
    std::string funcName;
    if (!isNew) funcName = it->second;
    PIN_ReleaseLock(&g_ApiCacheLock);

    // 3. Resolve Symbol (Only on first encounter)
    if (isNew) {
		std::fprintf(gOut, "Attempting to resolve new API at 0x%llx\n", targetAddr);
        PIN_LockClient();
        funcName = "unknown_extern";
        IMG img = IMG_FindByAddress(targetAddr);

        if (IMG_Valid(img)) {
            std::string imgName = IMG_Name(img);
            size_t slash = imgName.find_last_of("\\/");
            if (slash != std::string::npos) imgName = imgName.substr(slash + 1);
            std::transform(imgName.begin(), imgName.end(), imgName.begin(), [](unsigned char c) { return std::tolower(c); });

            RTN rtn = RTN_FindByAddress(targetAddr);
            if (RTN_Valid(rtn)) {
                std::string sym = RTN_Name(rtn);
                sym = PIN_UndecorateSymbolName(sym, UNDECORATION_NAME_ONLY);
                funcName = imgName + "!" + sym;
            }
            else {
                funcName = imgName + "+offset";
            }
        }
        else {
            funcName = "dynamic_code";
        }

        if (isRet) {
            bool isCleanSymbol = (funcName.find("!") != std::string::npos && funcName.find("+") == std::string::npos);
            if (!isCleanSymbol) {
                funcName = "IGNORE";
                std::fprintf(gOut, "Dirty symbol detected at 0x%llx\n", targetAddr);
            }
        }

        // Noise Filter
        if (funcName.find("CriticalSection") != std::string::npos || // Covers RtlEnter/Leave, Init, Delete
            // funcName.find("LastError") != std::string::npos ||       // Covers GetLastError, SetLastError
            funcName.find("codePointer") != std::string::npos ||     // Covers RtlEncodePointer, RtlDecodePointer
            funcName.find("lsGetValue") != std::string::npos ||      // Covers TlsGetValue, FlsGetValue
            funcName.find("lsSetValue") != std::string::npos ||      // Covers TlsSetValue, FlsSetValue
            funcName.find("ListHead") != std::string::npos ||        // Covers RtlInitializeSListHead
            funcName.find("Sleep") != std::string::npos ||           // Covers Sleep, SleepEx)

            // Memory & Heap
            funcName.find("Heap") != std::string::npos ||            // Covers HeapAlloc, HeapFree, RtlAllocateHeap
            funcName.find("!mem") != std::string::npos ||            // Covers !memcpy, !memset, !memmove

            // String Comparisons
            funcName.find("strcmp") != std::string::npos ||          // Covers lstrcmp, strcmp, strcmpi
            funcName.find("wcscmp") != std::string::npos ||          // Covers wcscmp
            funcName.find("stricmp") != std::string::npos ||          // Covers _stricmp
            funcName.find("RtlTimeToSecondsSince1970") != std::string::npos) // Basic entropy generation: spammy
        {
            funcName = "IGNORE";
        }
        PIN_GetLock(&g_ApiCacheLock, 1);
        g_ApiCache[targetAddr] = funcName;
        PIN_ReleaseLock(&g_ApiCacheLock);
        PIN_UnlockClient();
    }

    // 4. Logging & Argument Parsing
    if (funcName != "IGNORE") {

        if (funcName == "dynamic_code" && srcLowAddr == 0) {
            return;
        }

        InstEntry ae;
        ae.seq = ++gSeqCounter;
        ae.tid = tid;
        ae.rip = sourceRip;

        auto sit = gStaticByRip.find(sourceRip);
        if (sit != gStaticByRip.end()) { ae.dis = sit->second.dis; ae.mod = sit->second.mod; ae.rva = sit->second.rva; }

        std::string details = "";
        std::string memoryEventApi;
        ADDRINT memoryEventBase = 0;
        ADDRINT memoryEventSize = 0;
        ADDRINT memoryEventProtect = 0;
        auto handleNote = [&](ADDRINT handle) -> std::string {
            std::string type = LookupHandleType(handle);
            return type.empty() ? "" : (" TYPE: " + type);
            };

        // --- THE NEW LOGIC: Check name and decode args ---
        if (funcName.find("GetProcAddress") != std::string::npos) {
            // Arg1 is lpProcName (ASCII)
            if (arg1 > 0xFFFF) details = " <FUNC: " + GetAsciiString(arg1) + ">";
            else details = " <ORDINAL: " + Hex(arg1) + ">";
        }
        else if (funcName.find("LoadLibrary") != std::string::npos) {
            // Arg0 is lpFileName (Check 'W' vs 'A' suffix usually, but try Wide first)
            if (funcName.back() == 'A') details = " <PATH: " + GetAsciiString(arg0) + ">";
            else details = " <PATH: " + GetWideString(arg0) + ">";
        }
        else if (funcName.find("RegQueryValue") != std::string::npos) {
            // Arg1 is lpValueName
            details = " <KEY: " + GetWideString(arg1) + ">";
        }
        else if (funcName.find("FindWindow") != std::string::npos) {
            // Arg1 is lpWindowName
            details = " <WINDOW: " + GetWideString(arg1) + ">";
        }
        else if (funcName.find("NtQueryInformationProcess") != std::string::npos) {
            TrackHandleType(arg0, "process");
            // Arg1 is ProcessInformationClass (Integer)
            if (arg1 == 7) details = " <CHECK: DebugPort>";
            else if (arg1 == 0x1E) details = " <CHECK: DebugObject>";
            else if (arg1 == 0x1F) details = " <CHECK: DebugFlags>";
            if (!details.empty()) {
                details.pop_back();
                details += " HANDLE: " + Hex(arg0) + handleNote(arg0) + ">";
            }
        }
        else if (funcName.find("VirtualAlloc") != std::string::npos) {
            // VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
            // Arg0: Address, Arg1: Size, Arg3 (R9): flProtect
            std::ostringstream oss;
            oss << " <ADDR: " << Hex(arg0)
                << " SIZE: " << Hex(arg1)
                << " PROT: " << DecodeProt(arg3) // Uses R9
                << ">";
            details = oss.str();
            if (arg0 != 0 && arg1 != 0) InvalidatePageMetadataRange(arg0, arg1);
            memoryEventApi = "VirtualAlloc";
            memoryEventBase = arg0;
            memoryEventSize = arg1;
            memoryEventProtect = arg3;
        }
        else if (funcName.find("VirtualProtect") != std::string::npos) {
            // VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
            // Arg0 (RCX): Address (Value, not a pointer)
            // Arg1 (RDX): Size (Value, not a pointer)
            // Arg2 (R8):  flNewProtect

            std::ostringstream oss;
            oss << " <ADDR: " << Hex(arg0)
                << " SIZE: " << Hex(arg1)
                << " NEW_PROT: " << DecodeProt(arg2) // Uses R8
                << ">";

            // --- THE UNPACKER TRIGGER ---
            // Check if the new protection includes EXECUTE (0x10, 0x20, 0x40, 0x80)
            bool isExecutable = (arg2 == 0x10 || arg2 == 0x20 || arg2 == 0x40 || arg2 == 0x80);

            if (isExecutable && arg0 != 0 && arg1 > 0 && arg1 < 0x10000000) {
                // Cap dump size to 256MB to prevent malicious massive size crashes

                std::string dumpName = "payload_vp_" + Hex(arg0) + ".bin";
                FILE* dumpFile = fopen(dumpName.c_str(), "wb");
                if (dumpFile) {
                    std::vector<UINT8> buffer(arg1);
                    // Use PIN_SafeCopy so we don't crash if the DRM lies about the size
                    size_t bytesRead = PIN_SafeCopy(buffer.data(), (void*)arg0, arg1);
                    fwrite(buffer.data(), 1, bytesRead, dumpFile);
                    fclose(dumpFile);

                    oss << " [!!! PAYLOAD DUMPED: " << std::dec << bytesRead << " bytes to " << dumpName << " !!!]";
                }
                else {
                    oss << " [!!! DUMP FAILED: Could not open file !!!]";
                }
            }

            details = oss.str();
            if (arg0 != 0 && arg1 != 0) InvalidatePageMetadataRange(arg0, arg1);
            memoryEventApi = "VirtualProtect";
            memoryEventBase = arg0;
            memoryEventSize = arg1;
            memoryEventProtect = arg2;
        }
        else if (funcName.find("NtAllocateVirtualMemory") != std::string::npos ||
            funcName.find("ZwAllocateVirtualMemory") != std::string::npos) {

            ADDRINT requestedBase = 0;
            ADDRINT requestedSize = 0;
            ADDRINT allocType = 0;
            ADDRINT protect = 0;

            // --- THE FIX: Adjust for Push/Ret offset ---
            // A standard CALL places Arg5 at +0x20. A PUSH/RET pushes the target address 
            // and often a fake return address, shifting the arguments down by 0x10.
            ADDRINT stackOffset = isRet ? 0x30 : 0x20;

            PIN_SafeCopy(&requestedBase, (void*)arg1, sizeof(ADDRINT));
            PIN_SafeCopy(&requestedSize, (void*)arg3, sizeof(ADDRINT));
            PIN_SafeCopy(&allocType, (void*)(rsp + stackOffset), sizeof(ADDRINT));
            PIN_SafeCopy(&protect, (void*)(rsp + stackOffset + 0x8), sizeof(ADDRINT));

            std::ostringstream oss;
            oss << " <BASE_PTR: " << Hex(arg1) << " (*val=" << Hex(requestedBase) << ")"
                << " SIZE_PTR: " << Hex(arg3) << " (*val=" << Hex(requestedSize) << ")"
                << " ALLOC_TYPE: " << Hex(allocType)
                << " PROT: " << DecodeProt(protect) << ">";
            details = oss.str();
            if (requestedBase != 0 && requestedSize != 0) InvalidatePageMetadataRange(requestedBase, requestedSize);
            memoryEventApi = "NtAllocateVirtualMemory";
            memoryEventBase = requestedBase;
            memoryEventSize = requestedSize;
            memoryEventProtect = protect;
        }

        // --- NATIVE PROTECTION FLIPS (Execution Prep) ---
        // --- NATIVE PROTECTION FLIPS (Execution Prep & Automated Dumping) ---
        else if (funcName.find("NtProtectVirtualMemory") != std::string::npos ||
            funcName.find("ZwProtectVirtualMemory") != std::string::npos) {
            // Arg0 (RCX): ProcessHandle
            // Arg1 (RDX): PVOID *BaseAddress
            // Arg2 (R8):  PSIZE_T NumberOfBytesToProtect
            // Arg3 (R9):  ULONG NewAccessProtection

            ADDRINT targetBase = 0;
            ADDRINT targetSize = 0;

            // Safely dereference the pointers
            PIN_SafeCopy(&targetBase, (void*)arg1, sizeof(ADDRINT));
            PIN_SafeCopy(&targetSize, (void*)arg2, sizeof(ADDRINT));

            std::ostringstream oss;
            oss << " <BASE_PTR: " << Hex(arg1) << " (*val=" << Hex(targetBase) << ")"
                << " SIZE_PTR: " << Hex(arg2) << " (*val=" << Hex(targetSize) << ")"
                << " NEW_PROT: " << DecodeProt(arg3) << ">";

            // --- THE UNPACKER TRIGGER ---
            // Check if the new protection includes EXECUTE (0x10, 0x20, 0x40, 0x80)
            bool isExecutable = (arg3 == 0x10 || arg3 == 0x20 || arg3 == 0x40 || arg3 == 0x80);

            if (isExecutable && targetBase != 0 && targetSize > 0 && targetSize < 0x10000000) {
                // Cap dump size to 256MB to prevent malicious massive size crashes

                std::string dumpName = "payload_" + Hex(targetBase) + ".bin";
                FILE* dumpFile = fopen(dumpName.c_str(), "wb");
                if (dumpFile) {
                    std::vector<UINT8> buffer(targetSize);
                    // Use PIN_SafeCopy so we don't crash if the DRM lies about the size
                    size_t bytesRead = PIN_SafeCopy(buffer.data(), (void*)targetBase, targetSize);
                    fwrite(buffer.data(), 1, bytesRead, dumpFile);
                    fclose(dumpFile);

                    oss << " [!!! PAYLOAD DUMPED: " << std::dec << bytesRead << " bytes to " << dumpName << " !!!]";
                }
                else {
                    oss << " [!!! DUMP FAILED: Could not open file !!!]";
                }
            }

            details = oss.str();
            if (targetBase != 0 && targetSize != 0) InvalidatePageMetadataRange(targetBase, targetSize);
            memoryEventApi = "NtProtectVirtualMemory";
            memoryEventBase = targetBase;
            memoryEventSize = targetSize;
            memoryEventProtect = arg3;
        }
        // --- SECTION VIEW MAPPING (Stealth Allocation / Injection) ---
        else if (funcName.find("NtMapViewOfSection") != std::string::npos ||
            funcName.find("ZwMapViewOfSection") != std::string::npos) {
            TrackHandleType(arg0, "section");
            // Arg0 (RCX): SectionHandle
            // Arg1 (RDX): ProcessHandle (0xFFFFFFFFFFFFFFFF / -1 means local process)
            // Arg2 (R8):  PVOID *BaseAddress
            // Stack[0x48]: ULONG Protect (9th argument, so RSP + 0x48)
            // Stack[0x38]: PSIZE_T ViewSize (7th argument, RSP + 0x38)

            ADDRINT processHandle = arg1;
            ADDRINT targetBase = 0;
            ADDRINT viewSize = 0;
            ADDRINT protect = 0;

            // Safely read the pointers and stack arguments
            PIN_SafeCopy(&targetBase, (void*)arg2, sizeof(ADDRINT));
            PIN_SafeCopy(&viewSize, (void*)(rsp + 0x38), sizeof(ADDRINT));

            // The size argument is a pointer, dereference it to get the actual size
            ADDRINT actualSize = 0;
            if (viewSize != 0) PIN_SafeCopy(&actualSize, (void*)viewSize, sizeof(ADDRINT));

            PIN_SafeCopy(&protect, (void*)(rsp + 0x48), sizeof(ADDRINT));

            std::string procTarget = (processHandle == (ADDRINT)-1) ? "LOCAL" : "REMOTE (" + Hex(processHandle) + ")";

            std::ostringstream oss;
            oss << " <SECTION: " << Hex(arg0) << handleNote(arg0)
                << " TARGET: " << procTarget
                << " BASE_PTR: " << Hex(arg2) << " (*val=" << Hex(targetBase) << ")"
                << " SIZE: " << Hex(actualSize)
                << " PROT: " << DecodeProt(protect) << ">";

            // --- THE UNPACKER TRIGGER ---
            bool isExecutable = (protect == 0x10 || protect == 0x20 || protect == 0x40 || protect == 0x80);

            if (isExecutable && targetBase != 0 && actualSize > 0 && actualSize < 0x10000000) {
                std::string dumpName = "payload_map_" + Hex(targetBase) + ".bin";
                FILE* dumpFile = fopen(dumpName.c_str(), "wb");
                if (dumpFile) {
                    std::vector<UINT8> buffer(actualSize);
                    size_t bytesRead = PIN_SafeCopy(buffer.data(), (void*)targetBase, actualSize);
                    fwrite(buffer.data(), 1, bytesRead, dumpFile);
                    fclose(dumpFile);
                    oss << " [!!! MAPPED PAYLOAD DUMPED: " << dumpName << " !!!]";
                }
            }
            details = oss.str();
            if (targetBase != 0 && actualSize != 0) InvalidatePageMetadataRange(targetBase, actualSize);
            memoryEventApi = "NtMapViewOfSection";
            memoryEventBase = targetBase;
            memoryEventSize = actualSize;
            memoryEventProtect = protect;
        }
        else if (funcName.find("OpenProcess") != std::string::npos) {
            // OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
            // Arg0 (RCX): dwDesiredAccess
            // Arg1 (RDX): bInheritHandle
            // Arg2 (R8):  dwProcessId

            std::ostringstream oss;
            oss << " <PID: " << std::dec << arg2 << " (0x" << std::hex << arg2 << ")"
                << " ACCESS: " << Hex(arg0)
                << " INHERIT: " << (arg1 ? "TRUE" : "FALSE")
                << ">";
            details = oss.str();
        }
        // --- CRYPTO NEXT GENERATION (CNG) HOOKS ---
        else if (funcName.find("BCryptHashData") != std::string::npos) {
            TrackHandleType(arg0, "bcrypt_hash");
            // BCryptHashData(hHash, pbInput, cbInput, dwFlags)
            // Logs what is currently being hashed
            std::ostringstream oss;
            oss << " <HASH_HANDLE: " << Hex(arg0)
                << handleNote(arg0)
                << " IN_BUF: " << Hex(arg1)
                << " IN_SIZE: " << std::dec << arg2 << ">";
            details = oss.str();
        }
        else if (funcName.find("BCryptFinishHash") != std::string::npos) {
            TrackHandleType(arg0, "bcrypt_hash");
            // BCryptFinishHash(hHash, pbOutput, cbOutput, dwFlags)
            // Arg1 (RDX): pbOutput
            // Arg2 (R8): cbOutput

            // COMMAND: Taint the resulting Hash

            std::ostringstream oss;
            oss << " <HASH_HANDLE: " << Hex(arg0)
                << handleNote(arg0)
                << " OUT_BUF: " << Hex(arg1)
                << " OUT_SIZE: " << std::dec << arg2 << ">";
            details = oss.str();
        }
        else if (funcName.find("BCryptDecrypt") != std::string::npos) {
            TrackHandleType(arg0, "bcrypt_key");
            // BCryptDecrypt has 10 arguments. We need Arg 7 (pbOutput) and Arg 8 (cbOutput).
            // RSP points to the Return Address.
            // RSP + 0x08 to 0x20 is the 32-byte Shadow Space.
            // RSP + 0x28 = Arg 5 (pbIV)
            // RSP + 0x30 = Arg 6 (cbIV)
            // RSP + 0x38 = Arg 7 (pbOutput)
            // RSP + 0x40 = Arg 8 (cbOutput)

            ADDRINT pbOutput = 0;
            ADDRINT cbOutput = 0;

            // Safely read the arguments off the stack
            PIN_SafeCopy(&pbOutput, (void*)(rsp + 0x38), sizeof(ADDRINT));
            PIN_SafeCopy(&cbOutput, (void*)(rsp + 0x40), sizeof(ADDRINT));

            std::ostringstream oss;
            oss << " <KEY_HANDLE: " << Hex(arg0)
                << handleNote(arg0)
                << " IN_BUF: " << Hex(arg1)     // Ciphertext buffer
                << " IN_SIZE: " << std::dec << arg2
                << " OUT_BUF: " << Hex(pbOutput) // Plaintext buffer
                << " OUT_SIZE: " << std::dec << cbOutput << ">";
            details = oss.str();
        }
        else if (funcName.find("CreateToolhelp32Snapshot") != std::string::npos) {
            // CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
            // Arg0 (RCX): dwFlags
            // Arg1 (RDX): th32ProcessID

            std::string flagStr = "";
            if (arg0 & 0x00000001) flagStr += "HEAPLIST|";
            if (arg0 & 0x00000002) flagStr += "PROCESS|";
            if (arg0 & 0x00000004) flagStr += "THREAD|";
            if (arg0 & 0x00000008) flagStr += "MODULE|";
            if (arg0 & 0x00000010) flagStr += "MODULE32|";
            if (arg0 & 0x80000000) flagStr += "INHERIT|";
            if (!flagStr.empty()) flagStr.pop_back(); // Remove trailing pipe

            std::ostringstream oss;
            oss << " <FLAGS: " << Hex(arg0) << " (" << flagStr << ")"
                << " PID: " << std::dec << arg1 << " (0x" << std::hex << arg1 << ")"
                << ">";
            details = oss.str();
        }
        else if (funcName.find("GetThreadContext") != std::string::npos ||
            funcName.find("Wow64GetThreadContext") != std::string::npos ||
            funcName.find("SetThreadContext") != std::string::npos) {
            UINT32 contextFlags = 0;
            if (arg1 != 0) PIN_SafeCopy(&contextFlags, (void*)arg1, sizeof(contextFlags));

            std::ostringstream oss;
            oss << " <THREAD: " << Hex(arg0)
                << " CTX_PTR: " << Hex(arg1)
                << " FLAGS: " << Hex(contextFlags);
            if (contextFlags & 0x10) oss << " DEBUG_REGS";
            if (contextFlags & 0x100001) oss << " CONTROL";
            oss << ">";
            details = oss.str();
        }
        else if (funcName.find("CreateFile") != std::string::npos) {
            // CreateFile(lpFileName, dwDesiredAccess, ...)
            // Arg0 (RCX): lpFileName
            // Arg1 (RDX): dwDesiredAccess
            bool isWide = (funcName.back() == 'W');
            std::string path = isWide ? GetWideString(arg0) : GetAsciiString(arg0);

            std::string accessStr;
            if (arg1 & 0x80000000) accessStr += "R"; // Generic Read
            if (arg1 & 0x40000000) accessStr += "W"; // Generic Write
            if (accessStr.empty()) accessStr = Hex(arg1);

            details = " <PATH: " + path + " ACCESS: " + accessStr + ">";
        }
        else if (funcName.find("CreateNamedPipe") != std::string::npos) {
            // CreateNamedPipe(lpName, dwOpenMode, dwPipeMode, ...)
            // Arg0 (RCX): lpName
            // Arg1 (RDX): dwOpenMode (Inbound/Outbound/Duplex)
            // Arg2 (R8):  dwPipeMode (Byte/Message)

            bool isWide = (funcName.back() == 'W');
            std::string name = isWide ? GetWideString(arg0) : GetAsciiString(arg0);

            std::ostringstream oss;
            oss << " <NAME: " << name
                << " OPEN_MODE: " << Hex(arg1)
                << " PIPE_MODE: " << Hex(arg2)
                << ">";
            details = oss.str();
        }
        else if (funcName.find("CreatePipe") != std::string::npos) {
            // CreatePipe(phReadPipe, phWritePipe, lpPipeAttributes, nSize)
            // Arg0 (RCX): Pointer to receive Read Handle
            // Arg1 (RDX): Pointer to receive Write Handle
            // Arg3 (R9):  nSize (Suggested Buffer Size)

            std::ostringstream oss;
            oss << " <PTR_READ: " << Hex(arg0)
                << " PTR_WRITE: " << Hex(arg1)
                << " SIZE: " << std::dec << arg3
                << ">";
            details = oss.str();
        }
        // --- NEW: Memory Mapping (Denuvo Trigger Loading) ---
        else if (funcName.find("MapViewOfFile") != std::string::npos) {
            TrackHandleType(arg0, "file_mapping");
            // MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)
            // Arg0 (RCX): Handle
            // Arg1 (RDX): Access
            // Arg2 (R8):  OffsetHigh

            std::ostringstream oss;
            oss << " <HANDLE: " << Hex(arg0)
                << handleNote(arg0)
                << " OFFSET_HI: " << Hex(arg2)
                << ">";
            details = oss.str();
        }
        // --- NEW: Hardware ID Checks ---
        else if (funcName.find("GetVolumeInformation") != std::string::npos) {
            // GetVolumeInformation(lpRootPathName, ...)
            // Arg0 (RCX): Root Path
            bool isWide = (funcName.back() == 'W');
            std::string root = isWide ? GetWideString(arg0) : GetAsciiString(arg0);
            details = " <ROOT: " + root + ">";
        }
        else if (funcName.find("ReadFile") != std::string::npos) {
            if (LookupHandleType(arg0).empty()) TrackHandleType(arg0, "file_or_pipe");
            // ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, ...)
            // Arg0 (RCX): hFile
            // Arg1 (RDX): lpBuffer (Pointer to memory where data will go)
            // Arg2 (R8):  nNumberOfBytesToRead

            std::ostringstream oss;
            oss << " <HANDLE: " << Hex(arg0)
                << handleNote(arg0)
                << " BUF_PTR: " << Hex(arg1)
                << " REQ_SIZE: " << std::dec << arg2
                << ">";
            details = oss.str();
        }
        // --- NEW: Integrity/Page Scanning ---
        else if (funcName.find("VirtualQuery") != std::string::npos) {
            // VirtualQuery(lpAddress, lpBuffer, dwLength)
            // Arg0 (RCX): lpAddress being queried
            std::ostringstream oss;
            oss << " <QUERY_ADDR: " << Hex(arg0) << ">";
            details = oss.str();
        }
        else if (!gConciseEnabled && funcName.find("MessageBox") != std::string::npos) {
            // MessageBox(hWnd, lpText, lpCaption, uType)
            // Arg1 (RDX): lpText
            // Arg2 (R8):  lpCaption
            bool isWide = (funcName.back() == 'W'); // Check A vs W suffix

            std::string text = isWide ? GetWideString(arg1) : GetAsciiString(arg1);
            std::string cap = isWide ? GetWideString(arg2) : GetAsciiString(arg2);

            // Cap to 128 chars as requested
            if (text.length() > 128) text = text.substr(0, 128) + "...";
            if (cap.length() > 128)  cap = cap.substr(0, 128) + "...";

            details = " <TXT: \"" + text + "\" CAP: \"" + cap + "\">";
        }
        // --- NEW: WriteFile Handling ---
        else if (!gConciseEnabled && funcName.find("WriteFile") != std::string::npos) {
            if (LookupHandleType(arg0).empty()) TrackHandleType(arg0, "file_or_pipe");
            // WriteFile(hFile, lpBuffer, nBytes, ...)
            // Arg0 (RCX): hFile
            // Arg1 (RDX): lpBuffer
            // Arg2 (R8):  nBytes

            // Limit dump to first 64 bytes
            std::string bufDump = GetBufferDump(arg1, (UINT32)arg2, 64);

            std::ostringstream oss;
            oss << " <HANDLE: " << Hex(arg0)
                << handleNote(arg0)
                << " BYTES: " << std::dec << arg2
                << " DATA: " << bufDump << ">";
            details = oss.str();
        }
        else if (funcName.find("CloseHandle") != std::string::npos) {
            std::ostringstream oss;
            oss << " <HANDLE: " << Hex(arg0) << handleNote(arg0) << ">";
            ForgetHandleType(arg0);
            details = oss.str();
        }

        else if (funcName == "dynamic_code") {
            // Dump standard ABI registers for dynamic code transitions
            std::ostringstream oss;
            oss << " <ARG0: " << Hex(arg0)
                << " ARG1: " << Hex(arg1)
                << " ARG2: " << Hex(arg2)
                << " ARG3: " << Hex(arg3)
                << " RSP: " << Hex(rsp) << ">";
            details = oss.str();
        }

        if (details.empty()) {
            // LOGIC: If we resolved a clean symbol (e.g. "ntdll.dll!RtlDecodePointer"), 
            // we don't need the raw address.
            // We ONLY show <TARGET> if the name implies a failure (e.g. "dynamic_code" or "mod+offset").

            bool isCleanSymbol = (funcName.find("!") != std::string::npos && funcName.find("+") == std::string::npos);

            if (!isCleanSymbol) {
                std::ostringstream oss;
                oss << " <TARGET: " << Hex(targetAddr) << ">";
                details = oss.str();
            }
        }
        // ------------------------------------------------

        std::string antiTag = GetAntiAnalysisTag(funcName, arg0, arg1, arg2, arg3);
        if (antiTag == "ExceptionHandlerManipulation") {
            st->lastHandlerRegistrationSeq = gSeqCounter.load();
            st->lastHandlerRegistrationRip = sourceRip;
        }
        if (antiTag == "TimingProbe") NoteTimingProbe(tid, sourceRip, funcName);
        if (!antiTag.empty()) {
            ae.reason = "ANTI_ANALYSIS_API <" + antiTag + "> API_CALL <" + funcName + ">" + details;
            ExportAntiAnalysisWitness(tid, sourceRip, ae.reason);
        }
        else {
            ae.reason = "API_CALL <" + funcName + ">" + details;
        }
        if (!memoryEventApi.empty()) {
            ExportMemoryEvent(memoryEventApi.c_str(), sourceRip, memoryEventBase, memoryEventSize, memoryEventProtect, details);
        }

        DispatchEntry(st, ae);
        if (gUseRing) { DumpWindow(st); st->dumping = true; st->postRemaining = gPostFollow; }
    }
}