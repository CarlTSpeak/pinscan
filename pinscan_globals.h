// Core Pinscan structures and global variable declarations

#ifndef PINSCAN_GLOBALS_H
#define PINSCAN_GLOBALS_H

#include "pin.H"
using namespace LEVEL_BASE;
using namespace LEVEL_PINCLIENT;
#include <atomic>
#include <chrono>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <array>
#include <set>
#include <deque>
#include <map>



// -------------------- Core Structures --------------------

struct InstEntry {
    uint64_t seq{ 0 };
    THREADID tid{ 0 };
    ADDRINT rip{ 0 };
    std::string mod;
    ADDRINT rva{ 0 };
    std::string dis;
    std::string bytes;
    std::string reason;
    std::vector<std::string> regLines;
    std::vector<std::string> memLines;
    std::string regJson;
    std::string memJson;
};

struct ThreadState {
    THREADID tid{ 0 };
    UINT64 instCount{ 0 };
    std::vector<InstEntry> ring;
    UINT32 next{ 0 };
    bool filled{ false };
    bool dumping{ false };
    UINT32 postRemaining{ 0 };
    bool gateOpen{ true };
    ADDRINT lastRip{ 0 };
    ADDRINT cpuidLeaf{ 0 };
    ADDRINT cpuidSubleaf{ 0 };
    ADDRINT cpuidInRax{ 0 };
    ADDRINT cpuidInRbx{ 0 };
    ADDRINT cpuidInRcx{ 0 };
    ADDRINT cpuidInRdx{ 0 };
    ADDRINT pendingWriteAddr{ 0 };
    ADDRINT pendingReadAddr{ 0 };
    bool ignoreNextTrap{ false };
    bool seenLdrInitializeThunk{ false };
    bool seenInitterm{ false };
    bool loggedPreMainExecution{ false };
    
    ADDRINT tebBase{ 0 };
    ADDRINT lastTimingProbeRip{ 0 };
    UINT32 timingProbeStreak{ 0 };
    ADDRINT exceptionFaultRip{ 0 };
    ADDRINT exceptionDispatchRip{ 0 };
    INT32 exceptionCode{ 0 };
    UINT32 repeatedExceptionCount{ 0 };
    UINT32 exceptionDispatchSteps{ 0 };
    bool exceptionResumePending{ false };
    bool exceptionDispatchSeen{ false };
    uint64_t lastHandlerRegistrationSeq{ 0 };
    ADDRINT lastHandlerRegistrationRip{ 0 };
    std::vector<ADDRINT> shadowCallStack;
    ADDRINT* pendingAllocBasePtr{ nullptr };
    size_t* pendingAllocSizePtr{ nullptr };
    bool hasPendingConcrete{ false };
    InstEntry pendingConcreteEntry;
    bool pendingConcreteDump{ false };
    bool pendingTraceGuiValid{ false };
    bool pendingTraceGuiDeferForWrite{ false };
    UINT32 pendingTraceGuiReadMask{ 0 };
    UINT32 pendingTraceGuiWriteMask{ 0 };
    UINT32 pendingTraceGuiAfterMask{ 0 };
    std::array<ADDRINT, 16> pendingTraceGuiRegBefore{};
    std::array<ADDRINT, 16> pendingTraceGuiRegAfter{};
    bool pendingTraceGuiRflagsRead{ false };
    bool pendingTraceGuiRflagsWrite{ false };
    bool pendingTraceGuiRflagsAfter{ false };
    ADDRINT pendingTraceGuiRflagsBefore{ 0 };
    ADDRINT pendingTraceGuiRflagsAfterValue{ 0 };
    ADDRINT pendingTraceGuiReadAddr1{ 0 };
    UINT32 pendingTraceGuiReadSize1{ 0 };
    std::string pendingTraceGuiReadValue1;
    ADDRINT pendingTraceGuiReadAddr2{ 0 };
    UINT32 pendingTraceGuiReadSize2{ 0 };
    std::string pendingTraceGuiReadValue2;
    ADDRINT pendingTraceGuiWriteAddr{ 0 };
    UINT32 pendingTraceGuiWriteSize{ 0 };
    std::string pendingTraceGuiWriteBefore;
    std::string pendingTraceGuiWriteAfter;
    std::deque<ADDRINT> lookbackBuffer;
    UINT32 consecutiveMatches{ 0 };
    ADDRINT loopHeadRip{ 0 };
    bool loopConfirmed{ false };
    UINT64 iterationCount{ 0 };
    bool loopSquelchActive{ false };
    std::vector<InstEntry> shadowBuffer;
    ADDRINT memReadAddr = 0;
    UINT32 memReadSize = 0;
};

struct PageMetadata {
    ADDRINT pageBase{ 0 };
    ADDRINT allocBase{ 0 };
    ADDRINT regionSize{ 0 };
    unsigned long protect{ 0 };
    unsigned long type{ 0 };
    bool executable{ false };
    bool knownImage{ false };
    bool mzChecked{ false };
    bool hasMz{ false };
    bool dirty{ true };
};

struct ExecPageState {
    std::vector<UINT8> before;
    THREADID writerTid{ 0 };
    ADDRINT writerRip{ 0 };
    UINT32 writeCount{ 0 };
    bool pendingExec{ false };
    uint64_t generation{ 0 };
    THREADID firstExecTid{ 0 };
    ADDRINT firstExecRip{ 0 };
    UINT32 executeCount{ 0 };
    ADDRINT firstBranchSourceRip{ 0 };
    std::set<ADDRINT> inboundSources;
    bool handlerPoolLogged{ false };
};

struct ExecRegionPageSnapshot {
    ADDRINT pageBase{ 0 };
    ExecPageState state{};
    std::vector<UINT8> after;
    UINT64 beforeHash{ 0 };
    UINT64 afterHash{ 0 };
    UINT32 changedBytes{ 0 };
    std::string diff;
};

struct MemTrigger {
    ADDRINT base{ 0 };
    ADDRINT size{ 0 };
    UINT32 width{ 0 }; 
    bool enabled{ false };
    bool onRead{ false };
    bool onWrite{ false };
};

struct InstStatic {
    std::string dis;
    std::string mod;
    ADDRINT rva{ 0 };
    std::string bytes;
    std::string mnemonic;
    UINT32 size{ 0 };
    bool isControlFlow{ false };
    UINT32 gprReadMask{ 0 };
    UINT32 gprWriteMask{ 0 };
    bool rflagsRead{ false };
    bool rflagsWrite{ false };
};

// -------------------- Globals --------------------

extern FILE* gOut;
extern FILE* gOutJson;
extern PIN_LOCK gLock;
extern TLS_KEY gTlsKey;
extern std::chrono::steady_clock::time_point gStartTime;
extern std::atomic<uint64_t> gSeqCounter;
extern UINT32 gRingSize;
extern UINT64 gHeartbeatInterval;
extern bool gMainOnly;
extern bool gVerbose;
extern bool gStreamMode;
extern bool gSpoofTimeEnabled;
extern bool gKuserEnabled;
extern bool gTimingEnabled;
extern bool gSyscallEnabled;
extern bool gConciseEnabled;
extern UINT32 gPostFollow;
extern bool gUseRing;
extern bool gApiEnabled;
extern UINT32 cpuidCount;
extern std::unordered_set<uint32_t> gTlsCallbackRvas;
extern std::string gNamed;
extern bool gConcreteEnabled;
extern UINT32 gLoopWindowSize;
extern bool gCfDumpEnabled;
extern bool gCfProvenanceEnabled;
extern bool gVmEntryEnabled; 

extern std::string gProfile;
extern std::string gMode;
extern UINT32 gLogLevel;
extern std::string gScope;
extern UINT32 gPid;
extern std::string gExportDir;
extern UINT64 gMaxLinesPrinted;
extern std::atomic<UINT64> gLinesPrinted;

extern bool gPebEnabled;
extern ADDRINT gPebBase;
static constexpr ADDRINT kPebSize = 0x1000;

extern std::unordered_map<ADDRINT, std::string> g_ApiCache;
extern PIN_LOCK g_ApiCacheLock;
extern PIN_LOCK g_HandleMapLock;
extern PIN_LOCK g_ExecPageLock;
extern PIN_LOCK g_PageMetaLock;
extern ADDRINT g_MainExeLow;
extern ADDRINT g_MainExeHigh;
extern std::unordered_set<ADDRINT> gKnownImageBases;
extern std::unordered_set<ADDRINT> gFlaggedMzBases;
extern ADDRINT gLdrInitializeThunk;
extern std::unordered_set<ADDRINT> gInittermAddrs;
extern std::unordered_map<ADDRINT, std::string> gHandleTypeMap;

extern PIN_LOCK g_AllocationLock;
extern std::map<ADDRINT, size_t> g_TrackedAllocations;

extern std::unordered_map<ADDRINT, std::string> g_DllEntryPoints;
extern PIN_LOCK g_EpLock;

extern std::unordered_map<ADDRINT, PageMetadata> gPageMetadata;
extern std::unordered_map<ADDRINT, ExecPageState> gExecPageStates;

extern ADDRINT gStartRip;
extern bool gStartRipEnabled;
extern bool gStartGateDisabled;
extern ADDRINT gStopRip;
extern bool gStopRipEnabled;

static constexpr size_t kMaxMemTriggers = 3;
static MemTrigger gMemTriggers[kMaxMemTriggers];

extern std::unordered_map<ADDRINT, InstStatic> gStaticByRip;
extern std::unordered_map<ADDRINT, std::string> gInterestingMnemonicByRip;
extern std::unordered_set<ADDRINT> g_DumpedJitRegions;

extern std::string gTriggerJsonlPath;
extern std::string gTargetJsonlPath;
extern std::string gSnapshotJsonlPath;
extern std::string gStartupJsonlPath;
extern std::string gMemoryEventJsonlPath;
extern std::string gAntiAnalysisJsonlPath;

extern const REG kRegMap[16];
extern std::unordered_map<ADDRINT, std::string> gSyscallNames;

#endif // PINSCAN_GLOBALS_H
