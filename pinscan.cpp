/* PinScan - event-triggered lookback.
 Must be run with pin -smc_strict 1 to force retrospective analysis.
 Intended for Windows x86-64 binaries.
 Avoid including windows.h directly here due to conflicts with Pin CRT libraries.

 Version history lives in CHANGELOG.md. */

#include "pinscan_globals.h"
#include "utils.h"
#include "pe_parser.h"
#include "telemetry.h"
#include "exec_tracker.h"
#include "api_tracer.h"
#include "cpu_context.h"
#include "tracegui_csv.h"

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <array>
#include <bitset>
#include <set>
#include <deque>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// -------------------- Manual Windows API Import --------------------
#ifdef _WIN32
extern "C" {
    static const unsigned long PROT_MEM_IMAGE = 0x1000000;
   // Unused atm: static const unsigned long PROT_MEM_MAPPED = 0x40000;
    static const unsigned long PROT_MEM_PRIVATE = 0x20000;
    static const unsigned long PROT_PAGE_EXECUTE = 0x10;
    static const unsigned long PROT_PAGE_EXECUTE_READ = 0x20;
    static const unsigned long PROT_PAGE_EXECUTE_READWRITE = 0x40;
   // Unused atm: static const unsigned long PROT_PAGE_EXECUTE_WRITECOPY = 0x80;
    static const unsigned long PROT_PAGE_READWRITE = 0x04;
    static const unsigned long PROT_PAGE_READONLY = 0x02;

    struct PINSCAN_MBI {
        void* BaseAddress;
        void* AllocationBase;
        unsigned long AllocationProtect;
        unsigned short PartitionId;
        unsigned short Gap;
        size_t RegionSize;
        unsigned long State;
        unsigned long Protect;
        unsigned long Type;
    };

    __declspec(dllimport) size_t __stdcall VirtualQuery(const void* lpAddress, PINSCAN_MBI* lpBuffer, size_t dwLength);
    void* __stdcall CreateFileA(const char* lpFileName, unsigned long dwDesiredAccess, unsigned long dwShareMode, void* lpSecurityAttributes, unsigned long dwCreationDisposition, unsigned long dwFlagsAndAttributes, void* hTemplateFile);
    int __stdcall CreateDirectoryA(const char* lpPathName, void* lpSecurityAttributes);
    int __stdcall WriteFile(void* hFile, const void* lpBuffer, unsigned long nNumberOfBytesToWrite, unsigned long* lpNumberOfBytesWritten, void* lpOverlapped);
    int __stdcall CloseHandle(void* hObject);
}
#define PINSCAN_GENERIC_WRITE 0x40000000
#define PINSCAN_OPEN_EXISTING 3
#endif

// -------------------- Knobs --------------------
KNOB<std::string> KnobOut(KNOB_MODE_WRITEONCE, "pintool", "o", "pinscan.txt", "primary text output file");
KNOB<std::string> KnobOutJson(KNOB_MODE_WRITEONCE, "pintool", "o2", "none", "secondary JSON output");
KNOB<std::string> KnobExportDir(KNOB_MODE_WRITEONCE, "pintool", "ps_export_dir", "", "Directory for Pushan-friendly JSONL witness exports");
KNOB<std::string> KnobMode(KNOB_MODE_WRITEONCE, "pintool", "ps_mode", "", "Logging mode: trigger, ring, or stream");
KNOB<UINT32> KnobRingSizeUnified(KNOB_MODE_WRITEONCE, "pintool", "ps_ring_size", "0", "Ring size used by mode=ring (0 = fallback to legacy ring)");
KNOB<UINT32> KnobPostSizeUnified(KNOB_MODE_WRITEONCE, "pintool", "ps_post_size", "0", "Post-trigger follow size used by mode=ring (0 = fallback to legacy post)");
KNOB<UINT32> KnobLoopWindow(KNOB_MODE_WRITEONCE, "pintool", "loop_window", "0", "Lookback window size for loop output suppression");
KNOB<UINT32> KnobLogLevel(KNOB_MODE_WRITEONCE, "pintool", "ps_log_level", "255", "0=concise, 1=standard, 2=verbose (255 = derive from legacy knobs)");
KNOB<std::string> KnobScope(KNOB_MODE_WRITEONCE, "pintool", "ps_scope", "", "Instrumentation scope: main, all, or a module name");
KNOB<BOOL> KnobMainOnly(KNOB_MODE_WRITEONCE, "pintool", "main_only", "1", "instrument only main executable");
KNOB<UINT32> KnobPostFollow(KNOB_MODE_WRITEONCE, "pintool", "post", "64", "post-trigger trace length");
KNOB<UINT32> KnobRingSize(KNOB_MODE_WRITEONCE, "pintool", "ring", "64", "ring buffer size");
KNOB<BOOL> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool", "verbose", "0", "verbose logging");
KNOB<std::string> KnobStart(KNOB_MODE_WRITEONCE, "pintool", "start", "0", "Start RIP");
KNOB<std::string> KnobStop(KNOB_MODE_WRITEONCE, "pintool", "stop", "0", "Stop RIP");
KNOB<BOOL> KnobKuser(KNOB_MODE_WRITEONCE, "pintool", "kuser", "0", "trigger on KUSER_SHARED_DATA");
KNOB<BOOL> KnobTiming(KNOB_MODE_WRITEONCE, "pintool", "timing", "0", "trigger on RDTSC");
KNOB<BOOL> KnobSyscall(KNOB_MODE_WRITEONCE, "pintool", "syscall", "0", "trigger on SYSCALL");
KNOB<BOOL> KnobSimpleMode(KNOB_MODE_WRITEONCE, "pintool", "simple", "0", "disable ring buffer");
KNOB<BOOL> KnobTraceApi(KNOB_MODE_WRITEONCE, "pintool", "api", "0", "Enable Windows API tracing (Source-based)");
KNOB<BOOL> KnobConciseMode(KNOB_MODE_WRITEONCE, "pintool", "concise", "0", "no disassembly on human output");
KNOB<std::string> KnobNamed(KNOB_MODE_WRITEONCE, "pintool", "named", "", "non-main module to instrument");
KNOB<BOOL> KnobPeb(KNOB_MODE_WRITEONCE, "pintool", "peb", "0", "trigger on PEB access");
KNOB<BOOL> KnobSpoofTime(KNOB_MODE_WRITEONCE, "pintool", "spoof_time", "0", "Enable InterruptTime and RDTSC spoofing");
KNOB<BOOL> KnobCpuidRewrite(KNOB_MODE_WRITEONCE, "pintool", "cpuid_rewrite", "0", "Rewrite CPUID output registers after each CPUID instruction");
KNOB<std::string> KnobCpuidEax(KNOB_MODE_WRITEONCE, "pintool", "cpuid_eax", "", "Optional DWORD value to force into EAX after CPUID");
KNOB<std::string> KnobCpuidEbx(KNOB_MODE_WRITEONCE, "pintool", "cpuid_ebx", "", "Optional DWORD value to force into EBX after CPUID");
KNOB<std::string> KnobCpuidEcx(KNOB_MODE_WRITEONCE, "pintool", "cpuid_ecx", "", "Optional DWORD value to force into ECX after CPUID");
KNOB<std::string> KnobCpuidEdx(KNOB_MODE_WRITEONCE, "pintool", "cpuid_edx", "", "Optional DWORD value to force into EDX after CPUID");
KNOB<UINT64> KnobHeartbeat(KNOB_MODE_WRITEONCE, "pintool", "heartbeat", "0", "Log progress every N instructions (0 = disabled).");
KNOB<BOOL> KnobCFDump(KNOB_MODE_WRITEONCE, "pintool", "cf_dump", "0", "Dump control flow targets, stack, and VM context during gated execution");
KNOB<std::string> KnobProfile(KNOB_MODE_WRITEONCE, "pintool", "ps_profile", "", "Comma-separated semantic profile names (triage, provenance, all)");
KNOB<ADDRINT> KnobSnapshotAddr(KNOB_MODE_WRITEONCE, "pintool", "snapshot", "0", "Exact RIP to trigger full memory dump");
KNOB<BOOL> KnobConcrete(KNOB_MODE_WRITEONCE, "pintool", "concrete", "0", "Record concrete IN/OUT register values");
KNOB<UINT64> KnobMaxLines(KNOB_MODE_WRITEONCE, "pintool", "max_lines", "0", "Maximum lines to print (0 = unlimited)");
KNOB<std::string> KnobConcreteTrace(KNOB_MODE_WRITEONCE, "pintool", "ps_concrete_jsonl", "", "Path for high-performance concrete trace JSONL");
KNOB<std::string> KnobTraceGuiCsv(KNOB_MODE_WRITEONCE, "pintool", "ps_tracegui_csv", "", "Path for TraceGui-compatible CSV output");


// Memory Triggers
KNOB<std::string> KnobMemTrigBase1(KNOB_MODE_WRITEONCE, "pintool", "mem1_base", "", "Base 1");
KNOB<std::string> KnobMemTrigSize1(KNOB_MODE_WRITEONCE, "pintool", "mem1_size", "", "Size 1");
KNOB<std::string> KnobMemTrigType1(KNOB_MODE_WRITEONCE, "pintool", "mem1_type", "RW", "Type 1");
KNOB<std::string> KnobMemTrigWidth1(KNOB_MODE_WRITEONCE, "pintool", "mem1_width", "0", "Access Width 1 (0=Any)");

KNOB<std::string> KnobMemTrigBase2(KNOB_MODE_WRITEONCE, "pintool", "mem2_base", "", "Base 2");
KNOB<std::string> KnobMemTrigSize2(KNOB_MODE_WRITEONCE, "pintool", "mem2_size", "", "Size 2");
KNOB<std::string> KnobMemTrigType2(KNOB_MODE_WRITEONCE, "pintool", "mem2_type", "RW", "Type 2");
KNOB<std::string> KnobMemTrigWidth2(KNOB_MODE_WRITEONCE, "pintool", "mem2_width", "0", "Access Width 2 (0=Any)");

KNOB<std::string> KnobMemTrigBase3(KNOB_MODE_WRITEONCE, "pintool", "mem3_base", "", "Base 3");
KNOB<std::string> KnobMemTrigSize3(KNOB_MODE_WRITEONCE, "pintool", "mem3_size", "", "Size 3");
KNOB<std::string> KnobMemTrigType3(KNOB_MODE_WRITEONCE, "pintool", "mem3_type", "RW", "Type 3");
KNOB<std::string> KnobMemTrigWidth3(KNOB_MODE_WRITEONCE, "pintool", "mem3_width", "0", "Access Width 3 (0=Any)");

// -------------------- Globals --------------------
static FILE* gOut = nullptr;
static FILE* gOutJson = nullptr;
static PIN_LOCK gLock;
static TLS_KEY gTlsKey;
static std::chrono::steady_clock::time_point gStartTime;
static std::atomic<uint64_t> gSeqCounter{ 0 };
static UINT32 gRingSize = 64;
static UINT64 gHeartbeatInterval = 0;
static bool gMainOnly = false;
static bool gVerbose = false;
static bool gStreamMode = false;
static bool gSpoofTimeEnabled = false;
static bool gKuserEnabled = true;
static bool gTimingEnabled = false;
static bool gSyscallEnabled = false;
static bool gConciseEnabled = false;
static UINT32 gPostFollow = 64;
static bool gUseRing = false;
static bool gApiEnabled = false;
static UINT32 cpuidCount = 0;
static std::unordered_set<uint32_t> gTlsCallbackRvas; // RVAs of TLS callbacks to detect module loading early
static std::string gNamed = "";
static bool gConcreteEnabled = false;
static UINT32 gLoopWindowSize = 0;
static bool gCfDumpEnabled = false;
static bool gCfProvenanceEnabled = false;
static std::string gProfile = "";
static std::string gMode = "trigger";
static UINT32 gLogLevel = 1;
static std::string gScope = "main";
static UINT32 gPid = 0; // For multiple processes else crash
static std::string gExportDir = "";
static UINT64 gMaxLinesPrinted = 0;
static std::atomic<UINT64> gLinesPrinted{ 0 };
static FILE* gConcreteTraceFile = nullptr;
static PIN_LOCK gConcreteTraceLock;
static FILE* gTraceGuiCsvFile = nullptr;
static PIN_LOCK gTraceGuiCsvLock;

// PEB Access Detection
static bool gPebEnabled = false;
static ADDRINT gPebBase = 0; // Will be resolved at runtime

// Optimization: Cached range of the Main Executable to avoid repeated IMG lookups
static std::unordered_map<ADDRINT, std::string> g_ApiCache;
static PIN_LOCK g_ApiCacheLock;
static PIN_LOCK g_HandleMapLock;
static PIN_LOCK g_ExecPageLock;
static PIN_LOCK g_PageMetaLock;
static ADDRINT g_MainExeLow = 0;
static ADDRINT g_MainExeHigh = 0;
static std::unordered_set<ADDRINT> gKnownImageBases;
static std::unordered_set<ADDRINT> gFlaggedMzBases;
static ADDRINT gLdrInitializeThunk = 0;
static std::unordered_set<ADDRINT> gInittermAddrs;
static std::unordered_map<ADDRINT, std::string> gHandleTypeMap;

PIN_LOCK g_AllocationLock;
std::map<ADDRINT, size_t> g_TrackedAllocations;

std::unordered_map<ADDRINT, std::string> g_DllEntryPoints;
PIN_LOCK g_EpLock;

// Gate Config
static ADDRINT gStartRip = 0;
static bool gStartRipEnabled = false;
static bool gStartGateDisabled = false;
static ADDRINT gStopRip = 0;
static bool gStopRipEnabled = false;

static std::unordered_map<ADDRINT, InstStatic> gStaticByRip;
static std::unordered_map<ADDRINT, std::string> gInterestingMnemonicByRip;
static std::unordered_set<ADDRINT> g_DumpedJitRegions;
static std::string gTriggerJsonlPath;
static std::string gTargetJsonlPath;
static std::string gSnapshotJsonlPath;
static std::string gStartupJsonlPath;
static std::string gMemoryEventJsonlPath;
static std::string gAntiAnalysisJsonlPath;

static const REG kRegMap[16] = {
    REG_GAX, REG_GBX, REG_GCX, REG_GDX, REG_GSI, REG_GDI, REG_GBP, REG_STACK_PTR,
    REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15
};

// -------------------- Structures --------------------



static std::unordered_map<ADDRINT, ExecPageState> gExecPageStates;
std::unordered_map<ADDRINT, PageMetadata> gPageMetadata;

// Windows Structures

// --- SYSCALL MAPPING ---
static std::unordered_map<ADDRINT, std::string> gSyscallNames;

static const ADDRINT kKuserSharedBase = 0x7ffe0000;
static const ADDRINT kKuserSharedSize = 0x1000;

struct KuserField { UINT32 offset; UINT32 size; const char* name; };

static const KuserField kKuserFields[] = {
    {0x000, 4, "TickCountLowDeprecated"},
    {0x004, 4, "TickCountMultiplier"},
    {0x008, 12, "InterruptTime"},
    {0x014, 12, "SystemTime"},
    {0x020, 12, "TimeZoneBias"},
    {0x02C, 2, "ImageNumberLow"},
    {0x02E, 2, "ImageNumberHigh"},
    {0x030, 520, "NtSystemRoot"},
    {0x238, 4, "MaxStackTraceDepth"},
    {0x23C, 4, "CryptoExponent"},
    {0x240, 4, "TimeZoneId"},
    {0x244, 4, "LargePageMinimum"},
    {0x248, 4, "AitSamplingValue"},
    {0x24C, 4, "AppCompatFlag"},
    {0x250, 8, "RNGSeedVersion"},
    {0x258, 4, "GlobalValidationRunlevel"},
    {0x25C, 4, "TimeZoneBiasStamp"},
    {0x260, 4, "NtBuildNumber"},
    {0x264, 4, "NtProductType"},
    {0x268, 1, "ProductTypeIsValid"},
    {0x269, 1, "Reserved0"},
    {0x26A, 2, "NativeProcessorArchitecture"},
    {0x26C, 4, "NtMajorVersion"},
    {0x270, 4, "NtMinorVersion"},
    {0x274, 64, "ProcessorFeatures"},
    {0x2B4, 4, "Reserved1"},
    {0x2B8, 4, "Reserved3"},
    {0x2BC, 4, "TimeSlip"},
    {0x2C0, 4, "AlternativeArchitecture"},
    {0x2C4, 4, "BootId"},
    {0x2C8, 8, "SystemExpirationDate"},
    {0x2D0, 4, "SuiteMask"},
    {0x2D4, 1, "KdDebuggerEnabled"},
    {0x2D5, 1, "MitigationPolicies"},
    {0x2D6, 2, "CyclesPerYield"},
    {0x2D8, 4, "ActiveConsoleId"},
    {0x2DC, 4, "DismountCount"},
    {0x2E0, 4, "ComPlusPackage"},
    {0x2E4, 4, "LastSystemRITEventTickCount"},
    {0x2E8, 4, "NumberOfPhysicalPages"},
    {0x2EC, 1, "SafeBootMode"},
    {0x2ED, 1, "VirtualizationFlags"},
    {0x2F0, 4, "SharedDataFlags"},
    {0x2F4, 4, "DataFlagsPad"},
    {0x300, 8, "TestRetInstruction"},
    {0x308, 8, "QpcFrequency"},
    {0x310, 8, "SystemCall"},
    {0x318, 4, "SystemDllNativeRelocation"},
    {0x31C, 4, "SystemDllSharedRelocation"},
    {0x320, 12, "TickCount"},
    {0x32C, 4, "TickCountPad"},
    {0x330, 4, "Cookie"},
    {0x334, 4, "CookieFirewall"},
    {0x338, 8, "ConsoleSessionId"},
    {0x340, 8, "ActiveProcessorCount"},
    {0x348, 2, "NtMajorVersion(Hi)"},
    {0x34A, 2, "NtMinorVersion(Hi)"},
    {0x350, 1, "DbgErrorPortPresent"},
    {0x351, 1, "DbgElevationEnabled"},
    {0x352, 1, "DbgVirtEnabled"},
    {0x353, 1, "DbgInstallerDetectEnabled"},
    {0x354, 1, "DbgLkgEnabled"},
    {0x355, 1, "DbgDynProcessorEnabled"},
    {0x356, 1, "DbgConsoleBrokerEnabled"},
    {0x357, 1, "DbgSecureBootEnabled"},
    {0x358, 1, "DbgMultiSessionSku"},
    {0x359, 1, "DbgMultiUsersInSessionSku"},
    {0x35A, 1, "DbgStateSeparationEnabled"},
    {0x360, 40, "Spare3"},
    {0x388, 4, "ConsoleSessionForegroundProcessId"},
    {0x38C, 4, "TimeUpdateSequence"},
    {0x390, 8, "BaselineSystemTimeQpc"},
    {0x398, 8, "BaselineInterruptTimeQpc"},
    {0x3A0, 8, "QpcSystemTimeIncrement"},
    {0x3A8, 8, "QpcInterruptTimeIncrement"},
    {0x3B0, 1, "QpcSystemTimeIncrementShift"},
    {0x3B1, 1, "QpcInterruptTimeIncrementShift"},
    {0x3B2, 2, "UnparkedProcessorCount"},
    {0x3B4, 4, "EnclaveFeatureMask"},
    {0x3B8, 4, "TelemetryCoverageRound"},
    {0x3BC, 4, "UserModeGlobalLogger"},
    {0x3C0, 4, "ImageFileExecutionOptions"},
    {0x3C4, 4, "LangGenerationCount"},
    {0x3C8, 8, "Reserved4"},
    {0x3D0, 8, "InterruptTimeBias"},
    {0x3D8, 8, "QpcBias"},
    {0x3E0, 4, "ActiveGroupCount"},
    {0x3E2, 1, "OverrideStateChange"},
    {0x3E3, 1, "Polarity"},
    {0x3E8, 4, "QpcData"},
    {0x720, 12, "FeatureConfigurationChangeStamp"},
    {0x72C, 4, "Spare"},
    {0x730, 8, "UserPointerAuthMask"},
    {0x738, 0x348, "XState"},
    {0xA80, 0x348, "Reserved10"}
};
static const size_t kKuserFieldCount = sizeof(kKuserFields) / sizeof(kKuserFields[0]);

// Modern Windows 10/11 PEB Map (x64)
// Based on Geoff Chappell & Vergilius Project
static const KuserField kPebFields[] = {
        // --- Header & Debugging (0x000 - 0x018) ---
        {0x000, 1, "InheritedAddressSpace"},
        {0x001, 1, "ReadImageFileExecOptions"},
        {0x002, 1, "BeingDebugged"},

        // UNION: BitField (0x03) vs Individual Flags
        {0x003, 1, "BitField (Union)"},
        {0x003, 1, "  -> ImageUsesLargePages (Bit 0)"},
        {0x003, 1, "  -> IsProtectedProcess (Bit 1)"},
        {0x003, 1, "  -> IsImageDynamicallyRelocated (Bit 2)"},
        {0x003, 1, "  -> SkipPatchingUser32Forwarders (Bit 3)"},
        {0x003, 1, "  -> IsPackagedProcess (Bit 4)"},
        {0x003, 1, "  -> IsAppContainer (Bit 5)"},
        {0x003, 1, "  -> IsProtectedProcessLight (Bit 6)"},
        {0x003, 1, "  -> IsLongPathAwareProcess (Bit 7)"},

        {0x004, 4, "Padding0"},
        {0x008, 8, "Mutant"},
        {0x010, 8, "ImageBaseAddress"},         // <--- HMODULE of the EXE

        // --- Loader Data (0x018 - 0x060) ---
        {0x018, 8, "Ldr"},                      // <--- _PEB_LDR_DATA* (Loaded Modules)
        {0x020, 8, "ProcessParameters"},        // <--- _RTL_USER_PROCESS_PARAMETERS* (CmdLine)
        {0x028, 8, "SubSystemData"},
        {0x030, 8, "ProcessHeap"},              // <--- Heap Handle
        {0x038, 8, "FastPebLock"},
        {0x040, 8, "AtlThunkSListPtr"},
        {0x048, 8, "IFEOKey"},                  // (Was SparePtr1)

        // UNION: CrossProcessFlags (0x050)
        {0x050, 4, "CrossProcessFlags (Union)"},
        {0x050, 4, "  -> ProcessInJob (Bit 0)"},
        {0x050, 4, "  -> ProcessInitializing (Bit 1)"},
        {0x050, 4, "  -> ProcessUsingVEH (Bit 2)"},
        {0x050, 4, "  -> ProcessUsingVCH (Bit 3)"},
        {0x050, 4, "  -> ProcessUsingFTH (Bit 4)"},
        {0x050, 4, "  -> ProcessPreviouslyThrottled (Bit 5)"},
        {0x050, 4, "  -> ProcessCurrentlyThrottled (Bit 6)"},
        {0x050, 4, "  -> ProcessImagesHotPatched (Bit 7)"},
        {0x054, 4, "Padding1"},

        // --- Kernel Callbacks & Global Flags (0x058 - 0x118) ---
        {0x058, 8, "KernelCallbackTable"},      // <--- Used for User32 hooks (e.g., OLE)
        {0x058, 8, "UserSharedInfoPtr (Legacy)"}, // Union with above
        {0x060, 4, "SystemReserved"},
        {0x064, 4, "AtlThunkSListPtr32"},       // WOW64 specific
        {0x068, 8, "ApiSetMap"},                // <--- API Sets Schema (Windows 10+)
        {0x070, 4, "TlsExpansionCounter"},
        {0x074, 4, "Padding2"},
        {0x078, 8, "TlsBitmap"},
        {0x080, 8, "TlsBitmapBits (0-63)"},
        {0x088, 8, "TlsBitmapBits (64-127)"},
        {0x090, 8, "ReadOnlySharedMemoryBase"},
        {0x098, 8, "SharedMemoryHeap"},         // (Was ReadOnlySharedMemoryHeap)
        {0x0A0, 8, "ReadOnlyStaticServerData"},
        {0x0A8, 8, "AnsiCodePageData"},
        {0x0B0, 8, "OemCodePageData"},
        {0x0B8, 8, "UnicodeCaseTableData"},
        {0x0C0, 4, "NumberOfProcessors"},
        {0x0C4, 4, "NtGlobalFlag"},             // <--- Anti-Debug (0x70 = Debugged)
        {0x0C8, 8, "CriticalSectionTimeout"},   // (LARGE_INTEGER)
        {0x0D0, 8, "HeapSegmentReserve"},
        {0x0D8, 8, "HeapSegmentCommit"},
        {0x0E0, 8, "HeapDeCommitTotalFreeThreshold"},
        {0x0E8, 8, "HeapDeCommitFreeBlockThreshold"},
        {0x0F0, 4, "NumberOfHeaps"},
        {0x0F4, 4, "MaximumNumberOfHeaps"},
        {0x0F8, 8, "ProcessHeaps"},             // <--- Pointer to array of Heaps
        {0x100, 8, "GdiSharedHandleTable"},
        {0x108, 8, "ProcessStarterHelper"},
        {0x110, 4, "GdiDCAttributeList"},
        {0x114, 4, "Padding3"},

        // --- Loader Lock & Version (0x118 - 0x2C0) ---
        {0x118, 8, "LoaderLock"},               // <--- Critical Section for Ldr
        {0x120, 4, "OSMajorVersion"},
        {0x124, 4, "OSMinorVersion"},
        {0x128, 2, "OSBuildNumber"},
        {0x12A, 2, "OSCSDVersion"},
        {0x12C, 4, "OSPlatformId"},
        {0x130, 4, "ImageSubsystem"},
        {0x134, 4, "ImageSubsystemMajorVersion"},
        {0x138, 4, "ImageSubsystemMinorVersion"},
        {0x13C, 4, "Padding4"},
        {0x140, 8, "ActiveProcessAffinityMask"},
        {0x148, 0x88, "GdiHandleBuffer"},       // (34 * DWORD)
        {0x1D0, 8, "PostProcessInitRoutine"},
        {0x1D8, 8, "TlsExpansionBitmap"},
        {0x1E0, 128, "TlsExpansionBitmapBits"}, // (32 * DWORD)
        {0x260, 4, "SessionId"},
        {0x264, 4, "Padding5"},

        // --- Modern Windows (AppCompat & Tracing) ---
        {0x268, 8, "AppCompatFlags"},           // (ULARGE_INTEGER)
        {0x270, 8, "AppCompatFlagsUser"},       // (ULARGE_INTEGER)
        {0x278, 8, "pShimData"},
        {0x280, 8, "AppCompatInfo"},            // <--- APP_COMPAT_INFO*
        {0x288, 16, "CSDVersion (String)"},     // UNICODE_STRING
        {0x298, 8, "ActivationContextData"},
        {0x2A0, 8, "ProcessAssemblyStorageMap"},
        {0x2A8, 8, "SystemDefaultActivationContextData"},
        {0x2B0, 8, "SystemAssemblyStorageMap"},
        {0x2B8, 8, "MinimumStackCommit"},
        {0x2C0, 8, "FlsCallback"},
        {0x2C8, 16, "FlsListHead"},             // _LIST_ENTRY
        {0x2D8, 8, "FlsBitmap"},
        {0x2E0, 16, "FlsBitmapBits"},           // (4 * DWORD)
        {0x2F0, 4, "FlsHighIndex"},
        {0x2F4, 4, "Padding6"},

        // --- WerRegistration & Tracing (0x2F8+) ---
        {0x2F8, 8, "WerRegistrationData"},
        {0x300, 8, "WerShipAssertPtr"},
        {0x308, 8, "pUnused"},                  // (Was pContextData)
        {0x310, 8, "pImageHeaderHash"},

        // UNION: TracingFlags (0x318 on Win11 x64, check overlap)
        // Note: Offset can shift to 0x378 in some 22H2 versions, 
        // but 0x318 is standard for modern 10/11.
        {0x318, 4, "TracingFlags (Union)"},
        {0x318, 4, "  -> HeapTracingEnabled (Bit 0)"},
        {0x318, 4, "  -> CritSecTracingEnabled (Bit 1)"},
        {0x318, 4, "  -> LibLoaderTracingEnabled (Bit 2)"},
        {0x31C, 4, "Padding7"},

        // --- The "Tail" (Win 10/11 Specifics) ---
        {0x320, 8, "CsrServerReadOnlySharedMemoryBase"},
        {0x328, 8, "TppWorkerpListLock"},
        {0x330, 16, "TppWorkerpList"},          // _LIST_ENTRY
        {0x340, 8, "WaitOnAddressHashTable [0x80]"}, // Huge array starts here
        // ... (Skipping the 1024 bytes of WaitOnAddress table for brevity)

        // Critical modern fields after the table:
        {0x740, 8, "ApiSetMap (Alternative)"},   // Sometimes mirrored here
        {0x748, 8, "TlsExpansionCounter (Alt)"},
        {0x750, 8, "ImageFileExecutionOptions"}, // <--- GlobalFlag (IFEO)
        {0x7C0, 8, "AppModelInfo"},              // AppContainer details
        {0x7C8, 8, "CsgLoaderInfo"}              // Enclave / VBS info
};
static const size_t kPebFieldCount = sizeof(kPebFields) / sizeof(kPebFields[0]);

ThreadState* GetToolThreadState(THREADID tid) {
    return static_cast<ThreadState*>(PIN_GetThreadData(gTlsKey, tid));
}

// Helper needed forward declaration
static bool InMemTrigger(ADDRINT a, ADDRINT size, bool isWriteAccess);
static bool InKuserShared(ADDRINT a);
static std::string GetTriggerModule(ADDRINT addr);
static bool ShouldInstrumentAddress(ADDRINT addr);
static void AppendReason(std::string& reason, const std::string& part);
static void TrackCallSite(THREADID tid, ADDRINT rip, ADDRINT retAddr, ADDRINT target);
static void TrackReturnSite(THREADID tid, ADDRINT rip, ADDRINT target, ADDRINT rsp);
static void TrackExecutableWriteBefore(THREADID tid, ADDRINT rip, ADDRINT addr, UINT32 size);
static void CheckFirstExecutionAfterWrite(THREADID tid, ADDRINT rip);
static void LogSemanticAlert(THREADID tid, ADDRINT rip, const std::string& reason);
static void NoteControlFlowIntoModifiedPage(THREADID tid, ADDRINT rip, ADDRINT target);
static void TrackExceptionResume(THREADID tid, ADDRINT rip);
static void InvalidatePageMetadataRange(ADDRINT base, ADDRINT size);
static bool CheckHiddenExecutableMzRegionCached(ADDRINT addr, std::string& outReason, bool allowRefresh);
static std::string ResolvePebAntiAnalysis(ADDRINT addr);
static std::string ResolveTebAntiAnalysis(const ThreadState* st, ADDRINT addr);
static void NoteTimingProbe(THREADID tid, ADDRINT rip, const std::string& source);
static std::string GetSemanticInstructionTag(INS ins, const std::string& mnemonic);

// Forward decl for logging
static void WriteEntry(const InstEntry& e);
static void DumpWindow(ThreadState* st);

// -------------------- Helpers --------------------



static void AppendReason(std::string& reason, const std::string& part) {
    if (part.empty()) return;
    if (!reason.empty()) reason += " | ";
    reason += part;
}

static bool InKuserShared(ADDRINT a) { return a >= kKuserSharedBase && a < (kKuserSharedBase + kKuserSharedSize); }

static bool IsInMainExe(ADDRINT addr) {
    return (addr >= g_MainExeLow && addr < g_MainExeHigh);
}




// Updated to support width check
static bool InMemTrigger(ADDRINT a, ADDRINT size, bool isWriteAccess) {
    for (size_t i = 0; i < kMaxMemTriggers; ++i) {
        if (!gMemTriggers[i].enabled) continue;

        // Width Check (0 = Any)
        if (gMemTriggers[i].width != 0 && gMemTriggers[i].width != size) continue;

        ADDRINT base = gMemTriggers[i].base;
        // Simple overlap check
        if ((a + size) > base && a < (base + gMemTriggers[i].size)) {
            if (isWriteAccess && gMemTriggers[i].onWrite) return true;
            if (!isWriteAccess && gMemTriggers[i].onRead) return true;
        }
    }
    return false;
}
static bool ShouldInstrument(INS ins) {
    ADDRINT rip = INS_Address(ins);
    if (IsInMainExe(rip)) return true;

    PIN_LockClient();
    IMG img = IMG_FindByAddress(rip);
    bool isValid = IMG_Valid(img);
    std::string name = isValid ? IMG_Name(img) : "";
    PIN_UnlockClient();

    if (!isValid) return true;

    size_t cutname = name.find_last_of("\\/");
    if (cutname != std::string::npos) name = name.substr(cutname + 1);
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });

    if (((name.find("ntdll.dll") != std::string::npos) ||
        (name.find("xinput") != std::string::npos)) && !gVerbose) {
        return false;
    }

    if (!gNamed.empty()) {
        return (name.find(gNamed) != std::string::npos);
    }

    return !gMainOnly;
}

static bool ShouldInstrumentAddress(ADDRINT rip) {
    // 1. Always trace the host application! (Fast path, no locks)
    if (IsInMainExe(rip)) return true;

    // 2. Safely query the global image table
    PIN_LockClient();
    IMG img = IMG_FindByAddress(rip);
    bool isValid = IMG_Valid(img);
    std::string name = isValid ? IMG_Name(img) : "";
    PIN_UnlockClient();

    // 3. Trace dynamic/unbacked code (e.g., JIT, unpacking stubs)
    if (!isValid) return true;

    // --- Everything below this line is a loaded DLL ---
    size_t cutname = name.find_last_of("\\/");
    if (cutname != std::string::npos) name = name.substr(cutname + 1);
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });

    // 4. Noise Filter 
    if (((name.find("ntdll.dll") != std::string::npos) ||
        (name.find("xinput") != std::string::npos)) && !gVerbose) {
        return false;
    }

    // 5. Specific Module Targeting
    if (!gNamed.empty()) {
        return (name.find(gNamed) != std::string::npos);
    }

    // 6. Fallback behavior
    return !gMainOnly;
}

static std::string ExtractMaskedRegs(const CONTEXT* ctxt, UINT32 mask) {
    if (mask == 0 || !ctxt) return "";

    static const REG kRegMap[16] = {
        REG_GAX, REG_GBX, REG_GCX, REG_GDX, REG_GSI, REG_GDI, REG_GBP,
        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15,
        REG_STACK_PTR // Index 15
    };

    std::ostringstream oss;
    bool first = true;
    for (int i = 0; i < 16; ++i) { // Ensure we loop all 16 bits
        if (mask & (1u << i)) {
            if (!first) oss << " ";
            oss << REG_StringShort(kRegMap[i]) << "=" << Hex(PIN_GetContextReg(const_cast<CONTEXT*>(ctxt), kRegMap[i]));
            first = false;
        }
    }
    return oss.str();
}

static void ManageLoopState(ThreadState* st, ADDRINT rip) {
    if (!st) return;

    // Phase 1 & 2: Burn-in and Lock-On
    if (!st->loopConfirmed) {
        // We only evaluate heuristics if the burn-in window is completely full
        if (st->lookbackBuffer.size() == gLoopWindowSize) {
            bool found = false;
            for (auto it = st->lookbackBuffer.begin(); it != st->lookbackBuffer.end(); ++it) {
                if (*it == rip) { found = true; break; }
            }

            if (found) {
                // If this is the first match of the sequence, tag it as the potential Loop Head
                if (st->consecutiveMatches == 0) {
                    st->loopHeadRip = rip;
                }

                st->consecutiveMatches++;

                // 5 consecutive matches confirms we are mathematically trapped in the working set
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

        // Slide the window
        st->lookbackBuffer.push_back(rip);
        if (st->lookbackBuffer.size() > gLoopWindowSize) {
            st->lookbackBuffer.pop_front();
        }
    }
    // Phase 3, 4, 5: Observation, Suppress, and Exit
    else {
        bool inWorkingSet = false;
        for (auto it = st->lookbackBuffer.begin(); it != st->lookbackBuffer.end(); ++it) {
            if (*it == rip) { inWorkingSet = true; break; }
        }

        if (!inWorkingSet) {
            // PHASE 5: EXIT & COMMIT
            // The CPU jumped to a RIP outside our instruction window.
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

            // Reset the entire state machine for the next loop
            st->loopConfirmed = false;
            st->loopSquelchActive = false;
            st->consecutiveMatches = 0;
            st->iterationCount = 0;
            st->lookbackBuffer.clear();
            st->lookbackBuffer.push_back(rip); // Start the new burn-in window
            st->shadowBuffer.clear();
        }
        else {
            // We are still inside the bounded working set.
            if (rip == st->loopHeadRip) {
                st->iterationCount++;

                // PHASE 4: SQUELCH (Triggered on the 4th iteration)
                if (st->iterationCount == 4) {
                    st->loopSquelchActive = true;

                    InstEntry marker;
                    marker.seq = ++gSeqCounter; marker.tid = st->tid; marker.rip = rip;
                    marker.reason = "=== [LOOP SUPPRESSION ACTIVE: Silencing Middle Iterations] ===";
                    WriteEntry(marker);
                }

                // The Marker-Based Reset: Clear the cache every time we hit the head
                if (st->loopSquelchActive) {
                    st->shadowBuffer.clear();
                }
            }
        }
    }
}

// -------------------- Output --------------------
extern void DispatchEntry(ThreadState* st, const InstEntry& e) {
    // 1. Advance the State Machine ONLY if the feature is enabled
    if (gLoopWindowSize > 0) {
        ManageLoopState(st, e.rip);
    }

    // 2. Route the output based on the state
    if (!st->loopSquelchActive) {
        WriteEntry(e);
        if (st->pendingConcreteDump && gUseRing) {
            DumpWindow(st); st->dumping = true; st->postRemaining = gPostFollow;
        }
    }
    else {
        st->shadowBuffer.push_back(e);

        // THE SAFETY VALVE: Prevents infinite RAM growth (VM Dispatcher runaway)
        if (st->shadowBuffer.size() > 4096) {
            for (const auto& shadowEntry : st->shadowBuffer) {
                WriteEntry(shadowEntry);
            }

            InstEntry marker;
            marker.seq = ++gSeqCounter; marker.tid = st->tid; marker.rip = e.rip;
            marker.reason = "=== [LOOP ABORTED: Iteration exceeded 4096 instructions] ===";
            WriteEntry(marker);

            // Emergency Reset
            st->loopConfirmed = false;
            st->loopSquelchActive = false;
            st->consecutiveMatches = 0;
            st->iterationCount = 0;
            st->lookbackBuffer.clear();
            st->shadowBuffer.clear();
        }
    }
}

// -------------------- Context Helpers --------------------

struct ProfileToggles {
    bool api{ false };
    bool syscall{ false };
    bool kuser{ false };
    bool peb{ false };
    bool timing{ false };
    bool cfDump{ false };
    bool provenance{ false };
};

static std::vector<std::string> SplitProfileTokens(const std::string& value) {
    std::vector<std::string> tokens;
    size_t start = 0;
    while (start < value.size()) {
        size_t end = value.find(',', start);
        std::string token = value.substr(start, (end == std::string::npos) ? std::string::npos : (end - start));
        size_t first = token.find_first_not_of(" \t");
        size_t last = token.find_last_not_of(" \t");
        if (first != std::string::npos) {
            tokens.push_back(LowerCopyProfile(token.substr(first, last - first + 1)));
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return tokens;
}

static ProfileToggles ParseSemanticProfile(const std::string& value) {
    ProfileToggles toggles;
    for (const std::string& token : SplitProfileTokens(value)) {
        if (token == "triage") {
            toggles.api = true;
            toggles.syscall = true;
            toggles.kuser = true;
            toggles.peb = true;
            toggles.timing = true;
        }
        else if (token == "provenance") {
            toggles.cfDump = true;
            toggles.provenance = true;
        }
        else if (token == "vm" || token == "triton") {
            toggles.cfDump = true;
            toggles.provenance = true;
        }
        else if (token == "all") {
            toggles.api = true;
            toggles.syscall = true;
            toggles.kuser = true;
            toggles.peb = true;
            toggles.timing = true;
            toggles.cfDump = true;
            toggles.provenance = true;
        }
    }
    return toggles;
}

static UINT32 ClampLogLevel(UINT32 value) {
    return (value > 2) ? 2 : value;
}

static const char* CurrentModeName() {
    if (gStreamMode) return "stream";
    if (gUseRing) return "ring";
    return "trigger";
}

static const char* CurrentScopeName() {
    if (!gNamed.empty()) return gNamed.c_str();
    return gMainOnly ? "main" : "all";
}

static std::string ParseEffectiveMode() {
    std::string mode = LowerCopyProfile(KnobMode.Value());
    if (mode == "trigger" || mode == "ring" || mode == "stream") {
        return mode;
    }

    if (KnobSimpleMode.Value()) {
        return "trigger";
    }

    if (KnobRingSizeUnified.Value() != 0 || KnobPostSizeUnified.Value() != 0) {
        return "ring";
    }

    if (KnobRingSize.Value() != 64 || KnobPostFollow.Value() != 64) {
        return "ring";
    }

    return "trigger";
}

static UINT32 ParseEffectiveLogLevel() {
    UINT32 configured = KnobLogLevel.Value();
    if (configured != 255) {
        return ClampLogLevel(configured);
    }

    if (KnobVerbose.Value()) {
        return 2;
    }

    if (KnobConciseMode.Value()) {
        return 0;
    }

    return 1;
}

static std::string ParseEffectiveScope() {
    std::string scope = KnobScope.Value();
    if (!scope.empty()) {
        std::string lowered = LowerCopyProfile(scope);
        if (lowered == "main" || lowered == "all") {
            return lowered;
        }
        return lowered;
    }

    if (!KnobNamed.Value().empty()) {
        return LowerCopyProfile(KnobNamed.Value());
    }

    return KnobMainOnly.Value() ? "main" : "all";
}

// PEB & KUSER Helpers

static std::string ResolvePebOffset(ADDRINT addr) {
    if (gPebBase == 0 || addr < gPebBase) return "";
    UINT32 offset = static_cast<UINT32>(addr - gPebBase);

    for (size_t i = 0; i < kPebFieldCount; ++i) {
        const KuserField& f = kPebFields[i];
        if (offset >= f.offset && offset < (f.offset + f.size)) {
            std::ostringstream oss;
            oss << " (0x" << std::hex << offset << " " << f.name;
            if (offset > f.offset) oss << "+" << std::hex << (offset - f.offset);
            oss << ")";
            return oss.str();
        }
    }
    std::ostringstream oss; oss << " (PEB+0x" << std::hex << offset << ")";
    return oss.str();
}

static std::string ResolveKuserOffset(ADDRINT addr) {
    if (addr < kKuserSharedBase) return "";

    // Calculate the exact offset from 0x7FFE0000
    UINT32 offset = static_cast<UINT32>(addr - kKuserSharedBase);

    for (size_t i = 0; i < kKuserFieldCount; ++i) {
        const KuserField& f = kKuserFields[i];
        if (offset >= f.offset && offset < (f.offset + f.size)) {
            std::ostringstream oss;
            oss << " (0x" << std::hex << offset << " " << f.name;
            UINT32 sub = offset - f.offset;
            if (sub > 0) oss << "+" << std::hex << sub;
            oss << ")";
            return oss.str();
        }
    }

    // Fallback: Return the specific offset even if unknown
    std::ostringstream oss;
    oss << " (unknown_kuser+0x" << std::hex << offset << ")";
    return oss.str();
}

static std::string ResolvePebAntiAnalysis(ADDRINT addr) {
    if (gPebBase == 0 || addr < gPebBase) return "";
    UINT32 offset = static_cast<UINT32>(addr - gPebBase);

    if (offset == 0x2) return "BeingDebugged";
    if (offset >= 0x18 && offset < 0x30) return "LoaderMetadataProbe";
    if (offset >= 0x30 && offset < 0x38) return "ProcessHeapProbe";
    if (offset >= 0x0BC && offset < 0x0C0) return "NtGlobalFlagProbe";
    if (offset >= 0x318 && offset < 0x31C) return "HeapTracingFlagsProbe";
    return "";
}

static std::string ResolveTebAntiAnalysis(const ThreadState* st, ADDRINT addr) {
    if (!st || st->tebBase == 0 || addr < st->tebBase) return "";
    UINT32 offset = static_cast<UINT32>(addr - st->tebBase);
    if (offset == 0x60) return "PebPointerWalk";
    return "";
}



static bool IsDebugRegister(REG reg) {
    switch (REG_FullRegName(reg)) {
    case REG_DR0:
    case REG_DR1:
    case REG_DR2:
    case REG_DR3:
    case REG_DR6:
    case REG_DR7:
        return true;
    default:
        return false;
    }
}

static std::string GetSemanticInstructionTag(INS ins, const std::string& mnemonic) {
    for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); ++i) {
        if (IsDebugRegister(INS_RegR(ins, i))) return "ANTI_ANALYSIS_INSN <DebugRegisterAccess>";
    }
    for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); ++i) {
        if (IsDebugRegister(INS_RegW(ins, i))) return "ANTI_ANALYSIS_INSN <DebugRegisterAccess>";
    }

    if (mnemonic == "RDPMC") return "ANTI_ANALYSIS_INSN <PerformanceCounterProbe>";
    if (mnemonic == "SIDT" || mnemonic == "SGDT" || mnemonic == "SLDT" ||
        mnemonic == "STR" || mnemonic == "SMSW") {
        return "ANTI_ANALYSIS_INSN <SystemDescriptorProbe>";
    }
    if (mnemonic == "XGETBV") return "ANTI_ANALYSIS_INSN <ExtendedStateProbe>";
    if (mnemonic == "INT1" || mnemonic == "ICEBP") return "ANTI_ANALYSIS_INSN <BreakpointProbe>";
    return "";
}

static int GprMaskIndex(REG reg) {
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

static UINT32 BuildGprReadMask(INS ins) {
    UINT32 mask = 0;
    for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); ++i) {
        int idx = GprMaskIndex(INS_RegR(ins, i));
        if (idx >= 0) mask |= (1u << idx);
    }
    return mask;
}

static UINT32 BuildGprWriteMask(INS ins) {
    UINT32 mask = 0;
    for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); ++i) {
        int idx = GprMaskIndex(INS_RegW(ins, i));
        if (idx >= 0) mask |= (1u << idx);
    }
    return mask;
}

static void CheckAndOpenGate(THREADID tid, ADDRINT rip, const CONTEXT* ctxt) {
    if (!gStartRipEnabled || gStartGateDisabled) return;

    ThreadState* st = GetToolThreadState(tid);
    if (st && !st->gateOpen && rip == gStartRip) {
        st->gateOpen = true;
        PIN_GetLock(&gLock, 0);
        std::fprintf(gOut ? gOut : stderr, "[pinscan] tid=%u start hit at %s\n", (unsigned)tid, Hex(rip).c_str());
        if (gOut) std::fflush(gOut);
        PIN_ReleaseLock(&gLock);

        // TRIGGER SNAPSHOT A
        if (gConcreteEnabled) {
            ExecuteSnapshot(tid, ctxt, "start");
        }
    }
}

static void CheckAndCloseGate(THREADID tid, ADDRINT rip, const CONTEXT* ctxt) {
    if (!gStopRipEnabled || gStartGateDisabled) return;

    ThreadState* st = GetToolThreadState(tid);
    if (st && st->gateOpen && rip == gStopRip) {
        st->gateOpen = false;
        PIN_GetLock(&gLock, 0);
        std::fprintf(gOut ? gOut : stderr, "[pinscan] tid=%u end hit at %s\n", (unsigned)tid, Hex(rip).c_str());
        if (gOut) std::fflush(gOut);
        PIN_ReleaseLock(&gLock);

        // TRIGGER SNAPSHOT B
        if (gConcreteEnabled) {
            ExecuteSnapshot(tid, ctxt, "stop");

            // Optional: If you want to force kill the game after the B slice is captured to save time
            // PIN_ExitApplication(0); 
        }
    }
}

static void ResolveBootstrapSymbols(IMG img) {
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            std::string sym = PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_NAME_ONLY);
            std::string lower = LowerCopy(sym);
            if (lower == "ldrinitializethunk") {
                gLdrInitializeThunk = RTN_Address(rtn);
            }
            if (lower == "_initterm" || lower == "_initterm_e" || lower == "initterm" || lower == "initterm_e") {
                gInittermAddrs.insert(RTN_Address(rtn));
            }
        }
    }
}

static void TrackPreMainExecution(THREADID tid, ADDRINT rip) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st) return;

    if (gLdrInitializeThunk != 0 && rip == gLdrInitializeThunk) {
        st->seenLdrInitializeThunk = true;
        st->loggedPreMainExecution = false;
    }

    if (gInittermAddrs.find(rip) != gInittermAddrs.end()) {
        st->seenInitterm = true;
        return;
    }

    if (st->seenLdrInitializeThunk && !st->seenInitterm && !st->loggedPreMainExecution && IsInMainExe(rip)) {
        st->loggedPreMainExecution = true;

        InstEntry e;
        e.seq = ++gSeqCounter;
        e.tid = tid;
        e.rip = rip;
        e.reason = "PRE_MAIN_EXECUTION_WINDOW <transition: LdrInitializeThunk -> _initterm pending>";

        auto it = gStaticByRip.find(rip);
        if (it != gStaticByRip.end()) {
            e.dis = it->second.dis;
            e.mod = it->second.mod;
            e.rva = it->second.rva;
        }
        DispatchEntry(st, e);
    }
}

static std::string DescribeCfProvenance(ADDRINT target, ADDRINT rsp, bool isRet, const ThreadState* st) {
    ADDRINT rspVal = 0;
    PIN_SafeCopy(&rspVal, (void*)rsp, sizeof(ADDRINT));

    std::string memType;
    ADDRINT allocBase = 0;
    GetMemInfo(target, memType, allocBase);

    bool stackTarget = (target >= (rsp > 0x4000 ? rsp - 0x4000 : 0) && target < (rsp + 0x4000));
    bool topOfStack = (target == rspVal && rspVal != 0);
    bool shadowMatch = (st && !st->shadowCallStack.empty() && st->shadowCallStack.back() == target);

    std::ostringstream oss;
    oss << "prov=";
    if (isRet && topOfStack) oss << "ret_stack";
    else if (stackTarget) oss << "stack_target";
    else if (memType.find("PRV") != std::string::npos) oss << "private_exec";
    else if (memType.find("IMG") != std::string::npos) oss << "image_exec";
    else oss << "mapped_or_unknown";

    oss << " mem=" << memType;
    if (allocBase != 0) oss << " base=" << Hex(allocBase);
    if (isRet) {
        oss << " stack_top=" << Hex(rspVal);
        oss << " shadow=" << (shadowMatch ? "match" : "mismatch");
    }
    return oss.str();
}

static void TrackCallSite(THREADID tid, ADDRINT rip, ADDRINT retAddr, ADDRINT target) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->gateOpen) return;
    if (ShouldInstrumentAddress(target)) {
        st->shadowCallStack.push_back(retAddr);
    }

    if (gCfProvenanceEnabled && !IsInMainExe(target)) {
        LogSemanticAlert(tid, rip, "INDIRECT_CALL_PROVENANCE <target: " + Hex(target) + " " + DescribeCfProvenance(target, retAddr, false, st) + ">");
    }
}

static void TrackReturnSite(THREADID tid, ADDRINT rip, ADDRINT target, ADDRINT rsp) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->gateOpen) return;
    if (!ShouldInstrumentAddress(target)) return;

    ADDRINT expected = 0;
    if (!st->shadowCallStack.empty()) {
        expected = st->shadowCallStack.back();
        st->shadowCallStack.pop_back();
    }

    if (gCfProvenanceEnabled && expected != 0 && expected != target) {
        LogSemanticAlert(tid, rip, "SHADOW_STACK_MISMATCH <expected: " + Hex(expected) + " actual: " + Hex(target) +
            " " + DescribeCfProvenance(target, rsp, true, st) + ">");
    }
}
// Time Spoofing Helpers


static void RecordControlFlow(THREADID tid, ADDRINT rip, ADDRINT target, ADDRINT rsp, const CONTEXT* ctxt) {
    ThreadState* st = GetToolThreadState(tid);
    // Respect the gate! If we aren't tracing, bail out immediately.
    if (!st || !st->gateOpen) return;

    std::string hiddenMzReason;
    if (CheckHiddenExecutableMzRegionCached(target, hiddenMzReason, true)) {
        InstEntry e;
        e.seq = ++gSeqCounter;
        e.tid = tid;
        e.rip = rip;
        e.reason = "CF_TARGET " + hiddenMzReason;
        auto it = gStaticByRip.find(rip);
        if (it != gStaticByRip.end()) {
            e.dis = it->second.dis;
            e.mod = it->second.mod;
            e.rva = it->second.rva;
        }
        DispatchEntry(st, e);
    }

    if (!IsInMainExe(target)) {
    // --- JUST-IN-TIME (JIT) DUMPER ---
    PIN_LockClient();
    IMG targetImg = IMG_FindByAddress(target);
    bool isValidImg = IMG_Valid(targetImg);
    PIN_UnlockClient();

    // If it's a legitimate OS DLL, just drop the noise.
    if (isValidImg) return;

        // If it's NOT a valid image, it's dynamic/JIT memory!
        // Lock and check if we have already dumped this memory region
        PIN_GetLock(&gLock, tid + 1);
        ADDRINT pageBase = target & ~0xFFFULL; // Round down to standard page boundary
        bool alreadyDumped = (g_DumpedJitRegions.find(pageBase) != g_DumpedJitRegions.end());
        if (!alreadyDumped) g_DumpedJitRegions.insert(pageBase);
        PIN_ReleaseLock(&gLock);

        if (!alreadyDumped) {
            // Query the Windows Memory Manager for the absolute boundaries of this allocation
            PINSCAN_MBI mbi = { 0 };
            if (VirtualQuery((const void*)target, &mbi, sizeof(mbi))) {

                // Check if the memory is private (not a mapped file) and has an Execute bit set (0x10, 0x20, 0x40, 0x80)
                if (mbi.Type == PROT_MEM_PRIVATE && (mbi.Protect & 0xF0) != 0) {

                    std::string dumpName = "payload_jit_" + Hex((ADDRINT)mbi.AllocationBase) + ".bin";
                    FILE* dumpFile = fopen(dumpName.c_str(), "wb");
                    if (dumpFile) {
                        std::vector<UINT8> buffer(mbi.RegionSize);
                        size_t bytesRead = PIN_SafeCopy(buffer.data(), (void*)mbi.AllocationBase, mbi.RegionSize);
                        fwrite(buffer.data(), 1, bytesRead, dumpFile);
                        fclose(dumpFile);

                        PIN_GetLock(&gLock, tid + 1);
                        if (gOut) {
                            std::fprintf(gOut, "[!JIT REGION DUMPED ON ENTRY: %s (Size: 0x%llx)]\n",
                                dumpName.c_str(), (unsigned long long)mbi.RegionSize);
                        }
                        PIN_ReleaseLock(&gLock);
                    }
                }
            }
        }
    }
    // Safely peek at what is sitting on top of the stack
    ADDRINT rspVal = 0;
    PIN_SafeCopy(&rspVal, (void*)rsp, sizeof(ADDRINT));
    std::string provenance = DescribeCfProvenance(target, rsp, false, st);
    ExportControlFlowWitness(tid, rip, target, rsp, ctxt, provenance);

}

// -------------------- Analysis --------------------
static const REG kTraceGuiRegByMaskIndex[16] = {
    REG_GAX, REG_GBX, REG_GCX, REG_GDX, REG_GSI, REG_GDI, REG_GBP, REG_R8,
    REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_STACK_PTR
};

static const char* kTraceGuiRegNameByMaskIndex[16] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8",
    "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rsp"
};

void LogTraceGuiCsvRow(const TraceGuiCsvRow& row) {
    if (!gTraceGuiCsvFile) return;
    std::string line = TraceGuiFormatRow(row);
    PIN_GetLock(&gTraceGuiCsvLock, 1);
    std::fprintf(gTraceGuiCsvFile, "%s\n", line.c_str());
    PIN_ReleaseLock(&gTraceGuiCsvLock);
}

static std::string TraceGuiValue(ADDRINT value) {
    return TraceGuiHexNoPrefix(value);
}

static std::string TraceGuiNormalizeHexValue(const std::string& value) {
    size_t start = 0;
    if (value.size() >= 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        start = 2;
    }
    std::string out;
    out.reserve(value.size() - start);
    for (size_t i = start; i < value.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(value[i]);
        out.push_back(static_cast<char>(std::toupper(ch)));
    }
    return out;
}

static std::string TraceGuiMemoryValue(ADDRINT addr, UINT32 size) {
    if (addr == 0 || size == 0) return "";
    return TraceGuiNormalizeHexValue(ReadMemHex(addr, size));
}

static std::string TraceGuiBuildRegisterColumn(const ThreadState* st) {
    if (!st) return "";
    UINT32 mask = st->pendingTraceGuiReadMask | st->pendingTraceGuiWriteMask;
    std::ostringstream oss;
    bool first = true;
    for (int i = 0; i < 16; ++i) {
        if ((mask & (1u << i)) == 0) continue;
        if (!first) oss << ' ';
        oss << kTraceGuiRegNameByMaskIndex[i] << ": ";
        if ((st->pendingTraceGuiWriteMask & (1u << i)) && (st->pendingTraceGuiAfterMask & (1u << i))) {
            oss << TraceGuiValue(st->pendingTraceGuiRegBefore[i])
                << "\xE2\x86\x92" << TraceGuiValue(st->pendingTraceGuiRegAfter[i]);
        }
        else {
            oss << TraceGuiValue(st->pendingTraceGuiRegBefore[i]);
        }
        first = false;
    }
    return oss.str();
}

static void TraceGuiAppendMemCell(std::ostringstream& oss, bool& first, ADDRINT addr,
    const std::string& before, const std::string& after) {
    if (addr == 0 || (before.empty() && after.empty())) return;
    if (!first) oss << ' ';
    oss << TraceGuiHexNoPrefix(addr, 16) << ": ";
    if (!before.empty() && !after.empty()) oss << before << "\xE2\x86\x92" << after;
    else if (!after.empty()) oss << after;
    else oss << before;
    first = false;
}

static std::string TraceGuiBuildMemoryColumn(const ThreadState* st) {
    if (!st) return "";
    std::ostringstream oss;
    bool first = true;
    TraceGuiAppendMemCell(oss, first, st->pendingTraceGuiReadAddr1, st->pendingTraceGuiReadValue1, "");
    TraceGuiAppendMemCell(oss, first, st->pendingTraceGuiReadAddr2, st->pendingTraceGuiReadValue2, "");
    TraceGuiAppendMemCell(oss, first, st->pendingTraceGuiWriteAddr,
        st->pendingTraceGuiWriteBefore, st->pendingTraceGuiWriteAfter);
    return oss.str();
}

static void TraceGuiResetPending(ThreadState* st) {
    if (!st) return;
    st->pendingTraceGuiValid = false;
    st->pendingTraceGuiDeferForWrite = false;
    st->pendingTraceGuiReadMask = 0;
    st->pendingTraceGuiWriteMask = 0;
    st->pendingTraceGuiAfterMask = 0;
    st->pendingTraceGuiReadAddr1 = 0;
    st->pendingTraceGuiReadSize1 = 0;
    st->pendingTraceGuiReadValue1.clear();
    st->pendingTraceGuiReadAddr2 = 0;
    st->pendingTraceGuiReadSize2 = 0;
    st->pendingTraceGuiReadValue2.clear();
    st->pendingTraceGuiWriteAddr = 0;
    st->pendingTraceGuiWriteSize = 0;
    st->pendingTraceGuiWriteBefore.clear();
    st->pendingTraceGuiWriteAfter.clear();
}

static void TraceGuiEmitPending(ThreadState* st, UINT32 insSize) {
    if (!st || !st->pendingTraceGuiValid) return;
    if (!gTraceGuiCsvFile) {
        TraceGuiResetPending(st);
        return;
    }

    TraceGuiCsvRow row;
    row.index = TraceGuiHexNoPrefix(st->pendingConcreteEntry.seq, 5);
    row.address = TraceGuiHexNoPrefix(st->pendingConcreteEntry.rip, 16);
    if (insSize == 0) {
        auto it = gStaticByRip.find(st->pendingConcreteEntry.rip);
        if (it != gStaticByRip.end()) insSize = it->second.size;
    }
    row.bytes = TraceGuiFormatBytesColon(ReadBytesHex(st->pendingConcreteEntry.rip, insSize));
    row.disassembly = st->pendingConcreteEntry.dis;
    size_t regsPos = row.disassembly.find(" | REGS:");
    size_t memPos = row.disassembly.find(" | MEM:");
    size_t cutPos = std::min(regsPos == std::string::npos ? row.disassembly.size() : regsPos,
        memPos == std::string::npos ? row.disassembly.size() : memPos);
    row.disassembly.resize(cutPos);
    row.registers = TraceGuiBuildRegisterColumn(st);
    row.memory = TraceGuiBuildMemoryColumn(st);

    std::ostringstream comments;
    comments << "tid=" << (unsigned)st->pendingConcreteEntry.tid;
    if (!st->pendingConcreteEntry.mod.empty()) comments << " mod=" << st->pendingConcreteEntry.mod;
    if (st->pendingConcreteEntry.rva != 0) comments << " rva=0x" << TraceGuiHexNoPrefix(st->pendingConcreteEntry.rva);
    if (!st->pendingConcreteEntry.reason.empty()) comments << " reason=" << st->pendingConcreteEntry.reason;
    row.comments = comments.str();

    LogTraceGuiCsvRow(row);
    TraceGuiResetPending(st);
}

static void TraceGuiPreparePending(ThreadState* st, ADDRINT rip,
    ADDRINT r1, UINT32 r1Size, ADDRINT r2, UINT32 r2Size,
    ADDRINT w1, UINT32 w1Size) {
    if (!st) return;
    TraceGuiResetPending(st);
    st->pendingTraceGuiValid = true;

    auto it = gStaticByRip.find(rip);
    if (it != gStaticByRip.end()) {
        st->pendingTraceGuiReadMask = it->second.gprReadMask;
        st->pendingTraceGuiWriteMask = it->second.gprWriteMask;
    }

    st->pendingTraceGuiReadAddr1 = r1;
    st->pendingTraceGuiReadSize1 = r1Size;
    st->pendingTraceGuiReadValue1 = TraceGuiMemoryValue(r1, r1Size);
    st->pendingTraceGuiReadAddr2 = r2;
    st->pendingTraceGuiReadSize2 = r2Size;
    st->pendingTraceGuiReadValue2 = TraceGuiMemoryValue(r2, r2Size);

    if (w1 != 0 && w1Size != 0) {
        st->pendingTraceGuiWriteAddr = w1;
        st->pendingTraceGuiWriteSize = w1Size;
        st->pendingTraceGuiWriteBefore = TraceGuiMemoryValue(w1, w1Size);
    }
}

static void Record(THREADID tid, ADDRINT rip, BOOL mnemonicInteresting,
    BOOL isPushImm, ADDRINT r1, UINT32 r1Size, ADDRINT r2, UINT32 r2Size,
    ADDRINT w1, UINT32 w1Size) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st->gateOpen) return;

    st->memReadAddr = r1;
    st->memReadSize = r1Size;

    // Flush pending concrete entries
    if (st->hasPendingConcrete) {
        TraceGuiEmitPending(st, 0);
        DispatchEntry(st, st->pendingConcreteEntry);
        st->hasPendingConcrete = false;
    }

    // 1. FAST COUNTERS
    // Increment the global timeline unconditionally and save our spot
    uint64_t currentSeq = ++gSeqCounter;

    // Fast thread-local heartbeat
    if (gHeartbeatInterval > 0) {
        st->instCount++;
        if (st->instCount % gHeartbeatInterval == 0) {
            PIN_GetLock(&gLock, 1);
            if (gOut) {
                std::string loc = "unknown";
                auto it = gStaticByRip.find(rip);
                if (it != gStaticByRip.end()) {
                    std::ostringstream oss;
                    oss << it->second.mod << "+" << std::hex << it->second.rva;
                    loc = oss.str();
                }
                std::fprintf(gOut, "[HEARTBEAT] tid=%u count=%llu rip=%s (%s)\n",
                    (unsigned)tid, (unsigned long long)st->instCount,
                    Hex(rip).c_str(), loc.c_str());
            }
            PIN_ReleaseLock(&gLock);
        }
    }

    if (gVerbose || (gLogLevel == 2)) { CheckFirstExecutionAfterWrite(tid, rip); }

    // 3. LIGHTWEIGHT TRIGGER CHECKS
    bool interesting = false;
    std::string reason;

    if (mnemonicInteresting) {
        auto rit = gInterestingMnemonicByRip.find(rip);
        if (rit != gInterestingMnemonicByRip.end()) { interesting = true; AppendReason(reason, rit->second); }
    }

    if (gKuserEnabled && (InKuserShared(r1) || InKuserShared(r2))) {
        interesting = true;
        ADDRINT kuser_addr = r1Size ? r1 : r2;
        AppendReason(reason, "kuser_shared_data_read" + ResolveKuserOffset(r1Size ? r1 : r2));
        if (kuser_addr == (kKuserSharedBase + 0x08) || kuser_addr == (kKuserSharedBase + 0x320)) {
            AppendReason(reason, "ANTI_ANALYSIS_KUSER <TimingFieldProbe>");
            NoteTimingProbe(tid, rip, "kuser_timing");
        }
    }

    if (st->tebBase != 0) {
        auto IsTeb = [&](ADDRINT a) { return a >= st->tebBase && a < (st->tebBase + 0x1000); };
        if (IsTeb(r1) || IsTeb(r2)) {
            ADDRINT tebAddr = IsTeb(r1) ? r1 : r2;
            std::string tebTag = ResolveTebAntiAnalysis(st, tebAddr);
            if (!tebTag.empty()) {
                interesting = true;
                AppendReason(reason, "ANTI_ANALYSIS_TEB <" + tebTag + ">");
            }
        }
    }

    if (gPebBase != 0) {
        auto IsPeb = [&](ADDRINT a) { return a >= gPebBase && a < (gPebBase + kPebSize); };
        if (IsPeb(r1) || IsPeb(r2)) {
            ADDRINT addr = IsPeb(r1) ? r1 : r2;
            std::string pebTag = ResolvePebAntiAnalysis(addr);
            if (gPebEnabled || !pebTag.empty()) interesting = true;
            if (gPebEnabled) AppendReason(reason, "peb_read" + ResolvePebOffset(addr));
            if (!pebTag.empty()) AppendReason(reason, "ANTI_ANALYSIS_PEB <" + pebTag + ">");
        }
    }

    if (r1Size && InMemTrigger(r1, r1Size, false)) {
        interesting = true;
        AppendReason(reason, "mem_trigger_r1 <addr: " + Hex(r1) + ", size: " + Hex(r1Size) +
            ", val: " + GetMemContent(r1, r1Size) + ", mod: " + GetTriggerModule(r1) + ">");
        std::string triggerMzReason;
        if (CheckHiddenExecutableMzRegionCached(r1, triggerMzReason, true)) AppendReason(reason, triggerMzReason);
    }
    if (r2Size && InMemTrigger(r2, r2Size, false)) {
        interesting = true;
        AppendReason(reason, "mem_trigger_r2 <addr: " + Hex(r2) + ", size: " + Hex(r2Size) +
            ", val: " + GetMemContent(r2, r2Size) + ", mod: " + GetTriggerModule(r2) + ">");
        std::string triggerMzReason;
        if (CheckHiddenExecutableMzRegionCached(r2, triggerMzReason, true)) AppendReason(reason, triggerMzReason);
    }

    if (w1Size && InMemTrigger(w1, w1Size, true)) {
        interesting = true;
        AppendReason(reason, "mem_trigger_w1_before <addr: " + Hex(w1) + ", size: " + Hex(w1Size) +
            ", old_val: " + GetMemContent(w1, w1Size) + ", mod: " + GetTriggerModule(w1) + ">");
        std::string triggerMzReason;
        if (CheckHiddenExecutableMzRegionCached(w1, triggerMzReason, true)) AppendReason(reason, triggerMzReason);
    }

    std::string hiddenMzReason;
    if (CheckHiddenExecutableMzRegionCached(rip, hiddenMzReason, false)) {
        interesting = true;
        AppendReason(reason, hiddenMzReason);
    }

    // 4. THE FAST BAILOUT
    // If we didn't hit a trigger, AND the ring buffer is off, AND we aren't currently 
    // dumping the post-trigger trace... GET OUT NOW.
    if (!interesting && !gUseRing && !gStreamMode && !(st->dumping && st->postRemaining > 0)) {
        return;
    }

    // 5. HEAVY OBJECT CREATION
    // We only perform the expensive map lookup if we are actually going to use the data.
    InstEntry e;
    e.seq = currentSeq; // Assign the value we captured at the top
    e.tid = tid;
    e.rip = rip;
    e.reason = reason;

    auto it = gStaticByRip.find(rip);
    if (it != gStaticByRip.end()) {
        e.dis = it->second.dis;
        e.mod = it->second.mod;
        e.rva = it->second.rva;
    }

    if (!gConcreteEnabled) {
        if (gStreamMode && !interesting) {
            DispatchEntry(st, e);
            return;
        }
        if (interesting) {
            ExportTriggerWitness(e, r1, r1Size, r2, r2Size, w1, w1Size);
            st->pendingConcreteDump = interesting;
            DispatchEntry(st, e);
        }
        return;
    }
    // 6. BUFFER MANAGEMENT & WRITING
    if (gUseRing) {
        if (st->ring.empty()) st->ring.resize(gRingSize);
        st->ring[st->next] = e;
        st->next = (st->next + 1) % gRingSize;
        if (st->next == 0) st->filled = true;
    }

    st->pendingConcreteEntry = e;
    st->pendingConcreteDump = interesting;
    st->hasPendingConcrete = true;
    TraceGuiPreparePending(st, rip, r1, r1Size, r2, r2Size, w1, w1Size);

    if (st->dumping && st->postRemaining > 0) {
        DispatchEntry(st, e);
        if (--st->postRemaining == 0) st->dumping = false;
    }
}


static void LogConcreteEventJson(const std::string& jsonLine) {
    if (!gConcreteTraceFile) return;
    PIN_GetLock(&gConcreteTraceLock, 1);
    std::fprintf(gConcreteTraceFile, "%s\n", jsonLine.c_str());
    PIN_ReleaseLock(&gConcreteTraceLock);
}

static void RecordConcreteBefore(THREADID tid, ADDRINT rip, const CONTEXT* ctxt) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->hasPendingConcrete) return;

    auto it = gStaticByRip.find(rip);
    if (it != gStaticByRip.end()) {
        UINT32 mask = it->second.gprReadMask | it->second.gprWriteMask;
        for (int i = 0; i < 16; ++i) {
            if (mask & (1u << i)) {
                st->pendingTraceGuiRegBefore[i] =
                    PIN_GetContextReg(const_cast<CONTEXT*>(ctxt), kTraceGuiRegByMaskIndex[i]);
            }
        }
    }
}

static void RecordConcreteAfter(THREADID tid, ADDRINT rip, UINT32 insSize, const CONTEXT* ctxt) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->hasPendingConcrete) return;

    auto it = gStaticByRip.find(rip);

    // JSONL export of register writes
    if (gConcreteTraceFile) {
        std::ostringstream oss;
        oss << "{\"kind\":\"insn\", \"seq\":" << st->pendingConcreteEntry.seq
            << ", \"tid\":" << (unsigned)tid
            << ", \"rip\":\"" << Hex(rip) << "\""
            << ", \"opcode_bytes\":\"" << ReadMemHex(rip, insSize) << "\"";

        if (st->memReadSize > 0) {
            oss << ", \"mem_read\":{"
                << "\"addr\":\"" << Hex(st->memReadAddr) << "\", "
                << "\"val\":\"" << ReadMemHex(st->memReadAddr, st->memReadSize) << "\"}";
        }

        if (it != gStaticByRip.end() && it->second.gprWriteMask != 0) {
            oss << ", \"regs_out\":{";
            bool first = true;
            for (int i = 0; i < 16; ++i) {
                if (it->second.gprWriteMask & (1u << i)) {
                    if (!first) oss << ", ";
                    oss << "\"" << REG_StringShort(kRegMap[i]) << "\":\""
                        << Hex(PIN_GetContextReg(const_cast<CONTEXT*>(ctxt), kRegMap[i])) << "\"";
                    first = false;
                }
            }
            oss << "}";
        }
        oss << "}";
        LogConcreteEventJson(oss.str());
    }

    if (it != gStaticByRip.end()) {
        for (int i = 0; i < 16; ++i) {
            if (it->second.gprWriteMask & (1u << i)) {
                st->pendingTraceGuiRegAfter[i] =
                    PIN_GetContextReg(const_cast<CONTEXT*>(ctxt), kTraceGuiRegByMaskIndex[i]);
                st->pendingTraceGuiAfterMask |= (1u << i);
            }
        }
    }

    std::string regs = TraceGuiBuildRegisterColumn(st);
    if (!regs.empty()) {
        st->pendingConcreteEntry.dis += " | REGS: [" + regs + "]";
    }

    if (st->pendingTraceGuiDeferForWrite) {
        return;
    }
    TraceGuiEmitPending(st, insSize);
    DispatchEntry(st, st->pendingConcreteEntry);
    if (st->pendingConcreteDump && gUseRing) { DumpWindow(st); st->dumping = true; st->postRemaining = gPostFollow; }

    st->hasPendingConcrete = false;
}

static void CaptureWriteAddr(THREADID tid, ADDRINT addr, UINT32 size) {
    if (ThreadState* st = GetToolThreadState(tid)) {
        st->pendingWriteAddr = addr;
        st->pendingTraceGuiWriteAddr = addr;
        st->pendingTraceGuiWriteSize = size;
        st->pendingTraceGuiWriteBefore = TraceGuiMemoryValue(addr, size);
        st->pendingTraceGuiDeferForWrite = st->pendingTraceGuiValid;
    }
}

static void RecordMemWriteAfter(THREADID tid, ADDRINT rip, UINT32 size, UINT32 insSize) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->gateOpen) return;

    ADDRINT addr = st->pendingWriteAddr;
    if (st->pendingTraceGuiValid && st->pendingTraceGuiWriteAddr == 0) {
        st->pendingTraceGuiWriteAddr = addr;
        st->pendingTraceGuiWriteSize = size;
    }
    if (st->pendingTraceGuiValid) {
        st->pendingTraceGuiWriteAfter = TraceGuiMemoryValue(addr, size);
        std::string mem = TraceGuiBuildMemoryColumn(st);
        if (!mem.empty()) {
            st->pendingConcreteEntry.dis += " | MEM: [" + mem + "]";
        }
        TraceGuiEmitPending(st, insSize);
        DispatchEntry(st, st->pendingConcreteEntry);
        if (st->pendingConcreteDump && gUseRing) { DumpWindow(st); st->dumping = true; st->postRemaining = gPostFollow; }
        st->hasPendingConcrete = false;
    }

    // Trigger check
    if (InMemTrigger(addr, size, true)) {
        InstEntry we; we.seq = ++gSeqCounter; we.tid = tid; we.rip = rip;
        auto it = gStaticByRip.find(rip);
        if (it != gStaticByRip.end()) { we.dis = it->second.dis; we.mod = it->second.mod; we.rva = it->second.rva; }
        std::ostringstream oss;
        oss << "mem_trigger_w1 <addr: " << Hex(addr)
            << ", new_val: " << GetMemContent(addr, size)
            << ", mod: " << GetTriggerModule(addr) << ">";
        we.reason = oss.str();
        DispatchEntry(st, we);
        if (gUseRing) { DumpWindow(st); st->dumping = true; st->postRemaining = gPostFollow; }
    }
	// Display concretised memory writes
    else if (gConcreteEnabled) {
        InstEntry we; we.seq = ++gSeqCounter; we.tid = tid; we.rip = rip;
        auto it = gStaticByRip.find(rip);
        if (it != gStaticByRip.end()) { we.dis = it->second.dis; we.mod = it->second.mod; we.rva = it->second.rva; }
        std::ostringstream oss;
        oss << "CONCRETE_MEM_WRITE <"
            << TraceGuiHexNoPrefix(addr, 16) << ": "
            << TraceGuiMemoryValue(addr, size)
            << " size: " << std::dec << size << ">";
        we.reason = oss.str();
        DispatchEntry(st, we);
    }
    // JSONL export of memory writes for post-processing 
    if (gConcreteEnabled && gConcreteTraceFile) {
        std::ostringstream oss;
        oss << "{\"kind\":\"mem_write\", \"seq\":" << gSeqCounter.load()
        << ", \"tid\":" << (unsigned)tid
        << ", \"rip\":\"" << Hex(rip) << "\""
        << ", \"opcode_bytes\":\"" << ReadMemHex(rip, insSize) << "\""
        << ", \"addr\":\"" << Hex(addr) << "\""
        << ", \"size\":" << size
        << ", \"val\":\"" << ReadMemHex(addr, size) << "\"}";
        LogConcreteEventJson(oss.str());
    }
}


// -------------------- API Call Handling --------------------

static void UpdateLastRip(THREADID tid, ADDRINT rip) {
    if (ThreadState* st = GetToolThreadState(tid)) {
        st->lastRip = rip;
        TrackPreMainExecution(tid, rip);
        TrackExceptionResume(tid, rip);
    }
}

static void InstrumentInstruction(INS ins, void*) {
    if (!ShouldInstrument(ins)) return;

    ADDRINT rip = INS_Address(ins);

    PIN_GetLock(&g_EpLock, 1);
    bool isEntryPoint = (g_DllEntryPoints.find(rip) != g_DllEntryPoints.end());
    PIN_ReleaseLock(&g_EpLock);

    if (isEntryPoint) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordDllMainEntry,
            IARG_ADDRINT, rip,
            IARG_THREAD_ID,
            IARG_END);
    }

    InstStatic st{};
    st.dis = INS_Disassemble(ins);
	// Handle RIP-relative addressing in the disassembly for better readability
    size_t ripPos = st.dis.find("rip+0x");
    if (ripPos != std::string::npos) {
        size_t endPos = st.dis.find("]", ripPos);
        if (endPos != std::string::npos) {
            std::string hexStr = st.dis.substr(ripPos + 6, endPos - (ripPos + 6));
            ADDRINT disp = std::strtoull(hexStr.c_str(), nullptr, 16);
            ADDRINT absAddr = rip + INS_Size(ins) + disp;
            st.dis.replace(ripPos, endPos - ripPos, Hex(absAddr));
        }
    }
    else {
        // Catch negative offsets just in case
        ripPos = st.dis.find("rip-0x");
        if (ripPos != std::string::npos) {
            size_t endPos = st.dis.find("]", ripPos);
            if (endPos != std::string::npos) {
                std::string hexStr = st.dis.substr(ripPos + 6, endPos - (ripPos + 6));
                ADDRINT disp = std::strtoull(hexStr.c_str(), nullptr, 16);
                ADDRINT absAddr = rip + INS_Size(ins) - disp;
                st.dis.replace(ripPos, endPos - ripPos, Hex(absAddr));
            }
        }
    }
    ADDRINT srcLowAddr = 0;
    ADDRINT srcHighAddr = 0;
    IMG img = IMG_FindByAddress(rip);
    if (IMG_Valid(img)) {
        srcLowAddr = IMG_LowAddress(img);
        srcHighAddr = IMG_HighAddress(img);
        std::string mod = IMG_Name(img);
        if (!mod.empty()) {
            size_t slash = mod.find_last_of("\\/");
            st.mod = (slash != std::string::npos) ? mod.substr(slash + 1) : mod;
        }
        else st.mod = "unknown_module";
        st.rva = rip - IMG_StartAddress(img);
    }
    else {
        ADDRINT allocBase = 0;
        GetMemInfo(rip, st.mod, allocBase);
        st.rva = (allocBase != 0 && rip >= allocBase) ? rip - allocBase : rip;
    }

    std::string up = INS_Mnemonic(ins);
    for (char& c : up) c = (char)std::toupper((unsigned char)c);
    st.mnemonic = up;
    st.isControlFlow = INS_IsControlFlow(ins);
    st.gprReadMask = BuildGprReadMask(ins);
    st.gprWriteMask = BuildGprWriteMask(ins);

    gStaticByRip[rip] = st;

    bool isRdtsc = (up == "RDTSC" || up == "RDTSCP");
    bool isCpuid = (up == "CPUID");
    bool isSyscall = (up == "SYSCALL" || up == "SYSENTER");
    bool mnemonicInteresting = (isCpuid || up == "XGETBV");
    std::string semanticTag = GetSemanticInstructionTag(ins, up);
    if (!semanticTag.empty()) mnemonicInteresting = true;
    bool isPushImm = (INS_Opcode(ins) == XED_ICLASS_PUSH &&
        INS_OperandCount(ins) > 0 &&
        INS_OperandIsImmediate(ins, 0));

    bool isTlsCallback = ((IsInMainExe(rip)) && gTlsCallbackRvas.find(st.rva) != gTlsCallbackRvas.end());

    if (isTlsCallback) {
        gInterestingMnemonicByRip[rip] = "PRE-MAIN_TLS_CALLBACK_START";
        mnemonicInteresting = true;
    }
    else if (!semanticTag.empty()) {
        gInterestingMnemonicByRip[rip] = semanticTag;
    }
    else if (mnemonicInteresting) {
        gInterestingMnemonicByRip[rip] = up;
    }

    if (isRdtsc) gInterestingMnemonicByRip[rip] = up;
    if (isSyscall && gSyscallEnabled) gInterestingMnemonicByRip[rip] = up;

    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)UpdateLastRip, IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_END);

    if (gStartRipEnabled) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckAndOpenGate,
            IARG_THREAD_ID,
            IARG_ADDRINT, rip,
            IARG_CONST_CONTEXT,  // <--- ADDED THIS
            IARG_END);
    }

    if (gStopRipEnabled) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckAndCloseGate,
            IARG_THREAD_ID,
            IARG_ADDRINT, rip,
            IARG_CONST_CONTEXT,  // <--- ADDED THIS
            IARG_END);
    }

    if (INS_IsCall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackCallSite,
            IARG_THREAD_ID,
            IARG_ADDRINT, rip,
            IARG_ADDRINT, rip + INS_Size(ins),
            IARG_BRANCH_TARGET_ADDR,
            IARG_END);
    }
    else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackReturnSite,
            IARG_THREAD_ID,
            IARG_ADDRINT, rip,
            IARG_BRANCH_TARGET_ADDR,
            IARG_REG_VALUE, REG_STACK_PTR,
            IARG_END);
    }

    if (INS_IsIndirectBranchOrCall(ins) || INS_IsRet(ins) || INS_IsDirectBranch(ins)) {
        if (gCfDumpEnabled) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)NoteControlFlowIntoModifiedPage,
                IARG_THREAD_ID,
                IARG_ADDRINT, rip,
                IARG_BRANCH_TARGET_ADDR,
                IARG_END);
        }
    }

    if (isRdtsc && gTimingEnabled) {
        // 1. Record the instruction entry (Standard trace)
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Record),
            IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_BOOL, false,
            IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_END);

        // Spoofing (Only if -spoof_time 1)
        if (gSpoofTimeEnabled) {
            INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(HandleRdtsc), IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_CONTEXT, IARG_END);
        }
        else {
            // If spoofing is OFF, we might still want to log the REAL output for analysis
            INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(RecordRdtscAfter), IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_CONST_CONTEXT, IARG_END);
        }
        return;
    }

    if (isCpuid) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SaveCpuidInputs),
            IARG_THREAD_ID,
            IARG_REG_VALUE, REG_GAX,
            IARG_REG_VALUE, REG_GBX,
            IARG_REG_VALUE, REG_GCX,
            IARG_REG_VALUE, REG_GDX,
            IARG_END);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Record),
            IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_BOOL, false,
            IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_END);
        INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(RecordCpuidAfter),
            IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_UINT32, INS_Size(ins), IARG_CONTEXT, IARG_END);
        return;
    }
  

    if (isSyscall && gSyscallEnabled) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(RecordSyscallBefore), IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_CONST_CONTEXT, IARG_END);
        return;
    }

    // --- Control Flow Dump Instrumentation ---
    if (gCfDumpEnabled) {
        if (INS_IsIndirectBranchOrCall(ins) || INS_IsRet(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordControlFlow,
                IARG_THREAD_ID,
                IARG_INST_PTR,            // Source (RIP)
                IARG_BRANCH_TARGET_ADDR,  // Destination (Dynamically resolved by Pin)
                IARG_REG_VALUE, REG_STACK_PTR, // Current RSP
                IARG_CONST_CONTEXT,
                IARG_END);
        }
    }
	// --- Snapshot Trigger Instrumentation ---
    if(KnobSnapshotAddr.Value() != 0 && INS_Address(ins) == KnobSnapshotAddr.Value()) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ExecuteSnapshot,
            IARG_THREAD_ID,
            IARG_CONST_CONTEXT,
            IARG_END);
    }
    // --- InterruptTime Spoofing (Anti-Timing) ---
     // Gated behind -spoof_time 1 to prevent overhead/confusion by default.
    if (gSpoofTimeEnabled && INS_IsMemoryRead(ins)
        && !INS_IsStackRead(ins)             // Ignore local var reads
        && INS_MemoryReadSize(ins) == 4)     // InterruptTime is 4 bytes
    {
        REG dstReg = REG_INVALID();
        bool isSpoofCandidate = false;

        if (INS_OperandCount(ins) > 0 && INS_OperandIsReg(ins, 0) && INS_OperandWritten(ins, 0)) {
            dstReg = INS_OperandReg(ins, 0);
            isSpoofCandidate = true;
        }
        else if (up == "LODSD") {
            dstReg = REG_EAX;
            isSpoofCandidate = true;
        }

        if (isSpoofCandidate && dstReg != REG_INVALID()) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CaptureReadTarget, IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_END);
            INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)SpoofSystemTime, IARG_THREAD_ID, IARG_UINT32, dstReg, IARG_CONTEXT, IARG_END);
        }
    }

       
    // --- API Tracing Instrumentation ---
    // Expanded to catch JMP-to-API and PUSH/RET-to-API
    if (gApiEnabled) {
        bool isApiTransfer = false;

        // 1. Standard Calls (Direct & Indirect)
        if (INS_IsCall(ins)) {
            isApiTransfer = true;
        }
        // 2. Unconditional Branches (Catches tail calls and indirect JMP to IAT)
        // INS_HasFallThrough is false for JMP, but true for Jcc (conditional jumps).
        else if (INS_IsBranch(ins) ) {
            isApiTransfer = true;
        }
        // 3. Returns (The "Push/Ret" trick)
        else if (INS_IsRet(ins)) {
            isApiTransfer = true;
        }

 

        if (isApiTransfer) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnApiCall,
                IARG_THREAD_ID,
                IARG_INST_PTR,            // Source (RIP)
                IARG_BRANCH_TARGET_ADDR,  // Destination (The API Address)
                IARG_ADDRINT, srcLowAddr, // Source Module Base
                IARG_ADDRINT, srcHighAddr,// Source Module Ceiling
                IARG_REG_VALUE, REG_RCX,  // Arg 0
                IARG_REG_VALUE, REG_RDX,  // Arg 1
                IARG_REG_VALUE, REG_R8,   // Arg 2
                IARG_REG_VALUE, REG_R9,   // Arg 3
                IARG_REG_VALUE, REG_STACK_PTR, // RSP
                IARG_BOOL, INS_IsRet(ins), // <--- NEW: Tell the hook if this is a RET
                IARG_END);
        }
    }

    bool safeForAfter = !INS_IsControlFlow(ins) && !INS_IsSyscall(ins) && !INS_HasRealRep(ins);
    bool hasWrite = INS_IsMemoryWrite(ins);

    if (hasWrite) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TrackExecutableWriteBefore),
            IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
    }

    IARGLIST al = IARGLIST_Alloc();
    IARGLIST_AddArguments(al, IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_BOOL, mnemonicInteresting, IARG_BOOL, isPushImm, IARG_END);
    if (INS_IsMemoryRead(ins)) { IARGLIST_AddArguments(al, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END); }
    else { IARGLIST_AddArguments(al, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_END); }
    if (INS_HasMemoryRead2(ins)) { IARGLIST_AddArguments(al, IARG_MEMORYREAD2_EA, IARG_UINT32, INS_MemoryOperandSize(ins, 1), IARG_END); }
    else { IARGLIST_AddArguments(al, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_END); }
    if (hasWrite && !safeForAfter) { IARGLIST_AddArguments(al, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END); }
    else { IARGLIST_AddArguments(al, IARG_ADDRINT, 0, IARG_UINT32, 0, IARG_END); }
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Record), IARG_IARGLIST, al, IARG_END);
    IARGLIST_Free(al);

    if (gConcreteEnabled) {
        // Now Pin only generates the heavy context-saving assembly if the knob is actually ON
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(RecordConcreteBefore),
            IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_CONST_CONTEXT, IARG_END);

        if (safeForAfter) {
            INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(RecordConcreteAfter),
                IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_UINT32, INS_Size(ins), IARG_CONST_CONTEXT, IARG_END);
        }
    }

    if (hasWrite && safeForAfter) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(CaptureWriteAddr),
            IARG_THREAD_ID, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
        INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(RecordMemWriteAfter),
            IARG_THREAD_ID, IARG_ADDRINT, rip, IARG_UINT32, INS_MemoryWriteSize(ins), IARG_UINT32, INS_Size(ins), IARG_END);
    }
}

// -------------------- Lifecycle --------------------
static void ThreadStart(THREADID tid, CONTEXT* ctxt, INT32, VOID*) {
    auto* st = new ThreadState();
    st->tid = tid;
    if (gUseRing) st->ring.resize(gRingSize);
    st->gateOpen = gStartRipEnabled ? false : true;
 // st->regTaint.resize(REG_LAST, 0);
    PIN_SetThreadData(gTlsKey, st, tid);

    // On x64, GS base is the TEB.
    ADDRINT tebAddr = PIN_GetContextReg(ctxt, REG_SEG_GS_BASE);
    st->tebBase = tebAddr;

    if (gPebBase == 0) {
        if (tebAddr != 0) {
            // PEB is at TEB + 0x60
            ADDRINT pebPtr = tebAddr + 0x60;
            ADDRINT pebVal = 0;
            if (PIN_SafeCopy(&pebVal, (void*)pebPtr, sizeof(ADDRINT)) == sizeof(ADDRINT)) {
                gPebBase = pebVal;
                if (gPebEnabled && gVerbose) {
                    PIN_GetLock(&gLock, 0);
                    fprintf(gOut ? gOut : stdout, "[pinscan] Resolved PEB at %p\n", (void*)gPebBase);
                    PIN_ReleaseLock(&gLock);
                }
            }
        }
    }
    ExportStartupSnapshot(tid, ctxt, tebAddr, gPebBase);
}

// -------------------- Context Change / Exception Tracking --------------------

static VOID OnContextChange(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT* ctxtFrom, CONTEXT* ctxtTo, INT32 info, VOID* v) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->gateOpen) return;

    // We only care when an actual exception occurs
    if (reason == CONTEXT_CHANGE_REASON_EXCEPTION) {

        // Extract the exact IP where the fault occurred
        ADDRINT faultRip = PIN_GetContextReg(ctxtFrom, REG_INST_PTR);

        // Extract the IP where Windows is trying to route the thread (usually KiUserExceptionDispatcher)
        ADDRINT targetRip = PIN_GetContextReg(ctxtTo, REG_INST_PTR);

        if (st->exceptionFaultRip == faultRip &&
            st->exceptionDispatchRip == targetRip &&
            st->exceptionCode == info) {
            st->repeatedExceptionCount++;
        }
        else {
            st->repeatedExceptionCount = 1;
        }

        st->exceptionFaultRip = faultRip;
        st->exceptionDispatchRip = targetRip;
        st->exceptionCode = info;
        st->exceptionResumePending = true;
        st->exceptionDispatchSeen = false;
        st->exceptionDispatchSteps = 0;

        InstEntry e;
        e.seq = ++gSeqCounter;
        e.tid = tid;
        e.rip = faultRip;
        e.mod = "OS_EXCEPTION_DISPATCH";

        // 'info' contains the NTSTATUS exception code (e.g., 0xC0000005 for Access Violation)
        std::ostringstream oss;
        oss << "EXCEPTION_TRIGGERED <Fault_ADDR: " << Hex(faultRip)
            << " Dispatch_Target: " << Hex(targetRip)
            << " Exception_Code: " << Hex(info)
            << " repeat: " << st->repeatedExceptionCount;
        if (st->lastHandlerRegistrationSeq != 0 &&
            (gSeqCounter.load() - st->lastHandlerRegistrationSeq) <= 4096) {
            oss << " handler_reg_recent: yes"
                << " handler_reg_rip: " << Hex(st->lastHandlerRegistrationRip);
        }
        oss << ">";
        e.reason = oss.str();

        DispatchEntry(st, e);

        // Dump the lookback ring buffer to see the obfuscated instructions leading up to the crash
        if (gUseRing) {
            DumpWindow(st);
            st->dumping = true;
            st->postRemaining = gPostFollow;
        }
    }
}

static void ThreadFini(THREADID tid, const CONTEXT*, INT32 code, VOID*) {
    ThreadState* st = GetToolThreadState(tid);
    if (st && gUseRing) {
        InstEntry e; e.seq = ++gSeqCounter; e.tid = tid; e.rip = st->lastRip;
        std::ostringstream oss; oss << "THREAD_EXIT (Code: " << code << ")"; e.reason = oss.str();
        auto it = gStaticByRip.find(st->lastRip);
        if (it != gStaticByRip.end()) { e.dis = it->second.dis; e.mod = it->second.mod; e.rva = it->second.rva; }

        if (st->ring.empty()) st->ring.resize(gRingSize);
        st->ring[st->next] = e;
        st->next = (st->next + 1) % gRingSize;
        if (st->next == 0) st->filled = true;

        st->dumping = true;
        DumpWindow(st);

        PIN_GetLock(&gLock, 0);
        if (gOut) { std::fprintf(gOut, "=== END OF THREAD tid=%u ===\n", (unsigned)tid); std::fflush(gOut); }
        PIN_ReleaseLock(&gLock);
    }
    delete st;
    PIN_SetThreadData(gTlsKey, nullptr, tid);
}

static void ImageLoad(IMG img, VOID* v) {
    (void)v;
    std::string name = IMG_Name(img);
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });
    PIN_GetLock(&gLock, 0);
    gKnownImageBases.insert(IMG_StartAddress(img));
    gKnownImageBases.insert(IMG_LowAddress(img));
    PIN_ReleaseLock(&gLock);
    if (IMG_HighAddress(img) >= IMG_LowAddress(img)) {
        InvalidatePageMetadataRange(IMG_LowAddress(img), (IMG_HighAddress(img) - IMG_LowAddress(img)) + 1);
    }
    ResolveBootstrapSymbols(img);
    if (name.find("ntdll.dll") != std::string::npos) {
        ParseSyscallsFromDisk();
        if (gVerbose && gOut) {
            PIN_GetLock(&gLock, 0);
            fprintf(gOut, "[pinscan] Resolved %u syscalls directly from disk image\n", (unsigned int)gSyscallNames.size());
            PIN_ReleaseLock(&gLock);
        }
    }
    if (IMG_IsMainExecutable(img))
    {
        g_MainExeLow = IMG_LowAddress(img);
        g_MainExeHigh = IMG_HighAddress(img);

        ParseTlsFromDisk(IMG_Name(img)); // Read TLS callbacks from disk image to catch early
        if (!gTlsCallbackRvas.empty() && gOut) {
            PIN_GetLock(&gLock, 0);
            fprintf(gOut, "[pinscan] Discovered %zu TLS Callbacks\n", gTlsCallbackRvas.size());
            PIN_ReleaseLock(&gLock);
        }

        // Print to log to confirm it captured correctly
        if (gOut) {
		    fprintf(gOut, "[pinscan] Main Module Range: %s-%s\n", Hex(g_MainExeLow).c_str(), Hex(g_MainExeHigh).c_str());
        }
    }
    ADDRINT ep = IMG_EntryAddress(img);
    if (ep != 0 && !IMG_IsMainExecutable(img)) {
        std::string fullName = IMG_Name(img);
        std::string lowerName = fullName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), [](unsigned char c) { return std::tolower(c); });

        // Filter out standard Windows subsystems to prevent SMC thrashing
        if (lowerName.find("windows\\system32") == std::string::npos &&
            lowerName.find("windows\\syswow64") == std::string::npos) {

            PIN_GetLock(&g_EpLock, 1);
            g_DllEntryPoints[ep] = fullName;
            PIN_ReleaseLock(&g_EpLock);

            // Optional console heartbeat
            std::cerr << "[pinscan] Grabbed EP for " << fullName << " at 0x" << std::hex << ep << "\n";
        }
    }
    if (IMG_Name(img).find("ntdll.dll") != std::string::npos) {
        RTN allocRtn = RTN_FindByName(img, "NtAllocateVirtualMemory");
        if (RTN_Valid(allocRtn)) {
            RTN_Open(allocRtn);

            // Hook Entry: Grab Arg 1 (BaseAddress ptr) and Arg 3 (RegionSize ptr)
            RTN_InsertCall(allocRtn, IPOINT_BEFORE, (AFUNPTR)NtAllocateEntry,
                IARG_THREAD_ID,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_END);

            // Hook Exit: Grab the NTSTATUS return value
            RTN_InsertCall(allocRtn, IPOINT_AFTER, (AFUNPTR)NtAllocateExit,
                IARG_THREAD_ID,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);

            RTN_Close(allocRtn);
        }
    }
}

static void InitSyscallTable() {
    for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
        ImageLoad(img, nullptr);
    }
}

// -------------------- Multi-Process Tracking --------------------

static BOOL FollowChild(CHILD_PROCESS cProcess, VOID* userData) {
    UINT32 parentPid = PIN_GetPid();

    // Extract the exact command line the sample is using to spawn the child
    std::string cmdLine = "unknown_command_line";

    // Pin provides an API to get the command line arguments safely
    INT argc;
    const CHAR* const* argv;
    CHILD_PROCESS_GetCommandLine(cProcess, &argc, &argv);

    if (argc > 0 && argv != nullptr) {
        cmdLine = "";
        for (INT i = 0; i < argc; ++i) {
            cmdLine += argv[i];
            if (i < argc - 1) cmdLine += " ";
        }
    }

    // Log the lateral movement attempt in the parent's log
    PIN_GetLock(&gLock, 0);
    if (gOut) {
        std::fprintf(gOut, "\n[LATERAL MOVEMENT] Parent PID: %u is spawning a Child Process!\n", parentPid);
        std::fprintf(gOut, "  -> Child Command Line: %s\n", cmdLine.c_str());
        std::fprintf(gOut, "  -> Action: Injecting Pinscan into Child...\n\n");
        std::fflush(gOut);
    }
    PIN_ReleaseLock(&gLock);

    // Returning TRUE instructs Pin to automatically prepend the Pin framework 
    // and our pinscan.dll to the child's execution command, seamlessly 
    // instrumenting the new process with the exact same configuration knobs.
    return TRUE;
}

static void Fini(INT32 code, void*) {
    PIN_GetLock(&gLock, 0);
    if (gOut) {
        std::fprintf(gOut, "\n========================================\n");
        std::fprintf(gOut, "[!] PROCESS TERMINATED\n");
        std::fprintf(gOut, "[!] Final Exit Code: 0x%X (%d)\n", code, code);

        // Quick lookup for common DRM/Crash codes
        if (code == 0xC0000005) std::fprintf(gOut, "    -> STATUS_ACCESS_VIOLATION\n");
        else if (code == 0xC0000409) std::fprintf(gOut, "    -> STATUS_STACK_BUFFER_OVERRUN (Fast Fail)\n");
        else if (code == 0x40010006) std::fprintf(gOut, "    -> DBG_PRINTEXCEPTION_C\n");

        std::fprintf(gOut, "========================================\n");

        std::fflush(gOut);
        std::fclose(gOut);
    }
    if (gOutJson) std::fclose(gOutJson);
    if (gConcreteTraceFile) {
        std::fflush(gConcreteTraceFile);
        std::fclose(gConcreteTraceFile);
    }
    if (gTraceGuiCsvFile) {
        std::fflush(gTraceGuiCsvFile);
        std::fclose(gTraceGuiCsvFile);
    }
    PIN_ReleaseLock(&gLock);
}

static INT32 Usage() {
    std::fprintf(stderr, "[pinscan] startup failed during PIN_Init. Check RC1 knob names: -ps_mode, -ps_log_level, -ps_scope, -ps_ring_size, -ps_post_size.\n");
    return -1;
}

static void PrintConfigBanner() {
    PIN_GetLock(&gLock, 0);
    if (gOut) {
        std::fprintf(gOut, "  Pinscan Binary Instrumentation Tool - Build Date/Time: %s %s\n", __DATE__, __TIME__); 
        std::fprintf(gOut, "  \n  Running Configuration\n\n");
        std::fprintf(gOut, "  %-60s = %s\n", "version", "RC2");
        std::fprintf(gOut, "  %-60s = %s\n", "mode - trigger, ring, or stream", CurrentModeName());
        std::fprintf(gOut, "  %-60s = %u\n", "log_level - 0 concise, 1 standard, 2 verbose", gLogLevel);
        std::fprintf(gOut, "  %-60s = %s\n", "scope - main, all, or named module", CurrentScopeName());
		std::fprintf(gOut, "  %-60s = %u\n", "heartbeat - status interval (instructions)", gHeartbeatInterval);
        if (gUseRing) {
            std::fprintf(gOut, "  %-60s = %u\n", "ring_size - ring buffer for post-trigger", gRingSize);
            std::fprintf(gOut, "  %-60s = %u\n", "post_size - instructions after trigger to record", gPostFollow);
        }

        std::fprintf(gOut, "  %-60s = %s\n", "start - address to start instrumentation",
            gStartRipEnabled ? (gStartGateDisabled ? "never" : Hex(gStartRip).c_str()) : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "stop - address to stop instrumentation",
            gStopRipEnabled ? Hex(gStopRip).c_str() : "disabled");
		std::fprintf(gOut, "  %-60s = %s\n", "max_lines - max instructions to log (0 for unlimited)", gMaxLinesPrinted > 0 ? std::to_string(gMaxLinesPrinted).c_str() : "unlimited");
		std::fprintf(gOut, "  %-60s = %s\n", "concrete - record concrete memory values", gConcreteEnabled ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "ps_tracegui_csv - TraceGui CSV output", gTraceGuiCsvFile ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "kuser - show/resolve KUSER_SHARED_DATA reads", gKuserEnabled ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "rdtsc - record rdtsc instruction", gTimingEnabled ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "syscall - show/resolve syscalls", gSyscallEnabled ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "api - show API calls", gApiEnabled ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "peb - show PEB reads and resolve fields", gPebEnabled ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "spoof_time - spoof rdtsc/KUSER InterruptTiming", gSpoofTimeEnabled ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "cpuid_rewrite - rewrite CPUID output registers", KnobCpuidRewrite.Value() ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "ps_profile - semantic profile set", gProfile.empty() ? "disabled" : gProfile.c_str());
        std::fprintf(gOut, "  %-60s = %s\n", "cf_dump - gated control-flow dump", gCfDumpEnabled ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "cf_provenance - indirect call/ret provenance", gCfProvenanceEnabled ? "enabled" : "disabled");
        std::fprintf(gOut, "  %-60s = %s\n", "ps_export_dir - Pushan-friendly witness export", gExportDir.empty() ? "disabled" : gExportDir.c_str());
        std::fprintf(gOut, "  %-60s = %s\n", "loop_window - size of the loop detection window", gLoopWindowSize > 0 ? std::to_string(gLoopWindowSize).c_str() : "disabled");

        bool anyMemTrig = false;
        for (size_t i = 0; i < kMaxMemTriggers; ++i) {
            if (!gMemTriggers[i].enabled) continue;
            anyMemTrig = true;
            std::string mode = "RW";
            if (gMemTriggers[i].onRead && !gMemTriggers[i].onWrite) mode = "R";
            if (!gMemTriggers[i].onRead && gMemTriggers[i].onWrite) mode = "W";

            std::string wStr = (gMemTriggers[i].width == 0) ? "any" : std::to_string(gMemTriggers[i].width);

            std::fprintf(gOut, "  mem_trigger[%zu] = base=%s size=%s (%u bytes) width=%s mode=%s\n",
                i + 1, Hex(gMemTriggers[i].base).c_str(), Hex(gMemTriggers[i].size).c_str(), gMemTriggers[i].size, wStr.c_str(), mode.c_str());
        }
        if (!anyMemTrig) std::fprintf(gOut, "  %-60s = %s\n", "Memory triggers", "disabled");
        std::fflush(gOut);
    }
    PIN_ReleaseLock(&gLock);
}

int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();
    gPid = PIN_GetPid();
    gMode = ParseEffectiveMode();
    gLogLevel = ParseEffectiveLogLevel();
    gScope = ParseEffectiveScope();
    gStreamMode = (gMode == "stream");
    gUseRing = (gMode == "ring");
    UINT32 configuredRingSize = KnobRingSizeUnified.Value() != 0 ? KnobRingSizeUnified.Value() : KnobRingSize.Value();
    gRingSize = configuredRingSize;
    if (gRingSize < 64) gRingSize = 64;
    gPostFollow = gUseRing ? (KnobPostSizeUnified.Value() != 0 ? KnobPostSizeUnified.Value() : KnobPostFollow.Value()) : 0;
    gConciseEnabled = (gLogLevel == 0);
    gVerbose = (gLogLevel >= 2);
    if (gScope == "all") {
        gMainOnly = false;
        gNamed.clear();
    }
    else if (gScope == "main") {
        gMainOnly = true;
        gNamed.clear();
    }
    else {
        gMainOnly = true;
        gNamed = gScope;
    }
    gKuserEnabled = KnobKuser.Value();
    gTimingEnabled = KnobTiming.Value();
    gSyscallEnabled = KnobSyscall.Value();
	gApiEnabled = KnobTraceApi.Value();
    gSpoofTimeEnabled = KnobSpoofTime.Value();
    gPebEnabled = KnobPeb.Value();
    gHeartbeatInterval = KnobHeartbeat.Value();
    gProfile = KnobProfile.Value();
    gExportDir = KnobExportDir.Value();
    gConcreteEnabled = KnobConcrete.Value();
    gLoopWindowSize = KnobLoopWindow.Value();
	if (gLoopWindowSize > 256) gLoopWindowSize = 256;
    gMaxLinesPrinted = KnobMaxLines.Value();
    ProfileToggles profile = ParseSemanticProfile(gProfile);
    gApiEnabled = gApiEnabled || profile.api;
    gSyscallEnabled = gSyscallEnabled || profile.syscall;
    gKuserEnabled = gKuserEnabled || profile.kuser;
    gPebEnabled = gPebEnabled || profile.peb;
    gTimingEnabled = gTimingEnabled || profile.timing;
    gCfDumpEnabled = KnobCFDump.Value() || profile.cfDump;
    gCfProvenanceEnabled = gCfDumpEnabled || profile.provenance;

 

    gStartTime = std::chrono::steady_clock::now();
    if (!gExportDir.empty()) {
#ifdef _WIN32
        CreateDirectoryA(gExportDir.c_str(), nullptr);
#endif
        gTriggerJsonlPath = JoinPath(gExportDir, "pinscan_triggers_PID" + std::to_string(gPid) + ".jsonl");
        gTargetJsonlPath = JoinPath(gExportDir, "pinscan_targets_PID" + std::to_string(gPid) + ".jsonl");
        gSnapshotJsonlPath = JoinPath(gExportDir, "pinscan_snapshots_PID" + std::to_string(gPid) + ".jsonl");
        gStartupJsonlPath = JoinPath(gExportDir, "pinscan_startup_PID" + std::to_string(gPid) + ".jsonl");
        gMemoryEventJsonlPath = JoinPath(gExportDir, "pinscan_memory_events_PID" + std::to_string(gPid) + ".jsonl");
        gAntiAnalysisJsonlPath = JoinPath(gExportDir, "pinscan_antianalysis_PID" + std::to_string(gPid) + ".jsonl");
    }

    auto parseHex = [&](const std::string& s, ADDRINT& val) -> bool {
        if (s.empty() || s == "0") return false;
        std::string t = (s.find("0x") == 0 || s.find("0X") == 0) ? s.substr(2) : s;
        char* end = nullptr; val = std::strtoull(t.c_str(), &end, 16);
        return (end && *end == '\0');
        };

    auto parseHexAllowZero = [&](const std::string& s, ADDRINT& val) -> bool {
        if (s.empty()) return false;
        std::string t = (s.find("0x") == 0 || s.find("0X") == 0) ? s.substr(2) : s;
        if (t.empty()) return false;
        char* end = nullptr; val = std::strtoull(t.c_str(), &end, 16);
        return (end && *end == '\0');
        };

    UINT32 cpuidRewriteMask = CPUID_REG_NONE;
    ADDRINT cpuidRewriteEax = 0;
    ADDRINT cpuidRewriteEbx = 0;
    ADDRINT cpuidRewriteEcx = 0;
    ADDRINT cpuidRewriteEdx = 0;
    if (parseHexAllowZero(KnobCpuidEax.Value(), cpuidRewriteEax)) cpuidRewriteMask |= CPUID_REG_RAX;
    if (parseHexAllowZero(KnobCpuidEbx.Value(), cpuidRewriteEbx)) cpuidRewriteMask |= CPUID_REG_RBX;
    if (parseHexAllowZero(KnobCpuidEcx.Value(), cpuidRewriteEcx)) cpuidRewriteMask |= CPUID_REG_RCX;
    if (parseHexAllowZero(KnobCpuidEdx.Value(), cpuidRewriteEdx)) cpuidRewriteMask |= CPUID_REG_RDX;
    ConfigureCpuidRewrite(KnobCpuidRewrite.Value(), cpuidRewriteMask,
        cpuidRewriteEax, cpuidRewriteEbx, cpuidRewriteEcx, cpuidRewriteEdx);

    if ((KnobStart.Value() == "never")) {
        gStartGateDisabled = true; 
        gStartRipEnabled = true; 
    }
    else if (parseHex(KnobStart.Value(), gStartRip)) gStartRipEnabled = true;

    auto parseTrig = [&](const std::string& b, const std::string& s, const std::string& t, const std::string& w, MemTrigger& mt) {
        if (parseHex(b, mt.base) && parseHex(s, (ADDRINT&)mt.size)) {
            std::string type = t; for (char& c : type) c = toupper((unsigned char)c);
            if (type.empty()) type = "RW";
            if (type.find('R') != std::string::npos) mt.onRead = true;
            if (type.find('W') != std::string::npos) mt.onWrite = true;
            mt.enabled = (mt.onRead || mt.onWrite);

            ADDRINT width = 0;
            if (parseHex(w, width)) mt.width = (UINT32)width;
        }
        };

    parseTrig(KnobMemTrigBase1.Value(), KnobMemTrigSize1.Value(), KnobMemTrigType1.Value(), KnobMemTrigWidth1.Value(), gMemTriggers[0]);
    parseTrig(KnobMemTrigBase2.Value(), KnobMemTrigSize2.Value(), KnobMemTrigType2.Value(), KnobMemTrigWidth2.Value(), gMemTriggers[1]);
    parseTrig(KnobMemTrigBase3.Value(), KnobMemTrigSize3.Value(), KnobMemTrigType3.Value(), KnobMemTrigWidth3.Value(), gMemTriggers[2]);
    PIN_InitLock(&gLock);
    PIN_InitLock(&g_ApiCacheLock);
    PIN_InitLock(&g_HandleMapLock);
    PIN_InitLock(&g_ExecPageLock);
    PIN_InitLock(&g_PageMetaLock);
    gTlsKey = PIN_CreateThreadDataKey(nullptr);

    UINT32 pid = PIN_GetPid();

    std::string outTxtPath = KnobOut.Value();
    std::string outJsonPath = KnobOutJson.Value();

    std::string concreteTracePath = KnobConcreteTrace.Value();
    std::string traceGuiCsvPath = KnobTraceGuiCsv.Value();

    if (!concreteTracePath.empty()) {
        size_t dot = concreteTracePath.find_last_of('.');
        if (dot != std::string::npos) concreteTracePath.insert(dot, "_" + std::to_string(pid));
        else concreteTracePath += "_" + std::to_string(pid) + ".jsonl";

        gConcreteTraceFile = std::fopen(concreteTracePath.c_str(), "w");
        // Disable standard C buffering to prevent lost data if the DRM intentionally crashes
        if (gConcreteTraceFile) setvbuf(gConcreteTraceFile, nullptr, _IONBF, 0);
        PIN_InitLock(&gConcreteTraceLock);
    }

    if (!traceGuiCsvPath.empty()) {
        size_t dot = traceGuiCsvPath.find_last_of('.');
        if (dot != std::string::npos) traceGuiCsvPath.insert(dot, "_" + std::to_string(pid));
        else traceGuiCsvPath += "_" + std::to_string(pid) + ".csv";

        gTraceGuiCsvFile = std::fopen(traceGuiCsvPath.c_str(), "w");
        if (gTraceGuiCsvFile) {
            setvbuf(gTraceGuiCsvFile, nullptr, _IOFBF, 4 * 1024 * 1024);
            std::fprintf(gTraceGuiCsvFile, "Index,Address,Bytes,Disassembly,Registers,Memory,Comments\n");
            gConcreteEnabled = true;
        }
        PIN_InitLock(&gTraceGuiCsvLock);
    }

    if (!outTxtPath.empty()) {
        size_t dot = outTxtPath.find_last_of('.');
        if (dot != std::string::npos) outTxtPath.insert(dot, "_" + std::to_string(pid));
        else outTxtPath += "_" + std::to_string(pid);

        gOut = std::fopen(outTxtPath.c_str(), "w");
        if (gOut) setvbuf(gOut, nullptr, _IONBF, 0);
    }

    if (outJsonPath != "none") {
        size_t dot = outJsonPath.find_last_of('.');
        if (dot != std::string::npos) outJsonPath.insert(dot, "_" + std::to_string(pid));
        else outJsonPath += "_" + std::to_string(pid);

        gOutJson = std::fopen(outJsonPath.c_str(), "w");
    }
    InitSyscallTable();
    PrintConfigBanner();
    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    INS_AddInstrumentFunction(InstrumentInstruction, nullptr);
    PIN_AddThreadStartFunction(ThreadStart, nullptr);
    PIN_AddThreadFiniFunction(ThreadFini, nullptr);
    PIN_AddContextChangeFunction(OnContextChange, nullptr);
    PIN_AddFollowChildProcessFunction(FollowChild, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);
    PIN_StartProgram();
    return 0;
}
