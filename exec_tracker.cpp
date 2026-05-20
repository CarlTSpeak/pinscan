#include "pinscan_globals.h"
#include "exec_tracker.h"
#include <sstream>
#include <iostream>

// --- External Dependencies (Currently living in pinscan.cpp) ---
extern ThreadState* GetToolThreadState(THREADID tid);
// ---------------------------------------------------------------

#ifdef _WIN32
extern "C" {
    static const unsigned long PROT_MEM_IMAGE = 0x1000000;
    static const unsigned long PROT_MEM_PRIVATE = 0x20000;
    static const unsigned long PROT_PAGE_EXECUTE = 0x10;
    static const unsigned long PROT_PAGE_EXECUTE_READ = 0x20;
    static const unsigned long PROT_PAGE_EXECUTE_READWRITE = 0x40;
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
}
#endif

// -------------------- Memory State Helpers --------------------

static std::string ProtectToString(unsigned long prot) {
    unsigned long p = prot & 0xFF;
    if (p == PROT_PAGE_EXECUTE) return "X";
    if (p == PROT_PAGE_EXECUTE_READ) return "RX";
    if (p == PROT_PAGE_EXECUTE_READWRITE) return "RWX";
    if (p == PROT_PAGE_READWRITE) return "RW";
    if (p == PROT_PAGE_READONLY) return "R";
    return "---";
}

static std::string RegionTypeToString(unsigned long type) {
    return (type == PROT_MEM_IMAGE) ? "IMG" : (type == PROT_MEM_PRIVATE) ? "PRV" : "MAP";
}

static bool IsExecutableProtect(unsigned long prot) {
    unsigned long p = prot & 0xFF;
    return p == PROT_PAGE_EXECUTE ||
        p == PROT_PAGE_EXECUTE_READ ||
        p == PROT_PAGE_EXECUTE_READWRITE ||
        p == 0x80;
}

static void FillPageMetadataFromMbi(ADDRINT pageBase, const PINSCAN_MBI& mbi, PageMetadata& meta) {
    meta.pageBase = pageBase;
    meta.allocBase = (ADDRINT)mbi.AllocationBase;
    meta.regionSize = (ADDRINT)mbi.RegionSize;
    meta.protect = mbi.Protect;
    meta.type = mbi.Type;
    meta.executable = IsExecutableProtect(mbi.Protect);

    PIN_GetLock(&gLock, 0);
    meta.knownImage = (meta.allocBase != 0 && gKnownImageBases.find(meta.allocBase) != gKnownImageBases.end());
    PIN_ReleaseLock(&gLock);

    if (!meta.executable || meta.allocBase == 0 || meta.knownImage) {
        meta.mzChecked = true;
        meta.hasMz = false;
    }
    else {
        meta.mzChecked = false;
        meta.hasMz = false;
    }
    meta.dirty = false;
}

static bool GetPageMetadata(ADDRINT addr, PageMetadata& outMeta, bool allowRefresh) {
#ifdef _WIN32
    ADDRINT pageBase = addr & ~0xFFFULL;

    PIN_GetLock(&g_PageMetaLock, 0);
    auto it = gPageMetadata.find(pageBase);
    if (it != gPageMetadata.end() && !it->second.dirty) {
        outMeta = it->second;
        PIN_ReleaseLock(&g_PageMetaLock);
        return true;
    }
    PIN_ReleaseLock(&g_PageMetaLock);

    if (!allowRefresh) return false;

    PINSCAN_MBI mbi = { 0 };
    if (!VirtualQuery((const void*)addr, &mbi, sizeof(mbi))) return false;

    PageMetadata refreshed;
    FillPageMetadataFromMbi(pageBase, mbi, refreshed);

    PIN_GetLock(&g_PageMetaLock, 0);
    gPageMetadata[pageBase] = refreshed;
    outMeta = refreshed;
    PIN_ReleaseLock(&g_PageMetaLock);
    return true;
#else
    (void)addr;
    (void)outMeta;
    (void)allowRefresh;
    return false;
#endif
}

void InvalidatePageMetadataRange(ADDRINT base, ADDRINT size) {
    if (base == 0 || size == 0) return;
    ADDRINT start = base & ~0xFFFULL;
    ADDRINT end = (base + size - 1) & ~0xFFFULL;
    std::vector<ADDRINT> invalidatedBases;

    PIN_GetLock(&g_PageMetaLock, 0);
    for (ADDRINT page = start; page <= end; page += 0x1000) {
        auto it = gPageMetadata.find(page);
        if (it != gPageMetadata.end()) {
            if (it->second.allocBase != 0) invalidatedBases.push_back(it->second.allocBase);
            it->second.dirty = true;
            it->second.mzChecked = false;
            it->second.hasMz = false;
        }
    }
    PIN_ReleaseLock(&g_PageMetaLock);

    if (!invalidatedBases.empty()) {
        PIN_GetLock(&gLock, 0);
        for (ADDRINT allocBase : invalidatedBases) gFlaggedMzBases.erase(allocBase);
        PIN_ReleaseLock(&gLock);
    }
}

void GetMemInfo(ADDRINT rip, std::string& outType, ADDRINT& outBase) {
    outType = "unknown_mem";
    outBase = 0;
#ifdef _WIN32
    PageMetadata meta;
    if (GetPageMetadata(rip, meta, true)) {
        outType = RegionTypeToString(meta.type) + "_" + ProtectToString(meta.protect);
        outBase = meta.allocBase;
    }
#else
    (void)rip;
#endif
}

static bool RegionHasMzHeader(ADDRINT base) {
    UINT16 mz = 0;
    return PIN_SafeCopy(&mz, (void*)base, sizeof(mz)) == sizeof(mz) && mz == 0x5A4D;
}

bool CheckHiddenExecutableMzRegionCached(ADDRINT addr, std::string& outReason, bool allowRefresh) {
#ifdef _WIN32
    PageMetadata meta;
    if (!GetPageMetadata(addr, meta, allowRefresh)) return false;
    if (!meta.executable || meta.allocBase == 0 || meta.knownImage) return false;

    PIN_GetLock(&gLock, 0);
    bool alreadyFlagged = (gFlaggedMzBases.find(meta.allocBase) != gFlaggedMzBases.end());
    PIN_ReleaseLock(&gLock);
    if (alreadyFlagged) return false;

    bool shouldProbe = false;
    PIN_GetLock(&g_PageMetaLock, 0);
    auto it = gPageMetadata.find(meta.pageBase);
    if (it != gPageMetadata.end()) {
        if (it->second.dirty) {
            PIN_ReleaseLock(&g_PageMetaLock);
            if (!allowRefresh || !GetPageMetadata(addr, meta, true)) return false;
            PIN_GetLock(&g_PageMetaLock, 0);
            it = gPageMetadata.find(meta.pageBase);
        }
        if (it != gPageMetadata.end()) {
            meta = it->second;
            if (!it->second.mzChecked) shouldProbe = true;
        }
    }
    PIN_ReleaseLock(&g_PageMetaLock);

    if (shouldProbe) {
        bool hasMz = RegionHasMzHeader(meta.allocBase);
        PIN_GetLock(&g_PageMetaLock, 0);
        auto wit = gPageMetadata.find(meta.pageBase);
        if (wit != gPageMetadata.end()) {
            wit->second.mzChecked = true;
            wit->second.hasMz = hasMz;
            meta = wit->second;
        }
        PIN_ReleaseLock(&g_PageMetaLock);
    }

    if (!meta.hasMz) return false;

    PIN_GetLock(&gLock, 0);
    gFlaggedMzBases.insert(meta.allocBase);
    PIN_ReleaseLock(&gLock);

    std::ostringstream oss;
    oss << "exec_mz_outside_loader_list <addr: " << Hex(addr)
        << " alloc_base: " << Hex(meta.allocBase)
        << " size: " << Hex(meta.regionSize)
        << " type: " << ((meta.type == PROT_MEM_PRIVATE) ? "PRIVATE" : (meta.type == PROT_MEM_IMAGE) ? "IMAGE" : "MAPPED")
        << " prot: " << DecodeProt(meta.protect) << ">";
    outReason = oss.str();
    return true;
#else
    (void)addr;
    (void)allowRefresh;
    outReason.clear();
    return false;
#endif
}

// -------------------- OS Allocations & Snapshots --------------------

VOID NtAllocateEntry(THREADID tid, ADDRINT* pBaseAddress, size_t* pRegionSize) {
    if (ThreadState* st = GetToolThreadState(tid)) {
        st->pendingAllocBasePtr = pBaseAddress;
        st->pendingAllocSizePtr = pRegionSize;
    }
}

VOID NtAllocateExit(THREADID tid, ADDRINT status) {
    if (status == 0) { // NT_SUCCESS
        ThreadState* st = GetToolThreadState(tid);
        if (st && st->pendingAllocBasePtr && st->pendingAllocSizePtr) {
            ADDRINT base = 0;
            size_t size = 0;

            if (PIN_SafeCopy(&base, st->pendingAllocBasePtr, sizeof(ADDRINT)) == sizeof(ADDRINT) &&
                PIN_SafeCopy(&size, st->pendingAllocSizePtr, sizeof(size_t)) == sizeof(size_t)) {

                // Note: tid + 1 prevents Pin from complaining about a 0-value lock ID
                PIN_GetLock(&g_AllocationLock, tid + 1);
                g_TrackedAllocations[base] = size;
                PIN_ReleaseLock(&g_AllocationLock);
            }

            // Clean up the pointers so they don't leak into future calls
            st->pendingAllocBasePtr = nullptr;
            st->pendingAllocSizePtr = nullptr;
        }
    }
}

VOID ExecuteSnapshot(THREADID tid, const CONTEXT* ctxt, const char* prefix) {
    PIN_GetLock(&g_AllocationLock, tid);
    std::cout << "[*] Snapshot triggered! Dumping process state (" << prefix << ")..." << std::endl;

    // 1. Dump Registers (using your existing ContextRegsJson logic)

    // 2. Dump TEB and OS Structures
    ADDRINT tebBase = PIN_GetContextReg(const_cast<CONTEXT*>(ctxt), REG_SEG_GS_BASE);
    DumpMemoryToBinary(std::string(prefix) + "_snap_teb.bin", tebBase, 0x2000);

    if (gPebBase != 0) {
        DumpMemoryToBinary(std::string(prefix) + "_snap_peb.bin", gPebBase, 0x1000);
    }

    // 3. Dump the Full Stack Space
    ADDRINT stack_base = 0;
    ADDRINT stack_limit = 0;
    PIN_SafeCopy(&stack_base, reinterpret_cast<void*>(tebBase + 0x8), sizeof(ADDRINT));
    PIN_SafeCopy(&stack_limit, reinterpret_cast<void*>(tebBase + 0x10), sizeof(ADDRINT));
    if (stack_base > stack_limit) {
        DumpMemoryToBinary(std::string(prefix) + "_snap_stack.bin", stack_limit, stack_base - stack_limit);
    }

    // 4. Dump all tracked dynamically allocated memory
    int alloc_idx = 0;
    for (const auto& pair : g_TrackedAllocations) {
        std::string filename = std::string(prefix) + "_snap_alloc_" + std::to_string(alloc_idx++) + ".bin";
        DumpMemoryToBinary(filename, pair.first, pair.second);
    }

    for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
        if (IMG_IsMainExecutable(img)) {
            ADDRINT imgBase = IMG_LowAddress(img);
            size_t imgSize = IMG_HighAddress(img) - imgBase;
            DumpMemoryToBinary(std::string(prefix) + "_snap_module.bin", imgBase, imgSize);
            break;
        }
    }

    PIN_ReleaseLock(&g_AllocationLock);

    // DELIBERATELY REMOVED PIN_ExitApplication(0) so execution can continue to the stop gate
}

// -------------------- SMC & Execution Tracking --------------------

void TrackExceptionResume(THREADID tid, ADDRINT rip) {
    ThreadState* st = GetToolThreadState(tid);
    if (!st || !st->gateOpen || !st->exceptionResumePending) return;

    if (rip == st->exceptionDispatchRip) {
        st->exceptionDispatchSeen = true;
        st->exceptionDispatchSteps = 0;
        return;
    }

    if (!st->exceptionDispatchSeen) return;

    st->exceptionDispatchSteps++;
    if (st->exceptionDispatchSteps < 4) return;

    std::string memType;
    ADDRINT allocBase = 0;
    GetMemInfo(rip, memType, allocBase);

    LogSemanticAlert(tid, rip, "EXCEPTION_RESUME <fault: " + Hex(st->exceptionFaultRip) +
        " dispatch: " + Hex(st->exceptionDispatchRip) +
        " resume: " + Hex(rip) +
        " code: " + Hex((ADDRINT)(UINT32)st->exceptionCode) +
        " repeat: " + std::to_string(st->repeatedExceptionCount) +
        " mem: " + memType +
        (allocBase ? " base: " + Hex(allocBase) : "") + ">");

    st->exceptionResumePending = false;
    st->exceptionDispatchSeen = false;
    st->exceptionDispatchSteps = 0;
}

void TrackExecutableWriteBefore(THREADID tid, ADDRINT rip, ADDRINT addr, UINT32 size) {
#ifdef _WIN32
    PINSCAN_MBI mbi = { 0 };
    if (!VirtualQuery((const void*)addr, &mbi, sizeof(mbi))) return;
    InvalidatePageMetadataRange(addr, size ? size : 1);
    if (!IsExecutableProtect(mbi.Protect)) return;

    ADDRINT pageBase = addr & ~0xFFFULL;
    PIN_GetLock(&g_ExecPageLock, tid + 1);
    ExecPageState& state = gExecPageStates[pageBase];
    if (!state.pendingExec) {
        state.before.clear();
        if (!SnapshotPage(pageBase, state.before)) {
            gExecPageStates.erase(pageBase);
            PIN_ReleaseLock(&g_ExecPageLock);
            return;
        }
        state.generation++;
        state.writeCount = 0;
        state.firstExecTid = 0;
        state.firstExecRip = 0;
        state.executeCount = 0;
        state.firstBranchSourceRip = 0;
        state.inboundSources.clear();
        state.handlerPoolLogged = false;
    }
    state.writerTid = tid;
    state.writerRip = rip;
    state.writeCount++;
    state.pendingExec = true;
    PIN_ReleaseLock(&g_ExecPageLock);
#else
    (void)tid; (void)rip; (void)addr;
#endif
}

// Checks if page generation changes since last execution, if so captures state and logs diff

void CheckFirstExecutionAfterWrite(THREADID tid, ADDRINT rip) {
    ADDRINT pageBase = rip & ~0xFFFULL;
    std::vector<ExecRegionPageSnapshot> pages;

    PIN_GetLock(&g_ExecPageLock, tid + 1);
    auto seedIt = gExecPageStates.find(pageBase);
    if (seedIt == gExecPageStates.end() || !seedIt->second.pendingExec) {
        PIN_ReleaseLock(&g_ExecPageLock);
        return;
    }

    ADDRINT regionStart = pageBase;
    ADDRINT walk = pageBase;
    while (walk >= 0x1000) {
        ADDRINT prev = walk - 0x1000;
        auto prevIt = gExecPageStates.find(prev);
        if (prevIt == gExecPageStates.end() || !prevIt->second.pendingExec) break;
        regionStart = prev;
        walk = prev;
    }

    ADDRINT regionEnd = pageBase;
    walk = pageBase;
    for (;;) {
        ADDRINT next = walk + 0x1000;
        auto nextIt = gExecPageStates.find(next);
        if (nextIt == gExecPageStates.end() || !nextIt->second.pendingExec) break;
        regionEnd = next;
        walk = next;
    }

    for (ADDRINT current = regionStart; current <= regionEnd; current += 0x1000) {
        auto it = gExecPageStates.find(current);
        if (it == gExecPageStates.end() || !it->second.pendingExec) continue;
        if (it->second.firstExecRip == 0) {
            it->second.firstExecRip = rip;
            it->second.firstExecTid = tid;
        }
        it->second.executeCount++;
        it->second.pendingExec = false;

        ExecRegionPageSnapshot page;
        page.pageBase = current;
        page.state = it->second;
        pages.push_back(page);
    }
    PIN_ReleaseLock(&g_ExecPageLock);

    if (pages.empty()) return;

    std::vector<UINT8> regionBefore;
    std::vector<UINT8> regionAfter;
    UINT32 totalChangedBytes = 0;
    size_t processedPages = 0;
    std::string singlePageDiff;
    uint64_t minGeneration = UINT64_MAX;
    uint64_t maxGeneration = 0;
    std::ostringstream pageLineage;

    for (size_t i = 0; i < pages.size(); ++i) {
        ExecRegionPageSnapshot& page = pages[i];
        if (page.state.before.empty() || !SnapshotPage(page.pageBase, page.after)) {
            continue;
        }
        page.beforeHash = HashBytes(page.state.before.data(), page.state.before.size());
        page.afterHash = HashBytes(page.after.data(), page.after.size());
        page.changedBytes = CountPageDiffBytes(page.state.before, page.after);
        page.diff = (page.changedBytes <= 32) ? FormatPageDiff(page.state.before, page.after, page.changedBytes == 0 ? 1 : page.changedBytes)
                                              : SummarizePageDiff(page.state.before, page.after);

        processedPages++;
        singlePageDiff = page.diff;
        regionBefore.insert(regionBefore.end(), page.state.before.begin(), page.state.before.end());
        regionAfter.insert(regionAfter.end(), page.after.begin(), page.after.end());
        totalChangedBytes += page.changedBytes;
        minGeneration = std::min<uint64_t>(minGeneration, page.state.generation);
        maxGeneration = std::max<uint64_t>(maxGeneration, page.state.generation);

        if (pageLineage.tellp() > 0) pageLineage << ";";
        pageLineage << Hex(page.pageBase) << ":g" << page.state.generation;
    }

    if (regionBefore.empty() || regionAfter.empty()) return;

    UINT64 regionBeforeHash = HashBytes(regionBefore.data(), regionBefore.size());
    UINT64 regionAfterHash = HashBytes(regionAfter.data(), regionAfter.size());
    bool shouldDumpArtifacts = (processedPages > 1) || (totalChangedBytes > 32);
    std::string artifactInfo;

    if (shouldDumpArtifacts) {
        std::string regionDir = "modified_region_" + Hex(regionStart) + "_" + Hex(regionEnd + 0xFFFULL);
        EnsureDirectoryExists(regionDir);

        std::string regionTag = "region_gen_" + std::to_string(minGeneration) + "_" + std::to_string(maxGeneration);
        std::string beforeName = regionDir + "/" + regionTag + "_before.bin";
        std::string afterName = regionDir + "/" + regionTag + "_after.bin";
        std::string manifestName = regionDir + "/" + regionTag + "_manifest.txt";

        bool beforeDumped = DumpBufferToFile(beforeName, regionBefore);
        bool afterDumped = DumpBufferToFile(afterName, regionAfter);

        std::ostringstream manifest;
        manifest << "region_start=" << Hex(regionStart) << "\n";
        manifest << "region_end=" << Hex(regionEnd + 0xFFFULL) << "\n";
        manifest << "page_count=" << processedPages << "\n";
        manifest << "generation_min=" << minGeneration << "\n";
        manifest << "generation_max=" << maxGeneration << "\n";
        manifest << "first_exec_tid=" << (unsigned)tid << "\n";
        manifest << "first_exec_rip=" << Hex(rip) << "\n";
        manifest << "region_hash_before=" << Hex(regionBeforeHash) << "\n";
        manifest << "region_hash_after=" << Hex(regionAfterHash) << "\n";
        manifest << "region_changed=" << totalChangedBytes << "\n";
        manifest << "\n";

        std::vector<std::string> lineageFiles;
        lineageFiles.reserve(pages.size());
        for (size_t i = 0; i < pages.size(); ++i) {
            const ExecRegionPageSnapshot& page = pages[i];
            std::string lineageName = regionDir + "/page_" + Hex(page.pageBase) + "_gen_" + std::to_string(page.state.generation) + ".txt";
            std::ostringstream lineage;
            lineage << "page=" << Hex(page.pageBase) << "\n";
            lineage << "generation=" << page.state.generation << "\n";
            lineage << "writer_tid=" << (unsigned)page.state.writerTid << "\n";
            lineage << "writer_rip=" << Hex(page.state.writerRip) << "\n";
            lineage << "first_exec_tid=" << (unsigned)page.state.firstExecTid << "\n";
            lineage << "first_exec_rip=" << Hex(page.state.firstExecRip) << "\n";
            lineage << "writes=" << page.state.writeCount << "\n";
            lineage << "execute_count=" << page.state.executeCount << "\n";
            lineage << "changed=" << page.changedBytes << "\n";
            lineage << "hash_before=" << Hex(page.beforeHash) << "\n";
            lineage << "hash_after=" << Hex(page.afterHash) << "\n";
            lineage << "diff=" << page.diff << "\n";
            if (page.state.firstBranchSourceRip != 0) {
                lineage << "first_branch_source_rip=" << Hex(page.state.firstBranchSourceRip) << "\n";
            }
            lineage << "inbound_sources=" << page.state.inboundSources.size() << "\n";
            DumpTextToFile(lineageName, lineage.str());
            lineageFiles.push_back(lineageName);

            manifest << "page=" << Hex(page.pageBase)
                << " gen=" << page.state.generation
                << " writer_rip=" << Hex(page.state.writerRip)
                << " first_exec_rip=" << Hex(page.state.firstExecRip)
                << " changed=" << page.changedBytes
                << " lineage_file=" << lineageName
                << "\n";
        }

        bool manifestDumped = DumpTextToFile(manifestName, manifest.str());
        if (beforeDumped && afterDumped && manifestDumped) {
            artifactInfo = " artifacts: dir=" + regionDir +
                " region_before=" + beforeName +
                " region_after=" + afterName +
                " manifest=" + manifestName +
                " page_lineage=" + pageLineage.str();
        }
        else {
            artifactInfo = " artifacts: dir=" + regionDir + " failed";
        }
    }

    std::string summaryDiff;
    if (processedPages == 1 && totalChangedBytes <= 32) {
        summaryDiff = singlePageDiff;
    }
    else {
        summaryDiff = "region_changed=" + std::to_string(totalChangedBytes);
    }

    LogSemanticAlert(tid, rip, "EXEC_AFTER_WRITE <region: " + Hex(regionStart) + "-" + Hex(regionEnd + 0xFFFULL) +
        " pages: " + std::to_string(processedPages) +
        " gen_min: " + std::to_string(minGeneration) +
        " gen_max: " + std::to_string(maxGeneration) +
        " first_exec_tid: " + std::to_string((unsigned)tid) +
        " first_exec_rip: " + Hex(rip) +
        " hash_before: " + Hex(regionBeforeHash) +
        " hash_after: " + Hex(regionAfterHash) +
        " diff: " + summaryDiff +
        artifactInfo + ">");

    std::string hiddenMzReason;
    if (CheckHiddenExecutableMzRegionCached(rip, hiddenMzReason, true)) {
        LogSemanticAlert(tid, rip, hiddenMzReason);
    }
}

void NoteControlFlowIntoModifiedPage(THREADID tid, ADDRINT rip, ADDRINT target) {
    const ThreadState* st = GetToolThreadState(tid);

    if (!st || !st->gateOpen) return;

    ADDRINT pageBase = target & ~0xFFFULL;
    bool logLineage = false;
    bool logHandlerPool = false;
    ExecPageState snapshot;

    PIN_GetLock(&g_ExecPageLock, tid + 1);
    auto it = gExecPageStates.find(pageBase);
    if (it != gExecPageStates.end() && it->second.generation != 0) {
        if (it->second.firstBranchSourceRip == 0) {
            it->second.firstBranchSourceRip = rip;
            logLineage = true;
        }
        it->second.inboundSources.insert(rip);
        if (!it->second.handlerPoolLogged && it->second.inboundSources.size() >= 4) {
            it->second.handlerPoolLogged = true;
            logHandlerPool = true;
        }
        snapshot = it->second;
    }
    PIN_ReleaseLock(&g_ExecPageLock);

    if (snapshot.generation == 0) return;

    if (logLineage) {
        LogSemanticAlert(tid, rip, "CF_INTO_MODIFIED_PAGE <page: " + Hex(pageBase) +
            " gen: " + std::to_string(snapshot.generation) +
            " writer_rip: " + Hex(snapshot.writerRip) +
            " first_exec_rip: " + Hex(snapshot.firstExecRip) +
            " target: " + Hex(target) +
            " inbound_sources: " + std::to_string(snapshot.inboundSources.size())
            + ">");
    }

    if (logHandlerPool) {
        LogSemanticAlert(tid, rip, "MODIFIED_PAGE_HANDLER_POOL_CANDIDATE <page: " + Hex(pageBase) +
            " gen: " + std::to_string(snapshot.generation) +
            " distinct_sources: " + std::to_string(snapshot.inboundSources.size()) +
            " writer_rip: " + Hex(snapshot.writerRip) +
            " first_exec_rip: " + Hex(snapshot.firstExecRip) + ">");
    }
}