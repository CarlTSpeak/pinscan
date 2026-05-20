#ifndef PINSCAN_UTILS_H
#define PINSCAN_UTILS_H

#include "cpu_context.h"
#include <string>
#include <vector>

std::string Hex(ADDRINT a);
std::string JoinPath(const std::string& a, const std::string& b);
std::string ReadMemHex(ADDRINT addr, UINT32 size);
std::string ReadBytesHex(ADDRINT addr, UINT32 size);
std::string JsonEscape(const std::string& s);
std::string ContextRegsJson(const CONTEXT* ctxt);
std::string GetWideString(ADDRINT addr);
std::string GetAsciiString(ADDRINT addr);
std::string GetBufferDump(ADDRINT addr, UINT32 size, UINT32 limit);
std::string DecodeProt(ADDRINT prot);
UINT64 HashBytes(const UINT8* data, size_t size);
bool SnapshotPage(ADDRINT pageBase, std::vector<UINT8>& out);
UINT32 CountPageDiffBytes(const std::vector<UINT8>& before, const std::vector<UINT8>& after);
std::string FormatPageDiff(const std::vector<UINT8>& before, const std::vector<UINT8>& after, UINT32 maxShown);
std::string SummarizePageDiff(const std::vector<UINT8>& before, const std::vector<UINT8>& after);
bool DumpBufferToFile(const std::string& path, const std::vector<UINT8>& data);
bool DumpMemoryToBinary(const std::string& path, ADDRINT start_addr, size_t size);
bool DumpTextToFile(const std::string& path, const std::string& text);
void EnsureDirectoryExists(const std::string& path);
std::string LowerCopyProfile(std::string value);
std::string LowerCopy(std::string value);
std::string GetMemContent(ADDRINT addr, UINT32 size);

#endif // PINSCAN_UTILS_H