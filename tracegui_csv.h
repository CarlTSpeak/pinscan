#ifndef TRACEGUI_CSV_H
#define TRACEGUI_CSV_H

#include "pin.H"
using namespace LEVEL_BASE;
using namespace LEVEL_PINCLIENT;

#include <string>

struct TraceGuiCsvRow {
    std::string index;
    std::string address;
    std::string bytes;
    std::string disassembly;
    std::string registers;
    std::string memory;
    std::string comments;
};

std::string TraceGuiCsvEscape(const std::string& value);
std::string TraceGuiCsvQuote(const std::string& value);
std::string TraceGuiHexNoPrefix(ADDRINT value, unsigned width = 0);
std::string TraceGuiFormatBytesColon(const std::string& rawHex);
std::string TraceGuiFormatRow(const TraceGuiCsvRow& row);

#endif // TRACEGUI_CSV_H
