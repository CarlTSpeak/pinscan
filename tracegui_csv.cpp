#include "tracegui_csv.h"

#include <cctype>
#include <iomanip>
#include <sstream>

std::string TraceGuiCsvEscape(const std::string& value) {
    bool quote = false;
    for (char ch : value) {
        if (ch == '"' || ch == ',' || ch == '\n' || ch == '\r') {
            quote = true;
            break;
        }
    }
    if (!quote) return value;

    std::string out;
    out.reserve(value.size() + 2);
    out.push_back('"');
    for (char ch : value) {
        if (ch == '"') out.push_back('"');
        out.push_back(ch);
    }
    out.push_back('"');
    return out;
}

std::string TraceGuiHexNoPrefix(ADDRINT value, unsigned width) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex;
    if (width > 0) oss << std::setw(width) << std::setfill('0');
    oss << static_cast<unsigned long long>(value);
    return oss.str();
}

std::string TraceGuiFormatBytesColon(const std::string& rawHex) {
    size_t start = 0;
    if (rawHex.size() >= 2 && rawHex[0] == '0' && (rawHex[1] == 'x' || rawHex[1] == 'X')) {
        start = 2;
    }
    std::string hex;
    hex.reserve(rawHex.size());
    for (size_t i = start; i < rawHex.size(); ++i) {
        char ch = rawHex[i];
        if (std::isxdigit(static_cast<unsigned char>(ch))) {
            hex.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
        }
    }
    if (hex.empty()) return "";
    if ((hex.size() & 1u) != 0) hex.insert(hex.begin(), '0');

    std::string out;
    out.reserve(hex.size() + hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        if (!out.empty()) out.push_back(':');
        out.push_back(hex[i]);
        out.push_back(hex[i + 1]);
    }
    return out;
}

std::string TraceGuiFormatRow(const TraceGuiCsvRow& row) {
    std::ostringstream oss;
    oss << TraceGuiCsvEscape(row.index) << ','
        << TraceGuiCsvEscape(row.address) << ','
        << TraceGuiCsvEscape(row.bytes) << ','
        << TraceGuiCsvEscape(row.disassembly) << ','
        << TraceGuiCsvEscape(row.registers) << ','
        << TraceGuiCsvEscape(row.memory) << ','
        << TraceGuiCsvEscape(row.comments);
    return oss.str();
}
