#include "utils.h"
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <iostream>

#ifdef _WIN32
extern "C" int __stdcall CreateDirectoryA(const char* lpPathName, void* lpSecurityAttributes);
#endif

static std::string Hex(ADDRINT a) { std::ostringstream os; os << "0x" << std::hex << a; return os.str(); }

static std::string JoinPath(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (a.back() == '\\' || a.back() == '/') return a + b;
    return a + "/" + b;
}

static std::string ReadMemHex(ADDRINT addr, UINT32 size) {
    if (addr == 0 || size == 0 || size > 32) return "";
    std::vector<UINT8> buf(size);
    size_t got = PIN_SafeCopy(buf.data(), reinterpret_cast<void*>(addr), size);
    if (got != size) return "";
    std::ostringstream oss;
    oss << "0x";
    for (INT32 i = static_cast<INT32>(size) - 1; i >= 0; --i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(buf[static_cast<size_t>(i)]);
    }
    return oss.str();
}

static std::string ReadBytesHex(ADDRINT addr, UINT32 size) {
    if (addr == 0 || size == 0 || size > 512) return "";
    std::vector<UINT8> buf(size);
    size_t got = PIN_SafeCopy(buf.data(), reinterpret_cast<void*>(addr), size);
    if (got == 0) return "";
    std::ostringstream oss;
    for (size_t i = 0; i < got; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(buf[i]);
    }
    return oss.str();
}

static std::string JsonEscape(const std::string& s) {
    std::string out; out.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '"') out += "\\\""; else if (c == '\\') out += "\\\\"; else if (c < 0x20) out += " "; else out += c;
    }
    return out;
}

static std::string ContextRegsJson(const CONTEXT* ctxt) {
    if (!ctxt) return "{}";
    struct NamedReg { const char* name; REG reg; };
    static const NamedReg regs[] = {
        {"rax", REG_RAX}, {"rbx", REG_RBX}, {"rcx", REG_RCX}, {"rdx", REG_RDX},
        {"rsi", REG_RSI}, {"rdi", REG_RDI}, {"rbp", REG_RBP}, {"rsp", REG_STACK_PTR},
        {"r8", REG_R8}, {"r9", REG_R9}, {"r10", REG_R10}, {"r11", REG_R11},
        {"r12", REG_R12}, {"r13", REG_R13}, {"r14", REG_R14}, {"r15", REG_R15},
        {"rip", REG_INST_PTR}, {"rflags", REG_RFLAGS}
    };
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (const auto& item : regs) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << item.name << "\":\"" << Hex(PIN_GetContextReg(const_cast<CONTEXT*>(ctxt), item.reg)) << "\"";
    }
    oss << "}";
    return oss.str();
}

// -------------------- Safe String Helpers --------------------
static std::string GetWideString(ADDRINT addr) {
    if (addr == 0) return "NULL";
    std::string out;
    wchar_t buf;
    // Cap at 256 chars to prevent log flooding
    for (int i = 0; i < 256; i++) {
        if (PIN_SafeCopy(&buf, (void*)(addr + (i * 2)), sizeof(wchar_t)) != sizeof(wchar_t)) {
            break; // Stop on memory error
        }
        if (buf == 0) break;
        out += (buf >= 32 && buf <= 126) ? (char)buf : '.';
    }
    return out;
}

static std::string GetAsciiString(ADDRINT addr) {
    if (addr == 0) return "NULL";
    std::string out;
    char buf;
    for (int i = 0; i < 256; i++) {
        if (PIN_SafeCopy(&buf, (void*)(addr + i), sizeof(char)) != sizeof(char)) {
            break;
        }
        if (buf == 0) break;
        out += (buf >= 32 && buf <= 126) ? buf : '.';
    }
    return out;
}


// Helper for WriteFile buffer dumping (Hex + ASCII view)
static std::string GetBufferDump(ADDRINT addr, UINT32 size, UINT32 limit) {
    if (size == 0) return "[empty]";

    UINT32 readSize = (size > limit) ? limit : size;
    std::vector<UINT8> buf(readSize);

    if (PIN_SafeCopy(buf.data(), (void*)addr, readSize) != readSize) {
        return "[unreadable]";
    }

    std::ostringstream hexStream;
    std::ostringstream asciiStream;

    // Hex formatting
    // Hex formatting
    for (UINT32 i = 0; i < readSize; ++i) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
        if (i < readSize - 1) hexStream << " ";
    }

    // ASCII formatting
    for (UINT32 i = 0; i < readSize; ++i) {
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) asciiStream << c;
        else asciiStream << '.';
    }

    std::ostringstream out;
    out << "[" << hexStream.str() << "] \"" << asciiStream.str() << "\"";
    if (size > limit) out << "...";

    return out.str();
}

static std::string DecodeProt(ADDRINT prot) {
    // Mask off internal bits (like PAGE_GUARD 0x100 or PAGE_NOCACHE 0x200)
    // to focus on the permissions.
    UINT32 p = (UINT32)(prot & 0xFF);

    switch (p) {
    case 0x00: return "ZERO_ACCESS"; // PAGE_NOACCESS is usually 0x01, but sometimes 0 is passed
    case 0x01: return "NOACCESS";
    case 0x02: return "R";          // PAGE_READONLY
    case 0x04: return "RW";         // PAGE_READWRITE
    case 0x08: return "WC";         // PAGE_WRITECOPY
    case 0x10: return "X";          // PAGE_EXECUTE
    case 0x20: return "RX";         // PAGE_EXECUTE_READ
    case 0x40: return "RWX";        // PAGE_EXECUTE_READWRITE
    case 0x80: return "WCX";        // PAGE_EXECUTE_WRITECOPY
    default: break;
    }

    // If it's weird (combined with Guard pages etc), return Hex
    return Hex(prot);
}

static UINT64 HashBytes(const UINT8* data, size_t size) {
    UINT64 hash = 1469598103934665603ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static bool SnapshotPage(ADDRINT pageBase, std::vector<UINT8>& out) {
    out.assign(0x1000, 0);
    return PIN_SafeCopy(out.data(), (void*)pageBase, out.size()) == out.size();
}

static UINT32 CountPageDiffBytes(const std::vector<UINT8>& before, const std::vector<UINT8>& after) {
    UINT32 changed = 0;
    size_t limit = std::min(before.size(), after.size());
    for (size_t i = 0; i < limit; ++i) {
        if (before[i] != after[i]) ++changed;
    }
    return changed;
}

static std::string FormatPageDiff(const std::vector<UINT8>& before, const std::vector<UINT8>& after, UINT32 maxShown) {
    std::ostringstream oss;
    UINT32 shown = 0;
    UINT32 changed = 0;
    size_t limit = std::min(before.size(), after.size());
    for (size_t i = 0; i < limit; ++i) {
        if (before[i] == after[i]) continue;
        ++changed;
        if (shown < maxShown) {
            if (shown != 0) oss << ", ";
            oss << "+" << Hex((ADDRINT)i) << ":"
                << std::hex << std::setw(2) << std::setfill('0') << (UINT32)before[i]
                << "->" << std::setw(2) << (UINT32)after[i];
            ++shown;
        }
    }
    if (changed == 0) return "unchanged";
    oss << " total=" << std::dec << changed;
    return oss.str();
}

static std::string SummarizePageDiff(const std::vector<UINT8>& before, const std::vector<UINT8>& after) {
    return FormatPageDiff(before, after, 8);
}

static bool DumpBufferToFile(const std::string& path, const std::vector<UINT8>& data) {
    FILE* dumpFile = fopen(path.c_str(), "wb");
    if (!dumpFile) return false;
    fwrite(data.data(), 1, data.size(), dumpFile);
    fclose(dumpFile);
    return true;
}

static bool DumpMemoryToBinary(const std::string& path, ADDRINT start_addr, size_t size) {
    FILE* dumpFile = fopen(path.c_str(), "wb");
    if (!dumpFile) {
        std::cerr << "[!] Failed to open " << path << " for memory dump.\n";
        return false;
    }

    const size_t CHUNK_SIZE = 65536; // 64KB streaming buffer
    uint8_t chunk[CHUNK_SIZE];

    size_t bytes_remaining = size;
    ADDRINT current_addr = start_addr;

    while (bytes_remaining > 0) {
        size_t to_read = std::min(bytes_remaining, CHUNK_SIZE);

        size_t bytes_read = PIN_SafeCopy(chunk, reinterpret_cast<void*>(current_addr), to_read);

        if (bytes_read > 0) {
            fwrite(chunk, 1, bytes_read, dumpFile);
        }

        if (bytes_read < to_read) {
            std::cerr << "[!] Memory dump truncated at " << std::hex << current_addr
                << " (Unmapped or protected page).\n";
            break;
        }

        bytes_remaining -= bytes_read;
        current_addr += bytes_read;
    }

    fclose(dumpFile);
    return (bytes_remaining == 0); // True if we successfully dumped the exact requested size
}

static bool DumpTextToFile(const std::string& path, const std::string& text) {
    FILE* dumpFile = fopen(path.c_str(), "wb");
    if (!dumpFile) return false;
    fwrite(text.data(), 1, text.size(), dumpFile);
    fclose(dumpFile);
    return true;
}

static void EnsureDirectoryExists(const std::string& path) {
#ifdef _WIN32
    CreateDirectoryA(path.c_str(), nullptr);
#else
    (void)path;
#endif
}

static std::string LowerCopyProfile(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return value;
}

static std::string LowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return value;
}

static std::string GetMemContent(ADDRINT addr, UINT32 size) {
    if (size == 0) return "??";

    // 1. Read Data (Cap at 16 bytes for display sanity)
    UINT32 readSize = (size > 16) ? 16 : size;
    UINT8 buf[16];
    if (PIN_SafeCopy(buf, (VOID*)addr, readSize) != readSize) {
        return "??";
    }

    // 2. Prepare Hex Output (Integer view - Little Endian)
    std::string hexOut;
    std::ostringstream hexStream;
    hexStream << "0x";

    for (int i = readSize - 1; i >= 0; --i) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
    }

    // Assign to the OUTER variable (no shadowing!)
    hexOut = hexStream.str();

    // If the original requested size was > 16, append ellipses
    if (size > 16) {
        hexOut += "...";
    }

    // 3. Prepare Text Output (Memory order view)
    bool isText = true;
    for (UINT32 i = 0; i < readSize; i++) {
        // Allow printable chars (32-126) and null terminators.
        if ((buf[i] < 32 || buf[i] > 126) && buf[i] != 0) {
            isText = false;
            break;
        }
    }

    // 4. Combine
    if (isText && readSize > 0) {
        std::string textOut = " (\"";
        for (UINT32 i = 0; i < readSize; i++) {
            if (buf[i] == 0) break; // Stop string at null
            textOut += (char)buf[i];
        }
        textOut += "\")";
        return hexOut + textOut;
    }

    return hexOut;
}
