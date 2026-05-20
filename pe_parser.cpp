#include "pinscan_globals.h" // For access to gSyscallNames, gTlsCallbackRvas, etc.
#include "pe_parser.h"
#include <cstdint>
#include <fstream>
#include <vector>

// -------------------- Disk-Based PE Parser Structures --------------------

#pragma pack(push, 1)
struct PIN_IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4], e_oemid, e_oeminfo, e_res2[10];
    int32_t  e_lfanew; // Offset to NT Headers
};

struct PIN_IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader, Characteristics;
};

struct PIN_IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct PIN_IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    PIN_IMAGE_DATA_DIRECTORY DataDirectory[16]; // Index 0 is Export Directory
};

struct PIN_IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    PIN_IMAGE_FILE_HEADER FileHeader;
    PIN_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct PIN_IMAGE_SECTION_HEADER {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress; // RVA
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData; // File Offset
    uint32_t PointerToRelocations, PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct PIN_IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics, TimeDateStamp;
    uint16_t MajorVersion, MinorVersion;
    uint32_t Name, Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
};

struct PIN_IMAGE_TLS_DIRECTORY64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks; // NOTE: VA of array of callback pointers, not RVAs or callbacks numbnuts!
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};
#pragma pack(pop)

// -------------------- Implementation --------------------

static uint32_t RvaToOffset(uint32_t rva, const std::vector<PIN_IMAGE_SECTION_HEADER>& sections) {
    for (const auto& sec : sections) {
        if (rva >= sec.VirtualAddress && rva < (sec.VirtualAddress + sec.VirtualSize)) {
            return rva - sec.VirtualAddress + sec.PointerToRawData;
        }
    }
    return 0;
}

static void ParseSyscallsFromDisk() {
    std::ifstream file("C:\\Windows\\System32\\ntdll.dll", std::ios::binary);
    if (!file) return;

    PIN_IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (dosHeader.e_magic != 0x5A4D) return; // 'MZ'

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    PIN_IMAGE_NT_HEADERS64 ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));
    if (ntHeaders.Signature != 0x4550) return; // 'PE\0\0'

    std::vector<PIN_IMAGE_SECTION_HEADER> sections(ntHeaders.FileHeader.NumberOfSections);
    file.read(reinterpret_cast<char*>(sections.data()), sections.size() * sizeof(PIN_IMAGE_SECTION_HEADER));

    // Get Export Directory RVA (Data Directory Index 0)
    uint32_t exportDirRva = ntHeaders.OptionalHeader.DataDirectory[0].VirtualAddress;
    if (exportDirRva == 0) return;

    uint32_t exportDirOffset = RvaToOffset(exportDirRva, sections);
    if (exportDirOffset == 0) return;

    PIN_IMAGE_EXPORT_DIRECTORY exportDir;
    file.seekg(exportDirOffset, std::ios::beg);
    file.read(reinterpret_cast<char*>(&exportDir), sizeof(exportDir));

    std::vector<uint32_t> funcRvas(exportDir.NumberOfFunctions);
    file.seekg(RvaToOffset(exportDir.AddressOfFunctions, sections), std::ios::beg);
    file.read(reinterpret_cast<char*>(funcRvas.data()), funcRvas.size() * sizeof(uint32_t));

    std::vector<uint32_t> nameRvas(exportDir.NumberOfNames);
    file.seekg(RvaToOffset(exportDir.AddressOfNames, sections), std::ios::beg);
    file.read(reinterpret_cast<char*>(nameRvas.data()), nameRvas.size() * sizeof(uint32_t));

    std::vector<uint16_t> ordinals(exportDir.NumberOfNames);
    file.seekg(RvaToOffset(exportDir.AddressOfNameOrdinals, sections), std::ios::beg);
    file.read(reinterpret_cast<char*>(ordinals.data()), ordinals.size() * sizeof(uint16_t));

    for (size_t i = 0; i < exportDir.NumberOfNames; ++i) {
        uint32_t nameOffset = RvaToOffset(nameRvas[i], sections);
        if (nameOffset == 0) continue;

        file.seekg(nameOffset, std::ios::beg);
        std::string funcName;
        std::getline(file, funcName, '\0');

        // We only care about Nt/Zw prefixed system calls
        if (funcName.compare(0, 2, "Nt") == 0 || funcName.compare(0, 2, "Zw") == 0) {
            uint16_t ordinal = ordinals[i];
            uint32_t funcRva = funcRvas[ordinal];
            uint32_t funcOffset = RvaToOffset(funcRva, sections);

            if (funcOffset == 0) continue;

            // Read the first 32 bytes of the function to find the SSN
            file.seekg(funcOffset, std::ios::beg);
            uint8_t opcodes[32];
            file.read(reinterpret_cast<char*>(opcodes), sizeof(opcodes));

            // Standard Windows 10/11 x64 Syscall Stub:
            // 4C 8B D1          mov r10, rcx
            // B8 XX XX XX XX    mov eax, <SSN>
            for (int j = 0; j < 28; ++j) {
                if (opcodes[j] == 0xB8) { // opcode for 'mov eax, imm32'
                    uint32_t ssn = *reinterpret_cast<uint32_t*>(&opcodes[j + 1]);
                    gSyscallNames[ssn] = funcName;
                    break;
                }
            }
        }
    }
}

static void ParseTlsFromDisk(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return;

    PIN_IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (dosHeader.e_magic != 0x5A4D) return;

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    PIN_IMAGE_NT_HEADERS64 ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));
    if (ntHeaders.Signature != 0x4550) return;

    std::vector<PIN_IMAGE_SECTION_HEADER> sections(ntHeaders.FileHeader.NumberOfSections);
    file.read(reinterpret_cast<char*>(sections.data()), sections.size() * sizeof(PIN_IMAGE_SECTION_HEADER));

    // Data Directory Index 9 is the TLS Directory
    uint32_t tlsDirRva = ntHeaders.OptionalHeader.DataDirectory[9].VirtualAddress;
    if (tlsDirRva == 0) return; // No TLS Directory present

    uint32_t tlsDirOffset = RvaToOffset(tlsDirRva, sections);
    if (tlsDirOffset == 0) return;

    PIN_IMAGE_TLS_DIRECTORY64 tlsDir;
    file.seekg(tlsDirOffset, std::ios::beg);
    file.read(reinterpret_cast<char*>(&tlsDir), sizeof(tlsDir));

    if (tlsDir.AddressOfCallBacks == 0) return;

    // Convert the absolute VA to an RVA, then to a physical file offset
    uint64_t imageBase = ntHeaders.OptionalHeader.ImageBase;
    uint32_t callbacksRva = static_cast<uint32_t>(tlsDir.AddressOfCallBacks - imageBase);
    uint32_t callbacksOffset = RvaToOffset(callbacksRva, sections);
    if (callbacksOffset == 0) return;

    // Read the null-terminated array of callback VAs
    file.seekg(callbacksOffset, std::ios::beg);
    uint64_t callbackVa = 0;
    while (file.read(reinterpret_cast<char*>(&callbackVa), sizeof(callbackVa)) && callbackVa != 0) {
        uint32_t rva = static_cast<uint32_t>(callbackVa - imageBase);
        gTlsCallbackRvas.insert(rva);
    }
}