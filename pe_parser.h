#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <string>

// Parses ntdll.dll from disk to dynamically map System Service Numbers (SSNs)
void ParseSyscallsFromDisk();

// Parses a given executable from disk to locate TLS Callback RVAs
void ParseTlsFromDisk(const std::string& path);

#endif // PE_PARSER_H