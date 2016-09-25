/*******************************************************************************
 * Copyright (C) 2012..2016 norbert.klose@web.de
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/
#ifndef STACKTRACE_HPP
#define STACKTRACE_HPP

#include <DWARF.hpp>
#include <ELF.hpp>
#include <MachO.hpp>
#include <deque>
#include <iostream>
#include <iomanip>
#include <ostream>
#include <string>
#include <cstdint>

namespace common {

/**
 * @brief A StackTrace is a simple vector of strings.
 */
class StackTrace : public std::deque<std::string>
{
public:

    virtual ~StackTrace() {}

    /**
     * @brief Takes a snapshot from the current stack trace.
     */
    virtual void takeSnapshot();

};

/**
 * @brief Try to load a DWARF line number program section.
 */
void debugLine(const std::string & filename, dwarf::LineNumberSection & lineNumberSection);

} // namespace common

/**
 * @brief Prints a StackTrace.
 * The format looks like
 * #frame function() at sourceDirectory/sourceFile:line
 */
std::ostream & operator<<(std::ostream & stream, const common::StackTrace & right);

namespace common {

#if (defined _WIN32)
#pragma warning(disable: 4091)
#include <Windows.h>
#include <DbgHelp.h>

class Win32Static
{
public:

    Win32Static()
    {
        mutex = CreateMutex(0, FALSE, 0);
        currentProcess = GetCurrentProcess();
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
        BOOL successful = SymInitialize(currentProcess, 0, TRUE);
        if (!successful)
        {
            char systemText[1024];
            DWORD error = GetLastError();
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, systemText, sizeof(systemText), 0);
            char buffer[4096];
            sprintf_s(buffer, sizeof(buffer), "SymInitialize failed: %s (%lu)", systemText, (unsigned long) error);
            throw std::runtime_error(buffer);
        }
    }

    ~Win32Static()
    {
        SymCleanup(currentProcess);
    }

    HANDLE getCurrentProcess() const
    {
        return currentProcess;
    }

    HANDLE getMutex() const
    {
        return mutex;
    }

private:

    HANDLE mutex;
    HANDLE currentProcess;

};

void StackTrace::takeSnapshot()
{
    static Win32Static win32Static;
    HANDLE currentThread = GetCurrentThread();
    CONTEXT currentContext;
    memset(&currentContext, 0, sizeof(CONTEXT));
    RtlCaptureContext(&currentContext);

    STACKFRAME64 stackFrame;
    memset(&stackFrame, 0, sizeof(STACKFRAME64));
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Mode = AddrModeFlat;
#ifdef _AMD64_
    stackFrame.AddrPC.Offset = currentContext.Rip;
    stackFrame.AddrFrame.Offset = currentContext.Rsp;
    stackFrame.AddrStack.Offset = currentContext.Rsp;
#else
    stackFrame.AddrPC.Offset = currentContext.Eip;
    stackFrame.AddrFrame.Offset = currentContext.Esp;
    stackFrame.AddrStack.Offset = currentContext.Esp;
#endif

    char symbolInfo[sizeof(SYMBOL_INFO) + MAX_SYM_NAME + 1];
    SYMBOL_INFO * psymbolInfo = reinterpret_cast<SYMBOL_INFO*>(symbolInfo);
    psymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    psymbolInfo->MaxNameLen = MAX_SYM_NAME;

    DWORD waitResult = WaitForSingleObject(win32Static.getMutex(), INFINITE);
    if (waitResult != WAIT_OBJECT_0)
        return;
    unsigned frames = 0, ignore = 0;
    while (true)
    {
#if (defined _M_IX86)
        DWORD machineType = IMAGE_FILE_MACHINE_I386;
#elif (defined _M_AMD64)
        DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
        ignore = 1; // ignore frame[0]==getStackTrace(StackTrace&)
#elif (defined _M_IA64)
        DWORD machineType = IMAGE_FILE_MACHINE_IA64;
#endif
        BOOL hasFrame = StackWalk64(machineType, win32Static.getCurrentProcess(), currentThread, &stackFrame, &currentContext, 0, 0, 0, 0);
        if (!hasFrame) break;
        ++frames;

        psymbolInfo->Name[0] = 0;
        DWORD64 displacement64;
        if (frames > ignore && SymFromAddr(win32Static.getCurrentProcess(), stackFrame.AddrPC.Offset, &displacement64, psymbolInfo))
        {
            IMAGEHLP_LINE64 line;
            DWORD displacement;
            line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            if (SymGetLineFromAddr64(win32Static.getCurrentProcess(), stackFrame.AddrPC.Offset, &displacement, &line))
            {
                std::ostringstream strstr;
                strstr << line.FileName << "(" << line.LineNumber << "): " << psymbolInfo->Name;
                push_back(strstr.str());
            }
            else
            {
                push_back(psymbolInfo->Name);
            }
        }
    }
    ReleaseMutex(win32Static.getMutex());
}
#endif // _WIN32

inline void debugLine(const std::string & filename, dwarf::LineNumberSection & lineNumberSection)
{
    lineNumberSection.clear();
    if (elf::ELFFile::isELF(filename))
    {
        elf::ELFFile elfFile;
        elfFile.open(filename);
        std::deque<elf::ELFSection> sections;
        elfFile.findSections(dwarf::SN_DEBUG_LINE, sections);
        for (const elf::ELFSection & section : sections)
        {
            lineNumberSection.deserialize(section.binaryContent, section.binaryLength,
                                          elfFile.header.elfEndianness == elf::ELF_DATA2LSB,
                                          elfFile.header.elfClass == elf::ELF_CLASS64);
        }
    }
    else if (macho::MachOFile::isMachO(filename))
    {
        macho::MachOFile machoFile;
        machoFile.open(filename);
        std::deque<const macho::MachOSection*> sections;
        machoFile.findSections(dwarf::SN_DEBUG_LINE_MACHO, sections);
        for (const macho::MachOSection * section : sections)
        {
            lineNumberSection.deserialize(section->data(), section->size(),
                                          machoFile.header.isLittleEndian(),
                                          machoFile.header.is64Bit());
        }
    }
}

#if (defined __linux__) || (defined __MACH__)
#include <execinfo.h>

inline void StackTrace::takeSnapshot()
{
    static const int BUFFER_SIZE = 100;
    void * execBuffer[BUFFER_SIZE];
    int noOfFrames = backtrace(execBuffer, BUFFER_SIZE);
    if (noOfFrames >= 2)
    {
        char ** strings = backtrace_symbols(execBuffer, noOfFrames);
        if (strings)
        {
            for (std::size_t i = 1; i < noOfFrames; ++i)
            {
                char * frame = strings[i];
                // Whenever the stacktrace contains already the frame number, we cannot
                // compare the frames anymore as they depend on the depth and not just
                // the call hierarchy
                // On Mac OS X each frame starts with a frame number where the innermost
                // call starts with frame number 1
                while (isdigit(*frame)) ++frame;
                while (isblank(*frame)) ++frame;
                push_back(frame);
            }
            free(strings);
        }
    }
}
#endif // __linux__ || __MACH__

} // namespace common

#if (defined __GNUC__)
#include <cxxabi.h>
#endif
#if (defined __MACH__)
#include <mach-o/dyld.h>
#endif

inline std::ostream & operator<<(std::ostream & stream, const common::StackTrace & right)
{
    typedef std::map<std::string, dwarf::LineNumberSection> LineNumberSections;
    LineNumberSections lineNumberSections;
    std::size_t numFrame = 1;
#if (defined __MACH__)
    std::vector<char> executablePath;
    uint32_t pathLength = 512;
    do
    {
        pathLength *= 2;
        executablePath.resize(pathLength);
    } while (_NSGetExecutablePath(executablePath.data(), &pathLength) < 0);
    std::string modulePath = executablePath.data();
    modulePath.append(".dSYM/Contents/Resources/DWARF/unittest");
#endif
    for (const std::string & strFrame : right)
    {
        std::string module;
        std::string symbol;
        std::string offset;
        std::string address;
        std::string sourceLine;
#ifdef __linux__
        // in linux a stack frame looks like
        // module(symbol+0xoffset) [0xaddress]
        std::size_t startSymbol  = strFrame.find('('),
                    startOffset  = strFrame.find("+0x", startSymbol),
                    endSymbol    = strFrame.find(')', startOffset != std::string::npos ? startOffset : startSymbol),
                    startAddress = strFrame.find("[0x", endSymbol != std::string::npos ? endSymbol : 0),
                    endAddress   = strFrame.find(']', startAddress);

        module = strFrame.substr(0, std::min(startSymbol, startAddress));
        if (startSymbol != std::string::npos)
        {
            symbol = strFrame.substr(startSymbol + 1, std::min(startOffset, endSymbol) - startSymbol - 1);
            if (startOffset != std::string::npos)
                offset = strFrame.substr(startOffset + 3, endSymbol - startOffset - 3);
        }
        if (startAddress != std::string::npos)
            address = strFrame.substr(startAddress + 3, endAddress - startAddress - 3);
#endif
#if (defined __MACH__)
        // in MacOSX a stack frame looks like
        // module 0xaddress symbol + offset
        std::size_t startAddress = strFrame.find(" 0x"),
        startSymbol  = strFrame.find(' ', startAddress == std::string::npos ? startAddress : startAddress + 1),
                    startOffset  = strFrame.find(" + ", startSymbol);
        module = modulePath;
        if (startAddress != std::string::npos)
            address = strFrame.substr(startAddress + 3, startSymbol - startAddress - 3);
        if (startSymbol != std::string::npos)
            symbol = strFrame.substr(startSymbol + 1, startOffset - startSymbol - 1);
        if (startOffset != std::string::npos)
            offset = strFrame.substr(startOffset + 3);
#endif
        while (!module.empty() && isspace(module.back()))
            module.pop_back();
        if (!module.empty() && !address.empty())
        {
            LineNumberSections::const_iterator itr = lineNumberSections.find(module);
            while (itr == lineNumberSections.end())
            {
                dwarf::LineNumberSection & lineNumberSection = lineNumberSections[module];
                common::debugLine(module, lineNumberSection);
                itr = lineNumberSections.find(module);
            }
            uint64_t paddress = strtoull(address.c_str(), 0, 16);
            dwarf::LineNumberSection::AddressIndex::const_iterator atr = itr->second.addressToLine(paddress);
            while (atr != itr->second.addressIndex.begin() && !(--atr)->second->isStmt);
            if (atr != itr->second.addressIndex.end())
                sourceLine = atr->second->getSourceLine();
        }
#if (defined __GNUG__)
        if (!symbol.empty())
        {
            std::size_t length = 0;
            int status = 0;
            char * demangled = abi::__cxa_demangle(symbol.c_str(), 0, &length, &status);
            if (demangled && status == 0)
                symbol.assign(demangled);
            else
                symbol.append("+0x").append(offset);
            if (demangled)
                free(demangled);
        }
#endif

        // eventually symbol should either be the demangled symbol or symbol+0xoffset
        //        and module should either be source:line or module [0xaddress]
        stream << "#" << std::setw(2) << std::setfill('0') << numFrame;
        if (symbol.empty() && sourceLine.empty())
        {
            stream << " " << strFrame;
        }
        else
        {
            if (!symbol.empty())
                stream << " " << symbol;
            if (!sourceLine.empty())
            {
                stream << " at " << sourceLine;
            }
            else if (!module.empty() || !address.empty())
            {
                stream << " at ";
                if (!module.empty())
                    stream << module;
                if (!address.empty())
                    stream << " [0x" << address << "]";
            }
        }
        stream /* << " " << strFrame */ << std::endl;
        ++numFrame;
    }
    return stream;
}

#endif // STACKTRACE_HPP
