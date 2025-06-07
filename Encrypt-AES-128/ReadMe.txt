# AES-128 Shellcode Hex Encryption

This project provides a basic tool for encrypting shellcode represented as a hexadecimal string using **AES-128-CBC** mode. The encrypted output is printed as a C-style byte array, which can then be used for shellcode injection or other use cases.

---

## ✨ Features

* AES-128 encryption (CBC mode)
* Hex string input
* C-style encrypted byte array output

---

## 📅 Prerequisites

* `g++` compiler (Windows or Linux)

---

## 📂 How to Use

### 1. Modify the Source File

* Open `Encrypt2hexarray.cpp`
* Replace the placeholder `shellcode_hex_str` with your own hex string.
* Replace the `key` and `iv` arrays with your own 16-byte values (32 hex characters).

```cpp
uint8_t key[] = { /* your 16-byte AES key */ };
uint8_t iv[]  = { /* your 16-byte IV */ };
```

### 2. Compile the Project

* You need to include `aes.c` during compilation:

```bash
g++ Encrypt2hexarray.cpp Headers/aes.c -o out.exe
```

### 3. Run the Executable

* Execute `out.exe`
* Copy the resulting encrypted byte array for use in your payloads.

---

## ⚠ Important Notes

* This project uses AES-128 in CBC mode.
* Both the key and IV **must** be 16 bytes.
* The IV does not need to be secret, but must be **unique** for each encryption.
* **Do not reuse IVs with the same key.**

---

## 🚫 Disclaimer

This tool is provided for **educational and authorized testing purposes only**. Misuse of this tool for malicious activity is strictly prohibited.

---

## 🚀 Enjoy building and stay secure!
