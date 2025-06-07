# Self Injection with Encrypted Shellcode and API Hashing

## Overview
This project demonstrates a self-injection technique where an AES-encrypted shellcode is decrypted at runtime, Windows API functions are resolved dynamically using hashed API names for stealth, memory is allocated with execute permissions, the shellcode is written in parts, and finally executed within the current process.

This method is often used in advanced malware development and security research to evade detection by antivirus and static analysis tools.

---

## Features
- AES-encrypted shellcode decryption at runtime.
- Dynamic Windows API resolution via API name hashing.
- Memory allocation with executable permissions.
- Partial writing of shellcode to allocated memory in segments.
- Execution of the injected shellcode in the current process.

---

## How It Works
1. **Shellcode Decryption:**  
   The encrypted shellcode is decrypted using AES into its raw byte form.

2. **API Hashing and Resolution:**  
   API functions (e.g., `VirtualAlloc`, `memcpy`) are resolved by hashing their names and searching loaded modules, avoiding plain text API strings in the binary.

3. **Memory Allocation:**  
   Executable memory is allocated dynamically in the process memory space using `VirtualAlloc`.

4. **Partial Shellcode Writing:**  
   The decrypted shellcode is copied into the allocated memory in multiple small parts to evade detection from large continuous writes.

5. **Shellcode Execution:**  
   The allocated memory pointer is cast to a function pointer and called to execute the shellcode.

---

## Prerequisites
- Windows OS (Windows 7 or later recommended)
- C++ compiler (MSVC, MinGW, etc.)
- Basic understanding of Windows internals and shellcode concepts

---

## Build & Run

1. Compile the project:

```bash
g++ self.cpp Headers/aes.c -static -static-libgcc -static-libstdc++ -mwindows -o self.exe

