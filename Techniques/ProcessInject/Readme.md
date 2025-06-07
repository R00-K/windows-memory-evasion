# Process Injection with Encrypted Shellcode and API Hashing

## Overview
This project implements a process injection technique where an AES-encrypted shellcode is decrypted at runtime, Windows API functions are dynamically resolved using hashed API names, memory is allocated in a target process, shellcode is written in parts, and then executed inside the target process.

Process injection allows code execution inside another process’s memory space, a technique often used for stealthy payload execution and evading detection.

---

## Features
- AES-encrypted shellcode decryption at runtime.
- Dynamic resolution of Windows API functions through hashed API names.
- Injection of shellcode into a remote process.
- Writing shellcode in small parts to evade detection.
- Execution of injected shellcode within the target process.

---

## How It Works
1. **Shellcode Decryption:**  
   The encrypted shellcode is decrypted in memory to obtain the raw executable bytes.

2. **API Hashing and Resolution:**  
   APIs such as `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` are resolved dynamically by hashing their names to avoid plain text strings.

3. **Opening Target Process:**  
   The target process is opened with the necessary access rights (`PROCESS_ALL_ACCESS` or minimal required rights).

4. **Memory Allocation in Target:**  
   Executable memory is allocated inside the target process using `VirtualAllocEx`.

5. **Shellcode Writing:**  
   The decrypted shellcode is written into the target process memory  via `WriteProcessMemory`.

6. **Remote Thread Creation:**  
   A remote thread is created in the target process with its entry point set to the injected shellcode’s address, triggering execution.

---

## Prerequisites
- Windows OS (Windows 7 or later recommended)
- C++ compiler (MSVC, MinGW, etc.)
- Basic knowledge of Windows API, process injection, and shellcode

---

## Build & Run

1. Compile the source code:

```bash
g++ process.cpp Headers/aes.c -static -static-libgcc -static-libstdc++ -mwindows -o process_injection.exe
