# PPID Spoofing with API Hashing

## Overview
This project demonstrates PPID (Parent Process ID) spoofing using **API hashing** techniques to evade detection and minimize suspicion. Instead of calling native APIs directly by name, API function addresses are resolved dynamically via hashed function names, making static analysis and detection harder.

The technique creates a new process with a spoofed parent process ID, helping the payload to appear as if it was spawned by a legitimate process.

---

## Key Features
- **PPID spoofing** by setting the parent process of the new process.
- **API hashing** to dynamically resolve Windows API functions at runtime.
- Splits shellcode or payload into parts, writes them into allocated memory, and executes.
- Avoids direct API function name usage to evade static detection.

---

## How It Works
1. **API Hashing:**  
   Instead of using Windows API function names directly, the program calculates hash values for each required API function and locates their addresses dynamically during runtime.

2. **Process Handle Acquisition:**  
   Obtains a handle to the target parent process (the one to spoof as the parent).

3. **Memory Allocation and Shellcode Writing:**  
   Allocates memory in the target or current process, writes the shellcode in parts, and sets execution permissions.

4. **Process Creation with Spoofed PPID:**  
   Creates a new process while specifying the spoofed parent process handle via extended startup info structures.

---

## Prerequisites
- Windows operating system (Windows 7 or newer recommended)
- C++ compiler with Windows API support
- Administrator privileges to open handles to other processes

---

## Usage

### Build
Compile the source code using your preferred compiler:

```bash
g++ PPIDspoof.cpp Headers/aes.c -static -static-libgcc -static-libstdc++ -mwindows -o ppid_spoofing.exe
