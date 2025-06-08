# 🧬 Windows DLL Injection 

This subproject demonstrates Windows malware development techniques such as process injection, PPID spoofing, and AES-encrypted shellcode execution — all wrapped inside a DLL and triggered via `rundll32.exe` through a BAT file.

---

## 🔧 Techniques Implemented

* **PPID Spoofing**: Launches a process while faking its parent to evade behavioral detection.
* **Process Injection**: Injects encrypted shellcode into a remote or suspended process.
* **DLL-Based Execution**: Payload is compiled into a DLL with an exported entrypoint executed using `rundll32.exe`.
* **AES-128 Encrypted Shellcode**: Payload is AES-encrypted and decrypted in-memory at runtime to evade signature-based detection.
* **Batch Launcher**: `.bat` file to automate execution via `rundll32`.

---



## 🚀 Execution Guide

To run the payload via `rundll32`:

```bat
rundll32.exe systemdll.dll,RunPayload
```

Or just use the BAT script:

```bat

```

> ⚠️ Make sure DLL exports the function correctly (e.g., `StartW`), and that shellcode is embedded or decrypted at runtime.

---

## 🧪 Features Tested

* Shellcode injection (e.g., calc.exe or msfvenom-generated shellcode)
* AV evasion through runtime decryption
* PPID spoofing to make `explorer.exe` or `svchost.exe` the parent

---

## 📼 Notes

* Compiled using `x86` or `x64` MinGW (`i686-w64-mingw32-g++`)
* You can verify function exports with:
  `dumpbin /exports payload.dll` *(on Windows)*

---

## ⚠️ Legal Disclaimer

This repository is **strictly for educational and ethical hacking research**.
Do **NOT** deploy or distribute in environments you do not own or have explicit permission to test.

---

## 👤 Author

rook

---

⭐️ Feel free to fork or star this repo if you're learning about advanced Windows malware techniques.
