# Dex Stealer v9.0 - Malware Analysis

## Disclaimer

This document provides a technical analysis of a malware sample identified as "Dex Stealer v9.0". The information is intended for security researchers, malware analysts, and educational purposes only. Do not execute this malware on any system you do not own or have explicit permission to test on.

## 1. Overview

**Dex Stealer** is an information-stealing malware written in C. Its primary function is to extract authentication tokens from Discord clients and various Chromium-based web browsers on a victim's Windows machine. It achieves persistence through multiple methods and exfiltrates the stolen data to a hardcoded Discord webhook. The malware uses a combination of native Windows APIs for its operations, including DPAPI for decryption and WinINet for network communication.

## 2. Key Capabilities

* **Credential Theft:** Targets Discord authentication tokens stored in LevelDB (`.ldb`) files.
* **Broad Application Targeting:** Scans for a wide range of applications, including:
    * **Discord Clients:** Discord, Discord Canary, Discord PTB, Lightcord
    * **Web Browsers:** Google Chrome, Microsoft Edge, Brave, Opera, Opera GX, Vivaldi, Yandex
* **System Profiling:** Collects basic victim information:
    * Windows Username
    * Computer Name
    * Public IP Address (via `api64.ipify.org`)
* **Persistence:** Establishes persistence to ensure it runs automatically on system startup using two techniques:
    1.  **Startup Folder:** Copies itself to the user's `Startup` folder.
    2.  **Registry Run Key:** Creates a `Run` key in the `HKEY_CURRENT_USER` hive.
* **Data Exfiltration:** Sends all collected data formatted as a Discord embed message to a hardcoded webhook URL.

## 3. Indicators of Compromise (IoCs)

### File System Artifacts

| Type | Path / Name | Description |
| :--- | :--- | :--- |
| File | `%APPDATA%\Microsoft\SystemCert\certsync.exe` | The "master" copy of the malware payload. |
| File | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\MsUpdateService.exe` | The copy used for persistence via the Startup folder. |

### Registry Modifications

| Hive | Key | Value Name | Value Data |
| :--- | :--- |:--- | :--- |
| `HKEY_CURRENT_USER` | `Software\Microsoft\Windows\CurrentVersion\Run` | `Microsoft CertSync` | `%APPDATA%\Microsoft\SystemCert\certsync.exe` |

### Network Indicators

| Type | Address | Purpose |
| :--- | :--- | :--- |
| Domain | `api64.ipify.org` | Used to resolve the victim's public IP address. |
| URL | `https://discord.com/api/webhooks/1383189825816887418/DKFCGuShimdaQHhb2uqJw6miqvs2_5eRNSuF6rSETI3FDzxn0ufMdscpZIF5Rb0xwzln` | Hardcoded C2 webhook for data exfiltration. |

## 4. Technical Analysis (TTPs)

### Tactic: Execution & Persistence (TA0002, TA0003)

1.  **Initial Execution:** The malware runs via `WinMain`.
2.  **Persistence (`ensure_persistence`):**
    * It retrieves its own file path using `GetModuleFileNameW`.
    * It copies itself to `%APPDATA%\Microsoft\SystemCert\certsync.exe`.
    * It creates a secondary copy in the user's Startup folder as `MsUpdateService.exe` to ensure execution on login.
    * It creates a registry key under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` named `Microsoft CertSync` that points to the `certsync.exe` payload.
    * If the malware is not running from the `certsync.exe` path, it launches the master copy and terminates the original process.

### Tactic: Discovery & Collection (TA0007, TA0009)

1.  **System Info (`get_system_info`):**
    * Gathers the username (`GetUserNameW`), computer name (`GetComputerNameW`), and public IP address.
    * The IP address is fetched by making a GET request to `api64.ipify.org`.
2.  **File & Directory Discovery:**
    * The malware iterates through a hardcoded list of target application paths within `%APPDATA%` and `%LOCALAPPDATA%`.
3.  **Credential Discovery:**
    * It specifically looks for the `Local Storage\leveldb` subdirectory within each target application's data folder.
    * It iterates through all `.ldb` files in this directory.

### Tactic: Credential Access (TA0006)

1.  **Master Key Extraction (`get_master_key`):**
    * For each target application, it reads the `Local State` file.
    * It parses the JSON content to find the `os_crypt.encrypted_key` value.
    * This key is Base64 decoded. The first 5 bytes (`DPAPI`) are skipped.
    * The remaining blob is decrypted using the Windows Data Protection API (`CryptUnprotectData`) to retrieve the master decryption key.
2.  **Token Decryption (`find_and_decrypt_tokens`):**
    * The malware reads the content of each `.ldb` file.
    * It searches for the string pattern `dQw4w9WgXcQ:`, which is a prefix for encrypted Discord tokens.
    * The Base64-encoded encrypted token is extracted.
    * The token is decrypted using **AES-256-GCM**. The `master_key` is used as the decryption key, and the nonce and ciphertext are extracted from the decoded blob. The `BCrypt` family of Windows APIs is used for the cryptographic operations.

### Tactic: Exfiltration (TA0010)

1.  **Data Staging (`WinMain`):** All decrypted tokens are aggregated into a single string buffer.
2.  **Exfiltration (`send_report`):**
    * All collected information (user/pc info, IP, tokens) is formatted into a JSON payload.
    * This payload is structured to create a rich embed message in Discord.
    * The malware uses `WinINet` API functions (`InternetOpenW`, `InternetConnectW`, `HttpOpenRequestW`, `HttpSendRequestA`) to send the JSON payload via an `HTTPS POST` request to the hardcoded webhook URL.