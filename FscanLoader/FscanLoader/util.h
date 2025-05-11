#pragma once
#include "pch.h"
#include "pe.h"

typedef HANDLE(WINAPI* PCreateFileA)(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
typedef LPVOID(WINAPI* PVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(WINAPI* PGetFileSize)(HANDLE, LPDWORD);
typedef BOOL(WINAPI* PReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);
typedef FARPROC(WINAPI* PGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* PFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef HMODULE(WINAPI* PLoadLibraryA)(LPCSTR);
typedef HINTERNET(WINAPI* PInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET(WINAPI* PInternetConnectA)(HINTERNET, LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET(WINAPI* PHttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* PHttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI* PHttpQueryInfoA)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD);
typedef BOOL(WINAPI* PInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* PInternetCloseHandle)(HINTERNET);

VOID XorDecrypt(LPVOID Data, DWORD dataSize, PCHAR xorKey);
UINT32 HashStringA(PCHAR str);
UINT32 HashStringW(PWCHAR wstr);
BOOL ParseUrl(PCHAR url, PDWORD protocolHash, PCHAR host, PDWORD port, PCHAR path);
BOOL _ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD  nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead);
DWORD _GetFileSize(HANDLE hFile);
HANDLE _CreateFileA(LPCSTR lpFileName);
LPVOID _VirtualAlloc(SIZE_T dwSize);
HINTERNET _InternetOpenA();
HINTERNET _InternetConnectA(LPVOID hInternet, LPCSTR host, DWORD port);
HINTERNET _HttpOpenRequestA(LPVOID hConnect, LPCSTR path, DWORD protocolHash);
BOOL _HttpSendRequestA(LPVOID hRequest);
BOOL _HttpQueryInfoA(LPVOID hRequest,LPVOID lpBuffer,LPDWORD lpdwBufferLength);
BOOL _InternetReadFile(LPVOID hFile, LPVOID lpBuffer,DWORD  dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL _InternetCloseHandle(LPVOID hInternet);