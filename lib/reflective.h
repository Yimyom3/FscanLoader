#pragma once
#include <windows.h>
#include <winternl.h>
#define DllExport   __declspec( dllexport )
#define ALIGN_VIRTUAL_SIZE(v,p)(((v) == 0) ? 0 : (((v) - 1) | (p - 1)) + 1)
#define DEFAULT_HASHVALUE 5381				// hash函数默认基数
#define KERNEL32_DLL 2646973979				// L"C:\\Windows\\System32\\kernel32.dll"
#define NTDLL 2960136019					// L"C:\\Windows\\System32\\ntdll.dll"
#define VirtualAlloc 1490734039				// VirtualAlloc
#define VirtualProtect 2342436301			// VirtualProtect
#define LoadLibraryA 107362651				// LoadLibraryA
#define GetProcAddress 2182557567			// GetProcAddress
#define RtlAddFunctionTable 1305458222		// RtlAddFunctionTable
#define NtFlushInstructionCache 827535199	// NtFlushInstructionCache

typedef BOOL(WINAPI* PDllMain)(HINSTANCE, DWORD, LPVOID);
typedef LPVOID(WINAPI* PVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* PVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI* PLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI* PGetProcAddress)(HMODULE, LPCSTR);
typedef BOOLEAN(WINAPI* PRtlAddFunctionTable)(LPVOID, DWORD, DWORD64);
typedef NTSTATUS(NTAPI* PNtFlushInstructionCache)(HANDLE ,PVOID ,ULONG);

VOID DllInit();