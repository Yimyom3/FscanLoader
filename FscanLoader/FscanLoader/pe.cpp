#include "pe.h"

HANDLE _GetModuleHandle(UINT32 hashvalue) {
	if (hashvalue == DEFAULT_HASHVALUE || hashvalue == 0) {
		return NULL;
	}
#ifdef _WIN64
	PPEB processEnvironmentBlock = (PPEB)__readgsqword(offsetof(TEB, ProcessEnvironmentBlock)); //PEB指针
#else
	PPEB processEnvironmentBlock = NULL;
	__asm {
		mov eax, fs: [30h]
		mov processEnvironmentBlock, eax
	}
#endif
	if (processEnvironmentBlock == NULL) {
		return NULL;
	}
	PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)processEnvironmentBlock->Ldr; //LDR指针
	PLIST_ENTRY listHead = (PLIST_ENTRY)&ldr->Reserved2[1]; //InLoadOrderModuleList链表,三个链表中的第一个
	PLIST_ENTRY fristEntry = listHead->Flink; //第一个Flink指针
	PLIST_ENTRY currentEntry = fristEntry; //当前Flink指针
	do {
		PLDR_DATA_TABLE_ENTRY moduleEntry = (PLDR_DATA_TABLE_ENTRY)currentEntry; //模块链表结构体
		UNICODE_STRING fullDllName = moduleEntry->FullDllName; //DLL名称结构体
		if (fullDllName.Length != 0) {
			if (HashStringW(fullDllName.Buffer) == hashvalue) {
				return moduleEntry->DllBase; //返回DLL基址
			}
		}
		currentEntry = currentEntry->Flink; //下一个Flink指针
	} while (currentEntry != fristEntry); //判断链表是否循环结束
	return NULL;
}

FARPROC _GetProcAddress(LPVOID hModule, UINT32 hashvalue) {
	if (hModule == NULL || hashvalue == 0 || hashvalue == DEFAULT_HASHVALUE) {
		return NULL;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule; //DOS头指针
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew); //NT头指针
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}
	IMAGE_OPTIONAL_HEADER pOptionalHeader = pNtHeaders->OptionalHeader; //拓展头结构体
	IMAGE_DATA_DIRECTORY pDataDirectory = pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; //导出表目录表项
	if (pDataDirectory.VirtualAddress == 0 || pDataDirectory.Size == 0) {
		return NULL;
	}
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + pDataDirectory.VirtualAddress); //导出表目录指针
	DWORD numberOfNames = pExport->NumberOfNames; //函数名称表元素数量
	PDWORD pEAT = (PDWORD)((PBYTE)hModule + pExport->AddressOfFunctions); //函数地址数组指针，存储着4字节的函数地址RVA
	PDWORD pENT = (PDWORD)((PBYTE)hModule + pExport->AddressOfNames); //函数名称数组指针存储着4字节的函数名称的RVA
	PWORD pEIT = (PWORD)((PBYTE)hModule + pExport->AddressOfNameOrdinals); //函数序号数组指针，存储着2字节的函数序号
	for (DWORD i = 0; i < numberOfNames; i++) { //遍历函数名称数组
		if (HashStringA((PSTR)((BYTE*)hModule + (*(pENT + i)))) == hashvalue) { //函数名称匹配，得到指定函数名称在函数名称表中的下标
			WORD ordinal = *(pEIT + i); //通过下标得到函数序号
			return (FARPROC)((BYTE*)hModule + (*(pEAT + ordinal)));
		}
	}
	return NULL;
}

DWORD RVAToFOA(PIMAGE_NT_HEADERS pNtHeaders, DWORD rva) {
	if (pNtHeaders == NULL || rva == 0) {
		return 0;
	}
	IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeaders->OptionalHeader; //拓展头结构体
	WORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections; //节的数量
	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders + sizeof(IMAGE_NT_HEADERS)); //节表指针
	for (WORD i = 0; i < numberOfSections; i++) {
		PIMAGE_SECTION_HEADER currentSection = &sectionHeader[i]; //当前节指针
		DWORD virtualAddress = currentSection->VirtualAddress; //内存中节的RVA
		DWORD virtualSize = currentSection->Misc.VirtualSize; //节在内存中的大小(对齐前)
		DWORD pointerToRawData = currentSection->PointerToRawData; //磁盘中节的FOA
		if (virtualAddress <= rva && rva < virtualAddress + virtualSize) {
			return pointerToRawData + (rva - virtualAddress);
		}
	}
	return 0;
}

LPVOID GetPEProcAddress(LPVOID dllBase, UINT32 hashvalue) {
	if (dllBase == NULL  || hashvalue == 0 || hashvalue == DEFAULT_HASHVALUE) {
		return NULL;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBase; //DOS头指针
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew); //NT头指针
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}
	IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeaders->OptionalHeader; //拓展头结构体
	PIMAGE_DATA_DIRECTORY pExportDirectory = &optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; //函数导出表目录表项
	PIMAGE_EXPORT_DIRECTORY  pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dllBase + RVAToFOA(pNtHeaders, pExportDirectory->VirtualAddress)); //导出表指针
    DWORD numberOfNames = pExport->NumberOfNames; //函数名称表元素数量
	PDWORD pEAT = (PDWORD)((PBYTE)dllBase + RVAToFOA(pNtHeaders, pExport->AddressOfFunctions)); //函数地址数组指针
	PDWORD pENT = (PDWORD)((PBYTE)dllBase + RVAToFOA(pNtHeaders, pExport->AddressOfNames)); //函数名称数组指针
	PWORD pEIT = (PWORD)((PBYTE)dllBase + RVAToFOA(pNtHeaders, pExport->AddressOfNameOrdinals)); //函数序号数组指针
	for (DWORD i = 0; i < numberOfNames; i++) { //遍历函数名称数组
		if (HashStringA((PSTR)((PBYTE)dllBase + RVAToFOA(pNtHeaders, (*(pENT + i))))) == hashvalue) { //函数名称匹配，得到指定函数名称在函数名称表中的下标
			WORD ordinal = *(pEIT + i);
			return ((BYTE*)dllBase + RVAToFOA(pNtHeaders, (*(pEAT + ordinal))));
		}
	}
	return NULL;
}