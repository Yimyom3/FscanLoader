#include "pe.h"

HANDLE _GetModuleHandle(UINT32 hashvalue) {
	if (hashvalue == DEFAULT_HASHVALUE || hashvalue == 0) {
		return NULL;
	}
#ifdef _WIN64
	PPEB processEnvironmentBlock = (PPEB)__readgsqword(offsetof(TEB, ProcessEnvironmentBlock)); //PEBָ��
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
	PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)processEnvironmentBlock->Ldr; //LDRָ��
	PLIST_ENTRY listHead = (PLIST_ENTRY)&ldr->Reserved2[1]; //InLoadOrderModuleList����,���������еĵ�һ��
	PLIST_ENTRY fristEntry = listHead->Flink; //��һ��Flinkָ��
	PLIST_ENTRY currentEntry = fristEntry; //��ǰFlinkָ��
	do {
		PLDR_DATA_TABLE_ENTRY moduleEntry = (PLDR_DATA_TABLE_ENTRY)currentEntry; //ģ������ṹ��
		UNICODE_STRING fullDllName = moduleEntry->FullDllName; //DLL���ƽṹ��
		if (fullDllName.Length != 0) {
			if (HashStringW(fullDllName.Buffer) == hashvalue) {
				return moduleEntry->DllBase; //����DLL��ַ
			}
		}
		currentEntry = currentEntry->Flink; //��һ��Flinkָ��
	} while (currentEntry != fristEntry); //�ж������Ƿ�ѭ������
	return NULL;
}

FARPROC _GetProcAddress(LPVOID hModule, UINT32 hashvalue) {
	if (hModule == NULL || hashvalue == 0 || hashvalue == DEFAULT_HASHVALUE) {
		return NULL;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule; //DOSͷָ��
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew); //NTͷָ��
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}
	IMAGE_OPTIONAL_HEADER pOptionalHeader = pNtHeaders->OptionalHeader; //��չͷ�ṹ��
	IMAGE_DATA_DIRECTORY pDataDirectory = pOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; //������Ŀ¼����
	if (pDataDirectory.VirtualAddress == 0 || pDataDirectory.Size == 0) {
		return NULL;
	}
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + pDataDirectory.VirtualAddress); //������Ŀ¼ָ��
	DWORD numberOfNames = pExport->NumberOfNames; //�������Ʊ�Ԫ������
	PDWORD pEAT = (PDWORD)((PBYTE)hModule + pExport->AddressOfFunctions); //������ַ����ָ�룬�洢��4�ֽڵĺ�����ַRVA
	PDWORD pENT = (PDWORD)((PBYTE)hModule + pExport->AddressOfNames); //������������ָ��洢��4�ֽڵĺ������Ƶ�RVA
	PWORD pEIT = (PWORD)((PBYTE)hModule + pExport->AddressOfNameOrdinals); //�����������ָ�룬�洢��2�ֽڵĺ������
	for (DWORD i = 0; i < numberOfNames; i++) { //����������������
		if (HashStringA((PSTR)((BYTE*)hModule + (*(pENT + i)))) == hashvalue) { //��������ƥ�䣬�õ�ָ�����������ں������Ʊ��е��±�
			WORD ordinal = *(pEIT + i); //ͨ���±�õ��������
			return (FARPROC)((BYTE*)hModule + (*(pEAT + ordinal)));
		}
	}
	return NULL;
}

DWORD RVAToFOA(PIMAGE_NT_HEADERS pNtHeaders, DWORD rva) {
	if (pNtHeaders == NULL || rva == 0) {
		return 0;
	}
	IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeaders->OptionalHeader; //��չͷ�ṹ��
	WORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections; //�ڵ�����
	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders + sizeof(IMAGE_NT_HEADERS)); //�ڱ�ָ��
	for (WORD i = 0; i < numberOfSections; i++) {
		PIMAGE_SECTION_HEADER currentSection = &sectionHeader[i]; //��ǰ��ָ��
		DWORD virtualAddress = currentSection->VirtualAddress; //�ڴ��нڵ�RVA
		DWORD virtualSize = currentSection->Misc.VirtualSize; //�����ڴ��еĴ�С(����ǰ)
		DWORD pointerToRawData = currentSection->PointerToRawData; //�����нڵ�FOA
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
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBase; //DOSͷָ��
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew); //NTͷָ��
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}
	IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeaders->OptionalHeader; //��չͷ�ṹ��
	PIMAGE_DATA_DIRECTORY pExportDirectory = &optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; //����������Ŀ¼����
	PIMAGE_EXPORT_DIRECTORY  pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dllBase + RVAToFOA(pNtHeaders, pExportDirectory->VirtualAddress)); //������ָ��
    DWORD numberOfNames = pExport->NumberOfNames; //�������Ʊ�Ԫ������
	PDWORD pEAT = (PDWORD)((PBYTE)dllBase + RVAToFOA(pNtHeaders, pExport->AddressOfFunctions)); //������ַ����ָ��
	PDWORD pENT = (PDWORD)((PBYTE)dllBase + RVAToFOA(pNtHeaders, pExport->AddressOfNames)); //������������ָ��
	PWORD pEIT = (PWORD)((PBYTE)dllBase + RVAToFOA(pNtHeaders, pExport->AddressOfNameOrdinals)); //�����������ָ��
	for (DWORD i = 0; i < numberOfNames; i++) { //����������������
		if (HashStringA((PSTR)((PBYTE)dllBase + RVAToFOA(pNtHeaders, (*(pENT + i))))) == hashvalue) { //��������ƥ�䣬�õ�ָ�����������ں������Ʊ��е��±�
			WORD ordinal = *(pEIT + i);
			return ((BYTE*)dllBase + RVAToFOA(pNtHeaders, (*(pEAT + ordinal))));
		}
	}
	return NULL;
}