#include "reflective.h" 

/*
	1. 关闭编译器优化
	2. ReflectiveLoader函数只能使用局部变量
	3. 32位模式不支持RIP-relative寻址,所以获取当前指令地址需要使用内联汇编
*/

WCHAR ToLowerCaseW(WCHAR ch) {
	if (ch >= L'A' && ch <= L'Z') {
		return ch + (L'a' - L'A');
	}
	return ch;
}

CHAR ToLowerCaseA(CHAR ch) {
	if (ch >= 'A' && ch <= 'Z') {
		return ch + ('a' - 'A');
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
	IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeaders->OptionalHeader; //拓展头结构体
	IMAGE_DATA_DIRECTORY pDataDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; //导出表目录表项
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

HANDLE GetPEAddress() {
#ifdef _WIN64
	ULONG_PTR PEAddress = (ULONG_PTR)GetPEAddress; //64位下对应的汇编为: lea rax, [FFFFFFF5h],也就是RIP-5的地址，64位支持RIP-relative寻址，所以可以动态获取函数地址
												   //32位下对应的汇编为: mov [ebp-4], address, address是一个绝对地址，在编译时就确定了，不能用来获取函数地址，原因是因为32位不支持RIP-relative寻址，lea指令不能使用相对地址，所以需要使用内联汇编获取函数地址
#else
	ULONG_PTR PEAddress;
	__asm {
		call $ + 5; $表示当前指令的地址，$ + 5表示当前指令地址加上5字节的偏移量, 由于由于call指令本身占5字节，所以会到pop eax, 同时将pop eax的地址压入栈
		pop eax; 从栈中弹出eax，此时eax中存储的是当前指令的地址
		mov PEAddress, eax;
	}
#endif
	while (TRUE) {
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)PEAddress; //DOS头指针
		if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE ) {
			if (pDosHeader->e_cblp == 0x9090 && pDosHeader->e_cp == 0x9090) { //自定义特征，避免找错PE
				PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)PEAddress + pDosHeader->e_lfanew); //NT头指针
				if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE) {
					return (HANDLE)PEAddress;
				}
			}
		}
		PEAddress--;
	}
}

DWORD ConvertSectionFlagsToProtect(DWORD characteristics) { //将PE的节属性转换为内存的保护属性
	switch (characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) {
	case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ:
		return PAGE_EXECUTE_READ;
	case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE:
		return PAGE_READWRITE;
	default:
		return PAGE_READONLY;
	}
}


DllExport BOOL RtlVirtuallUnwind(LONG_PTR* handle) {
	/*
		1.定义变量: 要用到的DLL和函数名称、函数指针
	*/
	HANDLE hKernel32 = _GetModuleHandle(KERNEL32_DLL);
	HANDLE hNtdll = _GetModuleHandle(NTDLL);
	if ((hKernel32) == NULL || hNtdll == NULL) {
		return FALSE;
	}
	PVirtualAlloc _VirtualAlloc = (PVirtualAlloc)_GetProcAddress(hKernel32, VirtualAlloc);
	if (_VirtualAlloc == NULL) {
		return FALSE;
	}
	PVirtualProtect _VirtualProtect = (PVirtualProtect)_GetProcAddress(hKernel32, VirtualProtect);
	if (_VirtualProtect == NULL) {
		return FALSE;
	}
	PLoadLibraryA _LoadLibraryA = (PLoadLibraryA)_GetProcAddress(hKernel32, LoadLibraryA);
	if (_LoadLibraryA == NULL) {
		return FALSE;
	}
	PGetProcAddress __GetProcAddress = (PGetProcAddress)_GetProcAddress(hKernel32, GetProcAddress);
	if (__GetProcAddress == NULL) {
		return FALSE;
	}
	PNtFlushInstructionCache _NtFlushInstructionCache = (PNtFlushInstructionCache)_GetProcAddress(hNtdll, NtFlushInstructionCache);
	if (_NtFlushInstructionCache == NULL) {
		return FALSE;
	}
	PRtlAddFunctionTable _RtlAddFunctionTable = (PRtlAddFunctionTable)_GetProcAddress(hKernel32, RtlAddFunctionTable);
	if (_RtlAddFunctionTable == NULL) {
		return FALSE;
	}

		/*
		2.解析PE文件，获取关键信息
	*/
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetPEAddress(); //DOS头指针
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew); //NT头指针
	WORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections; //节的数量
	IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeaders->OptionalHeader; //拓展头结构体
	DWORD addressOfEntryPoint = optionalHeader.AddressOfEntryPoint; //程序入口地址RVA
	ULONG_PTR imageBase = optionalHeader.ImageBase; //PE中默认映象基址
	DWORD imageBaseOffset = pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER,ImageBase); //PE中默认映象基址在PE头中的偏移量
	DWORD sectionAlignment = optionalHeader.SectionAlignment; //内存对齐大小
	DWORD fileAlignment = optionalHeader.FileAlignment; //磁盘对齐大小
	DWORD sizeOfImage = optionalHeader.SizeOfImage; //映象文件总大小
	DWORD sizeOfHeaders = optionalHeader.SizeOfHeaders; //PE头总大小
	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders + sizeof(IMAGE_NT_HEADERS)); //节表指针

	/*
		3.申请内存空间，把PE文件内容复制
	*/
	LPVOID hDll = _VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); //申请内存得到DLL句柄
	if (hDll == NULL) {
		return FALSE;
	}
	*handle = (LONG_PTR)hDll; //返回dll句柄
	for (DWORD i = 0; i < sizeOfHeaders; i++) {
		*((PBYTE)hDll + i) = *((PBYTE)pDosHeader + i); //先把PE头复制过去
	}
	*(PULONG_PTR)((PBYTE)hDll + imageBaseOffset) = (ULONG_PTR)hDll; //修正映象基址
	for (WORD i = 0; i < numberOfSections; i++) {  //再复制每个节的内容
		PIMAGE_SECTION_HEADER currentSection = &sectionHeader[i]; //当前节指针
		DWORD virtualAddress = currentSection->VirtualAddress; //内存中节的RVA
		DWORD sizeOfRawData = currentSection->SizeOfRawData; //节在磁盘上的大小(对齐后)
		DWORD pointerToRawData = currentSection->PointerToRawData; //磁盘中节的FOA
		for (DWORD j = 0; j < sizeOfRawData; j++) {
			*((PBYTE)hDll + virtualAddress + j) = *((PBYTE)pDosHeader + pointerToRawData + j); //复制节的内容
		}
	}

	/*
		4.修复函数导入表
	*/
	PIMAGE_DATA_DIRECTORY pImportDirectory = &optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; //导入表目录表项
	if (pImportDirectory->VirtualAddress!= 0 && pImportDirectory->Size!= 0) {
		DWORD dllCount = 0; //需要导入dll的数量
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hDll + pImportDirectory->VirtualAddress); //导入表指针
		PIMAGE_IMPORT_DESCRIPTOR currentImportDescriptor = pImportDescriptor; //当前导入表指针
		while (currentImportDescriptor->Name != 0) { //遍历每个导入表
			dllCount++;
			currentImportDescriptor++;
		}
		for (DWORD i = 0; i < dllCount; i++) {
			currentImportDescriptor = pImportDescriptor + i; //当前导入表指针
			DWORD nameRVA = currentImportDescriptor->Name; //DLL名称的RVA
			LPSTR dllName = (LPSTR)((BYTE*)hDll + nameRVA); //获取DLL名称
			HMODULE dllHandle = _LoadLibraryA(dllName); //加载DLL
			if (dllHandle == NULL) {
				return FALSE;
			}
			PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hDll + currentImportDescriptor->OriginalFirstThunk); //原始的INT表指针
			PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hDll + currentImportDescriptor->FirstThunk); //INT表指针
			FARPROC funcAddress = NULL; //IAT表中的函数地址
			while (pOriginalFirstThunk->u1.Function != 0) { //遍历每个INT表
				if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) { //如果最高位为1，则表示函数的序号
					LPCSTR ordinal = (LPCSTR)(IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal)); //抹去最高位的结果为序号
					funcAddress = __GetProcAddress(dllHandle, ordinal); //通过序号获取函数地址
					if (funcAddress == NULL) {
						return FALSE;
					}
					pFirstThunk->u1.Function = (ULONG_PTR)funcAddress; //修复IAT表的地址
				}
				else { //如果最高位为0，则表示是IMAGE_IMPORT_BY_NAME的RVA
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hDll + pOriginalFirstThunk->u1.AddressOfData); //IMAGE_IMPORT_BY_NAME结构体指针
					LPCSTR funcName = (LPCSTR)pImportByName->Name; //函数名称
					funcAddress = __GetProcAddress(dllHandle, funcName); //通过函数名称获取函数地址
					if (funcAddress == NULL) {
						return FALSE;
					}
					pFirstThunk->u1.Function = (ULONG_PTR)funcAddress; //修复IAT表的地址
				}
				pOriginalFirstThunk++;
				pFirstThunk++;
			}
		}
	}

	/*
		5.修复重定位表
	*/
	PIMAGE_DATA_DIRECTORY pBaseRelocationDirectory = &optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]; //重定位表目录表项
	if (pBaseRelocationDirectory->VirtualAddress != 0 && pBaseRelocationDirectory->Size != 0) {
		ULONG_PTR difference = (ULONG_PTR)hDll - imageBase; //计算基址差值
		PIMAGE_BASE_RELOCATION PImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)hDll + pBaseRelocationDirectory->VirtualAddress); //重定位表指针
		DWORD totalSize = pBaseRelocationDirectory->Size; //重定位表总大小
		DWORD usedSize = 0; //已使用重定位表大小
		while (usedSize < totalSize) {
			PBYTE actualPageBase = (PBYTE)hDll + PImageBaseRelocation->VirtualAddress; //实际要重定位页的基址
			PWORD pEntries = (PWORD)((PBYTE)PImageBaseRelocation + 8);   //TypeOffset数组起始地址
			DWORD numRelocs = (PImageBaseRelocation->SizeOfBlock - 8) / 2;  //要重定位的条目数
			for (DWORD i = 0; i < numRelocs; i++) { //遍历每个条目
				WORD entry = pEntries[i];
				DWORD type = (entry >> 12) & 0xF;  //高4位是Type
				DWORD offset = entry & 0xFFF;      //低12位是Offset
				switch (type) { //根据Type字段进行重定位
				case IMAGE_REL_BASED_ABSOLUTE: //无需重定位
					break;
				case IMAGE_REL_BASED_HIGHLOW: //32位重定位
					*(PDWORD)((PBYTE)actualPageBase + offset) += (DWORD)difference;
					break;
				case IMAGE_REL_BASED_DIR64: //64位重定位
					*(PULONG_PTR)((PBYTE)actualPageBase + offset) += difference; //修正地址为重定位地址
					break;
				default: //其他类型不处理
					break;
				}
			} 
			usedSize += PImageBaseRelocation->SizeOfBlock; //更新已使用重定位表大小
			PImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)PImageBaseRelocation + PImageBaseRelocation->SizeOfBlock); //指向下一个重定位表
		}
	}

	/*
		6.为节分配正确的内存属性
	*/
	for (WORD i = 0; i < numberOfSections; i++) {  //遍历每个节
		PIMAGE_SECTION_HEADER currentSection = &sectionHeader[i]; //当前节指针
		DWORD virtualAddress = currentSection->VirtualAddress; //内存中节的RVA
		DWORD sizeOfRawData = currentSection->SizeOfRawData; //节在磁盘上的大小(对齐后)
		DWORD virtualSize = currentSection->Misc.VirtualSize; //节在内存中的大小(对齐前)
		DWORD characteristics = currentSection->Characteristics; //节在PE中的内存属性
		DWORD oldProtect = 0;
		if (ALIGN_VIRTUAL_SIZE(virtualSize, sectionAlignment) != 0) {
			if (!_VirtualProtect(((BYTE*)hDll + virtualAddress), ALIGN_VIRTUAL_SIZE(virtualSize, sectionAlignment), ConvertSectionFlagsToProtect(characteristics), &oldProtect)) { //为节分配属性
				return FALSE;
			}
		}
	}

	/*
		7.注册异常处理程序
	*/
	PIMAGE_DATA_DIRECTORY pExceptionDirectory = &optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]; //异常表目录表项
	if (pExceptionDirectory->VirtualAddress != 0 && pExceptionDirectory->Size != 0) {
		PIMAGE_RUNTIME_FUNCTION_ENTRY PImageExceptionDirectory = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((PBYTE)hDll + pExceptionDirectory->VirtualAddress); //异常表指针
		_RtlAddFunctionTable(PImageExceptionDirectory, pExceptionDirectory->Size / sizeof(PIMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)hDll); //注册异常处理程序
	}

	/*
		8.执行TLS回调函数
	*/
	PIMAGE_DATA_DIRECTORY pTlsDirectory = &optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]; //TLS表目录表项
	if (pTlsDirectory->VirtualAddress != 0 && pTlsDirectory->Size != 0) {
		PIMAGE_TLS_DIRECTORY PImageTlsDirectory = (PIMAGE_TLS_DIRECTORY)((PBYTE)hDll + pTlsDirectory->VirtualAddress); //TLS表指针
		if (PImageTlsDirectory->AddressOfCallBacks != 0) {
			PIMAGE_TLS_CALLBACK* arrayOfCallbacks = (PIMAGE_TLS_CALLBACK*)(PImageTlsDirectory->AddressOfCallBacks); //回调函数数组
			while (*arrayOfCallbacks != NULL) { //遍历每个回调函数
				(*arrayOfCallbacks)((PVOID)hDll, DLL_PROCESS_ATTACH, NULL); //执行回调函数
				arrayOfCallbacks++;
			}
		}
	}

	/*
		9.调用DLL入口函数
	*/
	_NtFlushInstructionCache((HANDLE)-1,NULL,0x00);//刷新缓存
	PDllMain _DllMain = (PDllMain)((BYTE*)hDll + addressOfEntryPoint); //DLL入口函数指针
	return _DllMain((HINSTANCE)hDll, DLL_PROCESS_ATTACH, NULL); //转到DLL入口函数开始执行
}

// Ctrl+C处理函数
BOOL WINAPI CtrlHandler(DWORD dwCtrlType) {
	if (dwCtrlType == CTRL_C_EVENT) {
		ExitProcess(-1);
		return TRUE;
	}
	return FALSE;
}

VOID DllInit() {
	SetConsoleCtrlHandler(CtrlHandler, TRUE);
}