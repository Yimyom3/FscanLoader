#pragma once
#include "util.h"
HANDLE _GetModuleHandle(UINT32 hashvalue);
FARPROC _GetProcAddress(LPVOID hModule, UINT32 hashvalue);
LPVOID GetPEProcAddress(LPVOID dllBase, UINT32 hashvalue);