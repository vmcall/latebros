#pragma once
#define WIN32_LEAN_AND_MEAN
#pragma comment(lib,"ntdll.lib")
#include <windows.h>
#include <WInternl.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>

#define MAX_MODULE_SEARCH_PARAM						0x02
#define MAX_HOOK_SEARCH_PARAM						0x05