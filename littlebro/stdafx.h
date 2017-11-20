#pragma once
#define WIN32_LEAN_AND_MEAN
#pragma comment(lib,"ntdll.lib")
#include <windows.h>
#include <WInternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <array>

#define STATUS_NOT_FOUND                 ((NTSTATUS)0xC0000225L)
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_INVALID_CID               ((NTSTATUS)0xC000000BL)