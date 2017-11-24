#pragma once

// PLATFORM HEADERS ----------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <SDKDDKVer.h>
#include <Windows.h>
#include <WInternl.h>
#include <TlHelp32.h>
#include <Psapi.h>

// STL HEADERS ---------------------------------------------------------------------------
#include <string_view>
#include <array>

// LIBRARIES -----------------------------------------------------------------------------
#pragma comment(lib, "ntdll.lib")