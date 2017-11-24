#pragma once

// PLATFORM HEADERS ----------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <SDKDDKVer.h>
#include <Windows.h>
#include <WInternl.h>
#include <Psapi.h>

// STL headers ---------------------------------------------------------------------------
// CONTAINERS
#include <unordered_map>
#include <string>
#include <vector>
#include <array>

// MISC
#include <algorithm>
#include <iostream>
#include <iterator>
#include <fstream>
#include <codecvt>
#include <memory>
#include <locale>
#include <random>

// C-ISH
#include <cstdio>
#include <cstdint>

// PROJECT HEADERS -----------------------------------------------------------------------
#include "safe_handle.hpp"
#include "logger.hpp"
