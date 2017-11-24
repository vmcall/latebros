// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

// PLATFORM HEADERS ----------------------------------------------------------------------
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

// C-ISH HEADERS
#include <cstdio>
#include <cstdint>

// PROJECT HEADERS -----------------------------------------------------------------------
#include "safe_handle.hpp"
#include "logger.hpp"

// TODO: reference additional headers your program requires here
