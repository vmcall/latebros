#pragma once
#include "stdafx.h"

class detour
{
public:
	static std::vector<char> generate_shellcode(uintptr_t hook_pointer);
};