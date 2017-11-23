#pragma once
#include "stdafx.h"

class detour 
{
public:	
	static std::array<uint8_t, 0xF> generate_shellcode(uintptr_t hook_pointer);
}
