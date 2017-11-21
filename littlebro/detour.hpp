#pragma once
#include "stdafx.h"

namespace detour 
{
	
	std::array<uint8_t, 0xF> generate_shellcode(uintptr_t hook_pointer);
	void hook_function(uintptr_t function_address, uintptr_t hook_address);
	void remove_detour(uintptr_t function_address, char* original_bytes, size_t length);

}
