#pragma once
#include "stdafx.h"

class detour
{
public:
    static std::array<unsigned char, 0xF> generate_shellcode(uintptr_t hook_pointer);
    static void hook_function(uintptr_t function_address, uintptr_t hook_address);
    static void remove_detour(uintptr_t function_address, char* original_bytes, size_t length);
};