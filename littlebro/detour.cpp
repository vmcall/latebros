#include "stdafx.h"
#include "detour.hpp"

std::vector<char> detour::generate_shellcode(uintptr_t hook_pointer)
{
	char hook_bytes[0xF] = {
		0xFF, 0x35, 0x01, 0x00, 0x00, 0x00,							// PUSH [RIP+1]
		0xC3,														// RET
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };			// HOOK POINTER
	*reinterpret_cast<uintptr_t*>(hook_bytes + 0x7) = hook_pointer;

	return std::vector<char>(hook_bytes, hook_bytes + sizeof(hook_bytes));
}

void detour::hook_function(uintptr_t function_address, uintptr_t hook_address)
{
	auto shellcode = detour::generate_shellcode(hook_address);

	DWORD old_protect;
	VirtualProtect(reinterpret_cast<void*>(function_address), 0x1000, 0x40, &old_protect);
	memcpy(reinterpret_cast<void*>(function_address), shellcode.data(), shellcode.size());
	VirtualProtect(reinterpret_cast<void*>(function_address), 0x1000, old_protect, &old_protect);
}

void detour::remove_detour(uintptr_t function_address, char* original_bytes, size_t length)
{
	DWORD old_protect;
	VirtualProtect(reinterpret_cast<void*>(function_address), 0x1000, 0x40, &old_protect);
	memcpy(reinterpret_cast<void*>(function_address), original_bytes, length);
	VirtualProtect(reinterpret_cast<void*>(function_address), 0x1000, old_protect, &old_protect);
}
