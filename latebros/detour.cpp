#include "stdafx.h"
#include "detour.hpp"

std::vector<char> detour::generate_shellcode(uintptr_t hook_pointer)
{
	//char hook_bytes[0xE] = {
	//	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,					// JMP [RIP]
	//	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };	// HOOK POINTER
	//*reinterpret_cast<uintptr_t*>(hook_bytes + 0x6) = hook_pointer;

	char hook_bytes[0xF] = {
		0xFF, 0x35, 0x01, 0x00, 0x00, 0x00,							// PUSH [RIP+1]
		0xC3,														// RET
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };			// HOOK POINTER
	*reinterpret_cast<uintptr_t*>(hook_bytes + 0x7) = hook_pointer;

	return std::vector<char>(hook_bytes, hook_bytes + sizeof(hook_bytes));
}
