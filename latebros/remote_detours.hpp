#pragma once
#include "stdafx.h"
#include "process.hpp"

struct hook_info
{
	std::string module_name;
	std::string function_name;
};

class remote_detours
{
public:
	remote_detours(const process& process, std::uintptr_t mapping_address = 0);

	bool hook_function(const hook_info& info, const std::string& hook_name);
	bool reset_function(const hook_info& info,  const std::string& hook_name);
	
	bool hook_import_entry(const hook_info& info, const uintptr_t hook_pointer);
	bool reset_import_entry(const hook_info& info, const uintptr_t hook_pointer);

private:
	using shellcode_buffer = std::array<std::uint8_t, 0xF>;

	const process& target_process;
	std::uintptr_t mapping_address;

	struct hook_data
	{
		std::uintptr_t   exported_container;
		shellcode_buffer original_bytes;
	};

	std::unordered_map<std::uintptr_t, std::uintptr_t> import_entry_detours;
	std::unordered_map<std::uintptr_t,  hook_data> function_detours;

	bool rewrite_bytes(const shellcode_buffer& buffer, std::uintptr_t function_address, std::uintptr_t buffer_address) const;

	static shellcode_buffer generate_shellcode(std::uintptr_t hook_pointer) noexcept;
};
