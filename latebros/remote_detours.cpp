#include "stdafx.h"
#include "remote_detours.hpp"

remote_detours::remote_detours(const process& process, std::uintptr_t mapping_address) 
	: target_process(process)
	, mapping_address(mapping_address) {}


bool remote_detours::hook_function(const hook_info& info, const std::string& hook_name)
{
	// ADDRESS OF MAPPED MODULE IS NOT SET
	if(!mapping_address)
		return false;

	// GET EXPORTED HOOK POINTER
	auto module_handle = reinterpret_cast<uintptr_t>(GetModuleHandleA(info.module_name.c_str())); // TODO: USE this->modules()
	auto function_address = this->target_process.get_module_export(module_handle, info.function_name.c_str());;

	if (!function_address)
	{
		logger::log_error("Failed to get module export");
		return false;
	}

	// READ OLD BYTES
	shellcode_buffer original_bytes;
	this->target_process.read_raw_memory(original_bytes.data(), function_address, sizeof(original_bytes));

	// WRITE OLD BYTES TO EXPORTED DATA CONTAINER
	auto exported_container = this->target_process.get_module_export(mapping_address, (hook_name + "_og").c_str());
	this->target_process.write_raw_memory(original_bytes.data(), sizeof(original_bytes), exported_container);

	// DETOUR FUNCTION
	auto hook_pointer = this->target_process.get_module_export(mapping_address, hook_name.c_str());
	auto shellcode = generate_shellcode(hook_pointer);
	this->target_process.write_raw_memory(shellcode.data(), shellcode.size(), function_address);

	this->function_detours.emplace(function_address, original_bytes);

	logger::log_formatted("Detoured", info.function_name);
	return true;
}

bool remote_detours::reset_function(const hook_info& info,  const std::string& hook_name)
{
	auto entry = this->target_process.get_import(info.module_name, info.function_name);
	if (const auto it = this->function_detours.find(entry); it != this->function_detours.end())
		return this->target_process.write_memory(it->second, it->first);

	return false;
}


bool remote_detours::hook_import_entry(const hook_info& info, const uintptr_t hook_pointer)
{
	auto entry = this->target_process.get_import(info.module_name, info.function_name);

	if (!entry)
		return false;

	uintptr_t function_address;
	this->target_process.read_memory(&function_address, entry);

	this->import_entry_detours.emplace(hook_pointer, function_address);

	if (!this->target_process.write_memory(hook_pointer, entry))
	{
		logger::log_error("Failed to write IAT entry");
		return false;
	}

	logger::log_formatted("Hooked", info.function_name);
	return true;
}

bool remote_detours::reset_import_entry(const hook_info& info, const uintptr_t hook_pointer)
{
	auto original_function = this->import_entry_detours.at(hook_pointer);

	if (!original_function)
		return false;

	auto entry = this->target_process.get_import(info.module_name, info.function_name);

	if (!entry || !this->target_process.write_memory(original_function, entry))
		return false;

	return true;
}


remote_detours::shellcode_buffer remote_detours::generate_shellcode(std::uintptr_t hook_pointer) noexcept
{
	//char hook_bytes[0xE] = {
	//	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,					// JMP [RIP]
	//	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };	// HOOK POINTER
	//*reinterpret_cast<uintptr_t*>(hook_bytes + 0x6) = hook_pointer;

	shellcode_buffer hook_bytes = {
		0xFF, 0x35, 0x01, 0x00, 0x00, 0x00,							// PUSH [RIP+1]
		0xC3,														// RET
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };			// HOOK POINTER
	std::memcpy(hook_bytes.data() + 0x7, &hook_pointer, sizeof(hook_pointer));

	return hook_bytes;
}
