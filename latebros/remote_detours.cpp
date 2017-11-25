#include "stdafx.h"
#include "remote_detours.hpp"
#include "logger.hpp"

remote_detours::remote_detours(const process& process, std::uintptr_t mapping_address) 
	: target_process(process)
	, mapping_address(mapping_address) {}


bool remote_detours::hook_function(const hook_info& info, const std::string& hook_name)
{
	logger::log_formatted("Hooking ", info.function_name);
	// ADDRESS OF MAPPED MODULE IS NOT SET
	if(!mapping_address)
	{
		logger::log_error("Failed due to mapping address being not set");
		return false;
	}
		
	// GET EXPORTED HOOK POINTER
	const auto function_address = this->target_process.get_module_export(info.module_name, info.function_name.c_str());
	if(!function_address)
		return false;

	// READ OLD BYTES
	shellcode_buffer original_bytes;
	if(!this->target_process.read_memory(&original_bytes, function_address))
	{
		logger::log_error("Failed to read original bytes");
		return false;
	}

	// WRITE OLD BYTES TO EXPORTED DATA CONTAINER
	auto exported_container = this->target_process.get_module_export(mapping_address, (hook_name + "_og").c_str());
	if(!exported_container)
	{
		logger::log_error("Failed to get exported container");
		return false;
	}

	if(!this->target_process.write_memory(original_bytes, exported_container))
	{
		logger::log_error("Failed to write original bytes to exported container");
		return false;
	}

	// DETOUR FUNCTION
	auto hook_pointer = this->target_process.get_module_export(mapping_address, hook_name.c_str());
	if(!hook_pointer)
	{
		logger::log_error("Failed to get hook pointer");
		return false;
	}

	auto shellcode = generate_shellcode(hook_pointer);
	if(!this->target_process.write_memory(shellcode, function_address))
	{
		logger::log_error("Failed to write generated shellcode");
		return false;
	}

	this->function_detours.emplace(function_address, hook_data{exported_container, original_bytes});
	return true;
}

bool remote_detours::reset_function(const hook_info& info,  const std::string& hook_name)
{
	logger::log_formatted("Resetting ", info.function_name);
	auto function_address = this->target_process.get_module_export(info.module_name, info.function_name.c_str());
	if(!function_address)
		return false;
	
	// TODO SUSPEND PROCESS HERE TO AVOID RACES
	if (const auto it = this->function_detours.find(function_address); it != this->function_detours.end())
		return rewrite_bytes(it->second.original_bytes, function_address, it->second.exported_container);

	logger::log_error("Failed to unhook function: import not found");
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


bool remote_detours::rewrite_bytes(const shellcode_buffer& buffer, std::uintptr_t function_address, std::uintptr_t buffer_address) const 
{
	// OVERWRITE THE HOOK
	if(!this->target_process.write_memory(buffer, function_address))
	{
		logger::log_error("Failed to rewrite hook bytes");
		return false;
	}

	// OVERWRITE THE EXPORTED BUFFER WITH ORIGINAL BYTES
	if(!this->target_process.write_memory(buffer, buffer_address))
	{
		logger::log_error("Failed to rewrite exported buffers bytes");
		return false;
	}

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
