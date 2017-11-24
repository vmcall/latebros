#include "stdafx.h"
#include "process.hpp"
#include "ntdll.hpp"
#include "api_set.hpp"
#include "detour.hpp"

process::process(uint32_t id, DWORD desired_access)
	: handle(OpenProcess(desired_access, false, id))
{
	/*if(!handle)
	{
		logger::log_error("Failed to open handle to process");
		logger::log_formatted("Process ID", id, true);
	}*/
}

process::operator bool()
{
	return static_cast<bool>(this->handle);
}

process process::current_process()
{
	return process(reinterpret_cast<HANDLE>(GetCurrentProcess()));
}

std::vector<uint32_t> process::get_all_from_name(const std::string& process_name)
{
	std::vector<uint32_t> processes;

	DWORD process_list[516], bytes_needed;
	if (EnumProcesses(process_list, sizeof(process_list), &bytes_needed))
	{
		for (size_t index = 0; index < bytes_needed / sizeof(uint32_t); index++)
		{
			auto proc = process(process_list[index], PROCESS_ALL_ACCESS);

			if (!proc)
				continue;

			if (process_name == proc.get_name())
				processes.emplace_back(process_list[index]);
		}
	}

	return processes;
}
std::vector<uint32_t> process::get_all()
{
	std::vector<uint32_t> processes;

	DWORD process_list[516], bytes_needed;
	if (EnumProcesses(process_list, sizeof(process_list), &bytes_needed))
	{
		for (size_t index = 0; index < bytes_needed / sizeof(uint32_t); index++)
		{
			auto proc = process(process_list[index], PROCESS_ALL_ACCESS);

			if (!proc)
				continue;
			
			processes.emplace_back(process_list[index]);
		}
	}

	return processes;
}

MEMORY_BASIC_INFORMATION process::virtual_query(const uintptr_t address)
{
	MEMORY_BASIC_INFORMATION mbi;

	VirtualQueryEx(this->handle.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION));

	return mbi;
}

uintptr_t process::raw_allocate(const SIZE_T virtual_size, const uintptr_t address)
{
	return reinterpret_cast<uintptr_t>(
		VirtualAllocEx(this->handle.get(), reinterpret_cast<LPVOID>(address), virtual_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	);
}

bool process::free_memory(const uintptr_t address)
{
	return VirtualFreeEx(this->handle.get(), reinterpret_cast<LPVOID>(address), NULL, MEM_RELEASE);
}


bool process::read_raw_memory(void* buffer, const uintptr_t address, const SIZE_T size)
{
	return ReadProcessMemory(this->handle.get(), reinterpret_cast<LPCVOID>(address), buffer, size, nullptr);
}

bool process::write_raw_memory(const void* buffer, const SIZE_T size, const uintptr_t address)
{
	return WriteProcessMemory(this->handle.get(), reinterpret_cast<LPVOID>(address), buffer, size, nullptr);
}

bool process::virtual_protect(const uintptr_t address, uint32_t protect, uint32_t* old_protect)
{
	return VirtualProtectEx(this->handle.get(), reinterpret_cast<LPVOID>(address), 0x1000, protect, reinterpret_cast<PDWORD>(old_protect));
}

uintptr_t process::map(memory_section& section)
{
	void* base_address = nullptr;
	SIZE_T view_size = section.size;
	auto result = ntdll::NtMapViewOfSection(section.handle.get(), this->handle.get(), &base_address, NULL, NULL, NULL, &view_size, 2, 0, section.protection);
	
	if (!NT_SUCCESS(result))
	{
		logger::log_error("NtMapViewOfSection failed");
		logger::log_formatted("Error code", result, true);
	}

	return reinterpret_cast<uintptr_t>(base_address);
}

std::unordered_map<std::string, uintptr_t> process::get_modules()
{
	auto result = std::unordered_map<std::string, uintptr_t>();

	HMODULE module_handles[1024];
	DWORD size_needed;

	if (EnumProcessModules(this->handle.get(), module_handles, sizeof(module_handles), &size_needed))
	{
		for (auto i = 0; i < size_needed / sizeof(HMODULE); i++)
		{
			CHAR szModName[MAX_PATH];
			GetModuleBaseNameA(this->handle.get(), module_handles[i], szModName, MAX_PATH);

			std::string new_name = szModName;
			std::transform(new_name.begin(), new_name.end(), new_name.begin(), ::tolower);

			result[new_name] = reinterpret_cast<uintptr_t>(module_handles[i]);
		}
	}



	return result;
}

uintptr_t process::get_base_address()
{
	std::string process_name = this->get_name();
	std::transform(process_name.begin(), process_name.end(), process_name.begin(), ::tolower);

	for (auto&[name, module_handle] : this->get_modules())
	{
		if (name == process_name)
			return module_handle;
	}

	return 0;
}

std::string process::get_name()
{
	char buffer[MAX_PATH];
	GetModuleBaseNameA(handle.get(), nullptr, buffer, MAX_PATH);

	auto name = std::string(buffer);

	std::transform(name.begin(), name.end(), name.begin(), ::tolower);

	return name;
}

uintptr_t process::get_import(const std::string& module_name, const std::string& function_name)
{
	auto image_base = this->get_base_address();
	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS64 nt_header;
	this->read_memory(&dos_header, image_base);
	this->read_memory(&nt_header, image_base + dos_header.e_lfanew);

	IMAGE_IMPORT_DESCRIPTOR import_table;
	auto import_table_address = image_base + nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	api_set api_schema;
	wstring_converter converter;

	this->read_memory(&import_table, import_table_address);
	for (; import_table.Name; import_table_address += sizeof(IMAGE_IMPORT_DESCRIPTOR), this->read_memory(&import_table, import_table_address))
	{
		char name_buffer[100];
		this->read_raw_memory(name_buffer, image_base + import_table.Name, sizeof(name_buffer));
		std::string current_module_name = name_buffer;

		std::wstring wide_module_name = converter.from_bytes(current_module_name.c_str());
		if (api_schema.query(wide_module_name))
			current_module_name = converter.to_bytes(wide_module_name);

		// LOWERCASE FOR MORE CONSISTENT COMPARISON RESULTS
		std::transform(current_module_name.begin(), current_module_name.end(), current_module_name.begin(), ::tolower);

		if (module_name != current_module_name)
			continue;

		IMAGE_THUNK_DATA64 entry;
		auto entry_address = image_base + import_table.OriginalFirstThunk;
		this->read_memory(&entry, entry_address);
		uintptr_t index = 0;

		for (; entry.u1.AddressOfData; index += sizeof(uintptr_t), entry_address += sizeof(IMAGE_THUNK_DATA64), this->read_memory(&entry, entry_address))
		{
			IMAGE_IMPORT_BY_NAME import_by_name;
			this->read_memory(&import_by_name, image_base + entry.u1.AddressOfData);

			char function_name_buffer[50];
			this->read_raw_memory(function_name_buffer, image_base + entry.u1.AddressOfData + sizeof(WORD), sizeof(function_name_buffer));

			if (function_name_buffer == function_name)
				return image_base + import_table.FirstThunk + index;
		}
	}

	return 0;
}

// thx blackbone :)
uintptr_t process::get_module_export(uintptr_t module_handle, const char* function_ordinal)
{
	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS64 nt_header;
	this->read_memory(&dos_header, module_handle);
	this->read_memory(&nt_header, module_handle + dos_header.e_lfanew);

	auto export_base = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	auto export_base_size = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (export_base) // CONTAINS EXPORTED FUNCTIONS
	{
		std::unique_ptr<IMAGE_EXPORT_DIRECTORY> export_data_raw(reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(malloc(export_base_size)));
		auto export_data = export_data_raw.get();

		// READ EXPORTED DATA FROM TARGET PROCESS FOR LATER PROCESSING
		if (!this->read_raw_memory(export_data, module_handle + export_base, export_base_size))
			logger::log_error("failed to read export data");

		// BLACKBONE PASTE, NEVER EXPERIENCED THIS BUT WHO KNOWS?
		if (export_base_size <= sizeof(IMAGE_EXPORT_DIRECTORY))
		{
			export_base_size = static_cast<DWORD>(export_data->AddressOfNameOrdinals - export_base
				+ std::max(export_data->NumberOfFunctions, export_data->NumberOfNames) * 255);

			export_data_raw.reset(reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(malloc(export_base_size)));
			export_data = export_data_raw.get();

			if (!this->read_raw_memory(export_data, module_handle + export_base, export_base_size))
				logger::log_error("failed to read export data");
		}

		// GET DATA FROM READ MEMORY
		auto delta = reinterpret_cast<uintptr_t>(export_data) - export_base;
		auto address_of_ordinals = reinterpret_cast<WORD*>(export_data->AddressOfNameOrdinals + delta);
		auto address_of_names = reinterpret_cast<DWORD*>(export_data->AddressOfNames + delta);
		auto address_of_functions = reinterpret_cast<DWORD*>(export_data->AddressOfFunctions + delta);

		// NO EXPORTED FUNCTIONS? DID WE FUCK UP?
		if (export_data->NumberOfFunctions <= 0)
			logger::log_error("No exports found!");

		auto ptr_function_ordinal = reinterpret_cast<uintptr_t>(function_ordinal);

		for (size_t i = 0; i < export_data->NumberOfFunctions; i++)
		{
			WORD ordinal;
			std::string function_name;
			auto is_import_by_ordinal = ptr_function_ordinal <= 0xFFFF;

			// GET EXPORT INFORMATION
			ordinal = static_cast<WORD>(is_import_by_ordinal ? i : address_of_ordinals[i]);
			function_name = reinterpret_cast<char*>(address_of_names[i] + delta);

			// IS IT THE FUNCTION WE ASKED FOR?
			auto found_via_ordinal = is_import_by_ordinal && static_cast<WORD>(ptr_function_ordinal) == (ordinal + export_data->Base);
			auto found_via_name = !is_import_by_ordinal && function_name == function_ordinal;

			if (found_via_ordinal || found_via_name)
			{
				auto function_pointer = module_handle + address_of_functions[ordinal];

				// FORWARDED EXPORT?
				// IF FUNCTION POINTER IS INSIDE THE EXPORT DIRECTORY, IT IS *NOT* A FUNCTION POINTER!
				// FUCKING SHIT MSVCP140 FUCK YOU
				if (function_pointer >= module_handle + export_base && function_pointer <= module_handle + export_base + export_base_size)
				{
					char forwarded_name[255] = { 0 };
					this->read_raw_memory(forwarded_name, function_pointer, sizeof(forwarded_name));

					std::string forward(forwarded_name);
					std::string library_name = forward.substr(0, forward.find(".")) + ".dll";
					function_name = forward.substr(forward.find(".") + 1, function_name.npos);

					// LOWERCASE THANKS
					std::transform(library_name.begin(), library_name.end(), library_name.begin(), ::tolower);

					auto modules = this->get_modules();
					auto search = modules.find(library_name);
					if (search != modules.end())
						return this->get_module_export(search->second, function_name.c_str());
					else
						logger::log_error("Forwarded module not loaded"); // TODO: HANDLE THIS? WHO CARES
				}

				return function_pointer;
			}
		}
	}

	logger::log_error("Export not found!");
	logger::log_formatted("Exported function", function_ordinal);

	return 0;
}

bool process::detour_import_entry(const std::string& module_name, const std::string& function_name, const uintptr_t hook_pointer)
{
	auto entry = this->get_import(module_name, function_name);

	if (!entry)
		return false;

	uintptr_t function_address;
	this->read_memory(&function_address, entry);

	this->import_entry_detours.emplace(hook_pointer, function_address);

	if (!this->write_memory(hook_pointer, entry))
	{
		logger::log_error("Failed to write IAT entry");
		return false;
	}

	logger::log_formatted("Hooked", function_name);
	return true;
}

bool process::reset_import_entry(const std::string& module_name, const std::string& function_name, const uintptr_t hook_pointer)
{
	auto original_function = this->import_entry_detours.at(hook_pointer);

	if (!original_function)
		return false;

	auto entry = this->get_import(module_name, function_name);

	if (!entry || !this->write_memory(original_function, entry))
		return false;

	return true;
}

bool process::detour_function(const std::string& module_name, const std::string& function_name, const uintptr_t littlebro, const std::string& hook_name)
{
	// GET EXPORTED HOOK POINTER
	auto module_handle = reinterpret_cast<uintptr_t>(GetModuleHandleA(module_name.c_str())); // TODO: USE this->modules()
	auto function_address = this->get_module_export(module_handle, function_name.c_str());;

	if (!function_address)
	{
		logger::log_error("Failed to get module export");
		return false;
	}

	// READ OLD BYTES
	char original_bytes[0xF] = {};
	this->read_raw_memory(original_bytes, function_address, sizeof(original_bytes));

	// WRITE OLD BYTES TO EXPORTED DATA CONTAINER
	auto exported_container = this->get_module_export(littlebro, (hook_name + "_og").c_str());
	this->write_raw_memory(original_bytes, sizeof(original_bytes), exported_container);

	// DETOUR FUNCTION
	auto hook_pointer = this->get_module_export(littlebro, hook_name.c_str());
	auto shellcode = detour::generate_shellcode(hook_pointer);
	this->write_raw_memory(shellcode.data(), shellcode.size(), function_address);

	logger::log_formatted("Detoured", function_name);
	return true;
}

bool process::reset_detour(const std::string& module_name, const std::string& function_name, const uintptr_t littlebro, const std::string& hook_name)
{
	auto entry = this->get_import(module_name, function_name);
	if (auto function = this->detours.find(entry); function != this->detours.end())
	{
		auto original_bytes = function->second;

		// TODO

		return true;
	}


	return false;
}

safe_handle process::create_thread(const uintptr_t address, const uintptr_t argument) const
{
	return safe_handle{ CreateRemoteThread(this->handle.get(), nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), reinterpret_cast<LPVOID>(argument), 0, nullptr) };
}
