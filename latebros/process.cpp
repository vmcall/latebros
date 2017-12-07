#include "stdafx.h"
#include "process.hpp"
#include "ntdll.hpp"
#include "api_set.hpp"

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

std::vector<std::uint32_t> process::get_all_from_name(const std::string& process_name)
{
	std::vector<std::uint32_t> processes;

	unsigned long process_list[516], bytes_needed;
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
	else
		logger::log_win_error("EnumProcesses");

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
	else
		logger::log_win_error("process::get_all->EnumProcesses");

	return processes;
}

MEMORY_BASIC_INFORMATION process::virtual_query(const uintptr_t address)
{
	MEMORY_BASIC_INFORMATION mbi;

	if(!VirtualQueryEx(this->handle.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
		logger::log_win_error("process::virtual_query->VirtualQueryEx");

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


bool process::read_raw_memory(void* buffer, const uintptr_t address, const SIZE_T size) const
{
	return ReadProcessMemory(this->handle.get(), reinterpret_cast<LPCVOID>(address), buffer, size, nullptr);
}

bool process::write_raw_memory(const void* buffer, const SIZE_T size, const uintptr_t address) const
{
	return WriteProcessMemory(this->handle.get(), reinterpret_cast<LPVOID>(address), buffer, size, nullptr);
}

bool process::virtual_protect(const uintptr_t address, uint32_t protect, uint32_t* old_protect) const
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

std::unordered_map<std::string, uintptr_t> process::get_modules() const
{
	std::unordered_map<std::string, uintptr_t> result;

	HMODULE module_handles[1024];
	DWORD size_needed;

	if (EnumProcessModules(this->handle.get(), module_handles, sizeof(module_handles), &size_needed))
	{
		for (std::size_t i = 0; i < size_needed / sizeof(HMODULE); i++)
		{
			std::string module_name;
			module_name.resize(MAX_PATH);
			auto len = GetModuleBaseNameA(this->handle.get(), module_handles[i], module_name.data(), MAX_PATH);
			if(!len) {
				logger::log_win_error("process::get_modules->GetModuleBaseNameA");
				continue;
			}

			module_name.resize(len);
			std::transform(module_name.begin(), module_name.end(), module_name.begin(), ::tolower);

			result[std::move(module_name)] = reinterpret_cast<uintptr_t>(module_handles[i]);
		}
	}
	else
		logger::log_win_error("process::get_modules->EnumProcessModules");

	return result;
}

uintptr_t process::get_base_address() const
{
	auto process_name = this->get_name();
	std::transform(process_name.begin(), process_name.end(), process_name.begin(), ::tolower);

	for (const auto&[name, module_handle] : this->get_modules())
		if (name == process_name)
			return module_handle;

	logger::log_error("process::get_base_address failed to find base");
	return 0;
}

std::string process::get_name() const
{
	std::string name;
	name.resize(MAX_PATH);
	auto len = GetModuleBaseNameA(handle.get(), nullptr, name.data(), MAX_PATH);
	if(!len) {
		logger::log_win_error("process::get_name->GetModuleBaseNameA");
		return {};
	}
	name.resize(len);

	std::transform(name.begin(), name.end(), name.begin(), ::tolower);

	return name;
}

uintptr_t process::get_import(const std::string& module_name, const std::string& function_name) const
{
	auto image_base = this->get_base_address();
	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS64 nt_header;
	this->read_memory(&dos_header, image_base);
	this->read_memory(&nt_header, image_base + dos_header.e_lfanew);

	IMAGE_IMPORT_DESCRIPTOR import_table;
	auto import_table_address = image_base + nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	api_set api_schema;

	this->read_memory(&import_table, import_table_address);
	for (; import_table.Name; import_table_address += sizeof(IMAGE_IMPORT_DESCRIPTOR), this->read_memory(&import_table, import_table_address))
	{
		auto current_module_name = read_string(image_base + import_table.Name, 128);
		if(current_module_name.empty())
			continue;

		api_schema.query(current_module_name);

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
	logger::log_error("process::get_import failed to find import");
	return 0;
}

// thx blackbone :)
uintptr_t process::get_module_export(uintptr_t module_handle, const char* function_ordinal) const
{
	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS64 nt_header;
	this->read_memory(&dos_header, module_handle);
	this->read_memory(&nt_header, module_handle + dos_header.e_lfanew);

	auto export_base = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	auto export_base_size = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (export_base) // CONTAINS EXPORTED FUNCTIONS
	{
		// TODO get rid of malloc or make a deleter that uses free
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

uintptr_t process::get_module_export(const std::string& module_name, const char* function_ordinal) const 
{
	const auto module_handle = reinterpret_cast<uintptr_t>(GetModuleHandleA(module_name.c_str())); // TODO: USE this->modules()
	if(!module_handle)
	{
		logger::log_error("Failed to get module handle");
		return 0;
	}

	const auto function_address = this->get_module_export(module_handle, function_ordinal);
	if (!function_address)
	{
		logger::log_error("Failed to get module export");
		return 0;
	}

	return function_address;
}

safe_handle process::create_thread(const uintptr_t address, const uintptr_t argument) const
{
	return safe_handle{ CreateRemoteThread(this->handle.get(), nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), reinterpret_cast<LPVOID>(argument), 0, nullptr) };
}
