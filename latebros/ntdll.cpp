#include "stdafx.h"
#include "ntdll.hpp"

fnNtCreateSection ntdll::NtCreateSection = nullptr;
fnNtMapViewOfSection ntdll::NtMapViewOfSection = nullptr;

void ntdll::initialise()
{
	auto module_handle = GetModuleHandle(L"ntdll.dll");
	ntdll::NtCreateSection = reinterpret_cast<fnNtCreateSection>(get_procedure_address(module_handle, "NtCreateSection"));
	ntdll::NtMapViewOfSection = reinterpret_cast<fnNtMapViewOfSection>(get_procedure_address(module_handle, "NtMapViewOfSection"));
}

/*++

Routine Description:

	This function acts as a custom GetProcAddress by iterating the export
	directory of the specified module, and retrieving its respective address.

Arguments:

	module - Handle to the target module.

	procedure_name - Name of routine to have its export address acquired.

Return Value:

	System or module routine address.

--*/
uintptr_t ntdll::get_procedure_address(void* module, std::string procedure_name)
{
	#if defined(_WIN32) 
		unsigned char* module_base = reinterpret_cast<unsigned char*>(module);
		IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
	
		if (dos_header->e_magic == 0x5A4D)
		{
	#if defined(_M_IX86)
			IMAGE_NT_HEADERS32* nt_header = reinterpret_cast<IMAGE_NT_HEADERS32*>(module_base + dos_header->e_lfanew);
	#elif defined(_M_AMD64)
			IMAGE_NT_HEADERS64* nt_header = reinterpret_cast<IMAGE_NT_HEADERS64*>(module_base + dos_header->e_lfanew);
	#endif
	
			if (nt_header->Signature == 0x4550)
			{
				IMAGE_EXPORT_DIRECTORY* export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(module_base + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				for (unsigned int iter = 0; iter < export_dir->NumberOfNames; ++iter)
				{
					char *name_table = reinterpret_cast<char*>(module_base + reinterpret_cast<unsigned long*>(module_base + export_dir->AddressOfNames)[iter]);
					if (!strcmp(name_table, procedure_name.c_str()))
					{
						unsigned short ordinal = reinterpret_cast<unsigned short*>(module_base + export_dir->AddressOfNameOrdinals)[iter];
						return reinterpret_cast<uintptr_t>(module_base + reinterpret_cast<unsigned long*>(module_base + export_dir->AddressOfFunctions)[ordinal]);
					}
				}
			}
		}
	#endif

	return 0;
}
