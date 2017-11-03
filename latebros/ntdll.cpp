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
uintptr_t ntdll::get_procedure_address(void *module, std::string procedure_name)
{
	std::uint8_t *base = reinterpret_cast<std::uint8_t *>(module);
	
	PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

	if (dos_header->e_magic = 0x5A4D) {
#if defined(_M_IX86)
		PIMAGE_NT_HEADERS32 nt_header = reinterpret_cast<PIMAGE_NT_HEADERS32>(base + dos_header->e_lfanew);
#elif defined(_M_AMD64)
		PIMAGE_NT_HEADERS64 nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + dos_header->e_lfanew);
#endif

		if (nt_header->Signature == 0x4550) {
			auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			for (auto iter = 0; iter < export_dir->NumberOfNames; iter++) {
				std::string name = reinterpret_cast<char *>(base + reinterpret_cast<uintptr_t *>(base + export_dir->AddressOfNames)[iter]);
				if (procedure_name == name) {
					std::uint16_t ordinal = reinterpret_cast<std::uint16_t *>(base + export_dir->AddressOfNameOrdinals)[iter];
					return reinterpret_cast<uintptr_t>(base + reinterpret_cast<uintptr_t *>(base + export_dir->AddressOfFunctions)[ordinal]);
				}
			}
		}
	}

	return 0;
}
