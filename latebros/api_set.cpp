#include "stdafx.h"
#include "api_set.hpp"

api_set::api_set()
{
	const auto peb = reinterpret_cast<uintptr_t>(NtCurrentTeb()->ProcessEnvironmentBlock);

	auto api_set = *reinterpret_cast<API_SET_NAMESPACE_ARRAY**>(peb + 0x68);

	for (ULONG entry_index = 0; entry_index < api_set->count; ++entry_index)
	{
		const auto descriptor = api_set->entry(entry_index);

		auto dll_name = api_set->get_name(descriptor);
		std::for_each(dll_name.begin(), dll_name.end(), ::tolower);

		const auto host_data = api_set->get_host(descriptor);

		std::vector<std::wstring> hosts;
		for (ULONG j = 0; j < host_data->count; j++)
		{
			const auto host = host_data->entry(api_set, j);

			std::wstring host_name(reinterpret_cast<wchar_t*>(reinterpret_cast<uint8_t*>(api_set) + host->value_offset),
				host->value_length / sizeof(wchar_t));

			if (!host_name.empty())
			{
				//wprintf(L"%s - %s\n", dll_name, host_name.c_str());
				hosts.push_back(host_name);
			}
		}

		this->schema.emplace(std::move(dll_name), std::move(hosts));
	}
}

bool api_set::query(std::wstring& name)
{
	// SEARCH FOR ANY ENTRIES OF OUR PROXY DLL
	auto iter = std::find_if(this->schema.begin(), this->schema.end(), [name](const map_api_schema::value_type& val)
	{
		return name.find(val.first) != name.npos;
	});

	if (iter != this->schema.end()) // FOUND
	{
		name = (iter->second.front() != name ? iter->second.front() : iter->second.back());
		return true;
	}

	return false;
}
