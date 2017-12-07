#pragma once
#include "stdafx.h"

struct API_SET_VALUE_ENTRY
{
	ULONG flags;
	ULONG name_offset;
	ULONG name_length;
	ULONG value_offset;
	ULONG value_length;
};

struct API_SET_VALUE_ARRAY
{
	ULONG flags;
	ULONG name_offset;
	ULONG unknown;
	ULONG name_length;
	ULONG data_offset;
	ULONG count;

	const API_SET_VALUE_ENTRY* entry(const void* api_set, SIZE_T index) const
	{
		return reinterpret_cast<API_SET_VALUE_ENTRY*>(reinterpret_cast<uintptr_t>(api_set) + data_offset + index * sizeof(API_SET_VALUE_ENTRY));
	}
};

struct API_SET_NAMESPACE_ENTRY
{
	ULONG limit;
	ULONG size;
};

struct API_SET_NAMESPACE_ARRAY
{
	ULONG version;
	ULONG size;
	ULONG flags;
	ULONG count;
	ULONG start;
	ULONG end;
	ULONG unknown[2];

	const API_SET_NAMESPACE_ENTRY* entry(SIZE_T index) const
	{
		return reinterpret_cast<API_SET_NAMESPACE_ENTRY*>(reinterpret_cast<uintptr_t>(this) + end + index * sizeof(API_SET_NAMESPACE_ENTRY));
	}

	const API_SET_VALUE_ARRAY* get_host(const API_SET_NAMESPACE_ENTRY* entry_pointer) const
	{
		return reinterpret_cast<API_SET_VALUE_ARRAY*>(reinterpret_cast<uintptr_t>(this) + start + sizeof(API_SET_VALUE_ARRAY) * entry_pointer->size);
	}

	std::wstring get_name(const API_SET_NAMESPACE_ENTRY* entry_pointer)
	{
		const auto array_pointer = get_host(entry_pointer);
		const auto name_ptr      = reinterpret_cast<char*>(this) + array_pointer->name_offset;
		const auto name_len      = array_pointer->name_length / sizeof(wchar_t);

		return std::wstring(reinterpret_cast<wchar_t*>(name_ptr), name_len);
	}
};


using map_api_schema = std::unordered_map<std::wstring, std::vector<std::wstring>>;
class api_set
{
public:
	api_set();
	bool query(std::wstring& name) const;
	bool query(std::string& name) const;
private:
	map_api_schema schema;
};