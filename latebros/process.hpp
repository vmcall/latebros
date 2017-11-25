#pragma once
#include "stdafx.h"
#include "memory_section.hpp"

using wstring_converter = std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>;

class process
{
public:
	process(uint32_t id, DWORD desired_access);
	process(HANDLE handle) : handle(handle) {}

	explicit operator bool();

#pragma region Statics
	static process current_process();
	static std::vector<uint32_t> get_all_from_name(const std::string& process_name);
	static std::vector<uint32_t> get_all();
#pragma endregion

#pragma region Memory
	MEMORY_BASIC_INFORMATION virtual_query(const uintptr_t address);
	uintptr_t raw_allocate(const SIZE_T virtual_size, const uintptr_t address = 0);
	bool free_memory(const uintptr_t address);
	bool read_raw_memory(void* buffer, const uintptr_t address, const SIZE_T size) const;
	bool write_raw_memory(const void* buffer, const SIZE_T size, const uintptr_t address) const;
	bool virtual_protect(const uintptr_t address, uint32_t protect, uint32_t* old_protect) const;

	uintptr_t map(memory_section& section);

	template <class T>
	inline uintptr_t allocate_and_write(const T& buffer)
	{
		auto buffer_pointer = allocate(buffer);
		write_memory(buffer, buffer_pointer);
		return buffer_pointer;
	}

	template <class T>
	inline uintptr_t allocate()
	{
		return raw_allocate(sizeof(T));
	}

	template<class T>
	inline bool read_memory(T* buffer, const uintptr_t address) const
	{
		return read_raw_memory(buffer, address, sizeof(T));
	}

	template<class T>
	inline bool write_memory(const T& buffer, const uintptr_t address) const
	{
		return write_raw_memory(&buffer, sizeof(T), address);
	}

	template<class T>
	bool write_memory_safe(const T& buffer, const uintptr_t address) const
	{
		uint32_t old_protect;
		auto result = this->virtual_protect(address, PAGE_EXECUTE_READWRITE, &old_protect);
		if(result)
			return false;
		
		result = write_raw_memory(&buffer, sizeof(T), address);
		this->virtual_protect(old_protect, PAGE_EXECUTE_READWRITE, &old_protect);

		return result;
	}
#pragma endregion

#pragma region Information
	std::unordered_map<std::string, uintptr_t> get_modules() const;
	uintptr_t get_base_address() const;
	std::string get_name() const;
	uintptr_t get_import(const std::string& module_name, const std::string& function_name) const;
	uintptr_t get_module_export(uintptr_t module_handle, const char* function_ordinal) const;

	uintptr_t get_module_export(const std::string& module_name, const char* function_ordinal) const;
#pragma endregion

#pragma region Thread
	safe_handle create_thread(const uintptr_t address, const uintptr_t argument = 0) const;
#pragma endregion

private:
	safe_handle handle;
};
