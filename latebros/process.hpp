#pragma once
#include "stdafx.h"
#include "memory_section.hpp"

class process;

process get_current_process();

std::vector<process> get_all_processes();

std::vector<process> get_all_processes(const std::string& process_name);

class process
{
public:
	process(uint32_t id, DWORD desired_access);
	process(HANDLE handle) : handle(handle) {}

	explicit operator bool() const;

#pragma region Memory
	MEMORY_BASIC_INFORMATION virtual_query(const uintptr_t address);
	uintptr_t raw_allocate(const SIZE_T virtual_size, const uintptr_t address = 0);
	bool free_memory(const uintptr_t address);
	bool read_raw_memory(void* buffer, const uintptr_t address, const SIZE_T size) const;
	bool write_raw_memory(const void* buffer, const SIZE_T size, const uintptr_t address) const;
	bool virtual_protect(const uintptr_t address, uint32_t protect, uint32_t* old_protect) const;

	uintptr_t map(memory_section& section);

	template <class T>
	uintptr_t allocate_and_write(const T& buffer)
	{
		auto buffer_pointer = allocate(buffer);
		write_memory(buffer, buffer_pointer);
		return buffer_pointer;
	}

	template <class T>
	uintptr_t allocate()
	{
		return raw_allocate(sizeof(T));
	}

	template<class T>
	bool read_memory(T* buffer, const uintptr_t address) const
	{
		return read_raw_memory(buffer, address, sizeof(T));
	}

	template<class T>
	bool write_memory(const T& buffer, const uintptr_t address) const
	{
		return write_raw_memory(&buffer, sizeof(T), address);
	}

	std::string read_string(std::uintptr_t address, std::size_t max_chars) const
	{
		std::string s;
		s.resize(max_chars);
		if(read_raw_memory(s.data(), address, max_chars))
			if(auto it = s.find('\0'); it != std::string::npos) {
				s.resize(it);
				return s;
			}

		return {};
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
