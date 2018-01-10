#pragma once
#include "stdafx.h"
#include <system_error>

namespace logger
{
	inline void log(const char* message)
	{
		std::cout << "[+] " << message << std::endl;
	}

	inline void log_win_error(const char* cause)
	{
		const auto ec = std::error_code(static_cast<int>(GetLastError()), std::system_category());
		std::cout << "[!] code: " << std::hex << ec.value()
				<< " message: " << ec.message()
				<< " what: " << cause << '\n';
	}

	inline void log_error(const char* message)
	{
		std::cout << "[!] " << message << std::endl;
	}

	template <class T>
	inline void log_formatted(const std::string& variable_name, const T& variable_data, bool hexadecimal = false)
	{
		auto format = hexadecimal ? std::hex : std::dec;
		std::cout << "[?] " << variable_name << ": " << format << variable_data << std::dec << std::endl;
	}
}