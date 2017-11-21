#pragma once
#include "stdafx.h"

class file
{
public:
	static std::vector<uint8_t> read_binary_file(const std::string& file_path);
};
