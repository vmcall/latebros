#include "stdafx.h"

std::vector<uint8_t> file::read_binary_file( const std::string& file_path )
{
	std::ifstream stream(file_path, std::ios::binary);

	stream.unsetf(std::ios::skipws);

	auto buffer = std::vector<uint8_t>();
	stream.seekg(0, std::ios::end);
	buffer.resize(stream.tellg());
	stream.seekg(0, std::ios::beg);

	stream.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

	return buffer;
}
