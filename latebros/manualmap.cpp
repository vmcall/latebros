#include "stdafx.h"
#include "manualmap.hpp"
#include "memory_section.hpp"
#include "binary_file.hpp"
#include "api_set.hpp"

uintptr_t injection::manualmap::inject(const std::vector<uint8_t>& buffer)
{
	// GET LINKED MODULES FOR LATER USE
	this->linked_modules = this->process.get_modules();

	// INITIALISE CONTEXT
	map_ctx ctx("littlebro", buffer);

	// MAP IMAGE AND ALL DEPENDENCIES
	if (!map_image(ctx))
		return 0;

	return ctx.remote_image;
}

bool injection::manualmap::map_image(map_ctx& ctx)
{

	auto section = memory_section(PAGE_EXECUTE_READWRITE, ctx.pe.get_optional_header().SizeOfImage);

	if (!section)
	{
		logger::log_error("Failed to create section");
		return false;
	}

	// MAP SECTION INTO BOTH LOCAL AND REMOTE PROCESS
	ctx.local_image = process::current_process().map(section);
	ctx.remote_image = this->process.map(section);

	if (!ctx.local_image || !ctx.remote_image)
	{
		logger::log_error("Failed to map section");
		return false;
	}

	// ADD MAPPED MODULE TO LIST OF MODULES
	this->mapped_modules.push_back(ctx);

	// MANUALMAP IMAGE
	write_headers(ctx);
	write_image_sections(ctx);
	fix_import_table(ctx);
	relocate_image_by_delta(ctx);

	return true;
}

uintptr_t injection::manualmap::find_or_map_dependency(const std::string& image_name)
{
	// HAVE WE MAPPED THIS MODULE ALREADY?
	for (const auto& module : this->mapped_modules)
		if (module.image_name == image_name)
			return module.remote_image;

	// WAS THIS MODULE ALREADY LOADED BY LDR?
	if (this->linked_modules.find(image_name) != this->linked_modules.end())
		return this->linked_modules.at(image_name);

	// TODO: PROPER FILE SEARCHING
	auto ctx = map_ctx(image_name, file::read_binary_file("C:\\Windows\\System32\\" + image_name));

	if (map_image(ctx))
		return ctx.remote_image;

	return 0;
}

void injection::manualmap::write_headers(map_ctx& ctx)
{
	memcpy(reinterpret_cast<void*>(ctx.local_image), ctx.get_pe_buffer(), ctx.pe.get_optional_header().SizeOfHeaders);
}
void injection::manualmap::write_image_sections(map_ctx& ctx)
{
	for (const auto& section : ctx.pe.get_sections())
		memcpy(reinterpret_cast<void*>(ctx.local_image + section.VirtualAddress), ctx.get_pe_buffer() + section.PointerToRawData, section.SizeOfRawData);
}

void injection::manualmap::relocate_image_by_delta(map_ctx& ctx)
{
	auto delta = ctx.remote_image - ctx.pe.get_image_base();

	for (auto&[entry, item] : ctx.pe.get_relocations(ctx.local_image))
		*reinterpret_cast<uintptr_t*>(ctx.local_image + entry.page_rva + item.get_offset()) += delta;
}

void injection::manualmap::fix_import_table(map_ctx& ctx)
{
	wstring_converter converter;
	api_set api_schema;

	for (const auto&[tmp_name, functions] : ctx.pe.get_imports(ctx.local_image))
	{
		auto module_name = tmp_name;

		std::wstring wide_module_name = converter.from_bytes(module_name.c_str());
		if (api_schema.query(wide_module_name))
			module_name = converter.to_bytes(wide_module_name);

		auto module_handle = find_or_map_dependency(module_name);
		if (!module_handle)
			logger::log_error("Failed to map dependency");

		for (const auto& fn : functions)
		{
			*reinterpret_cast<uintptr_t*>(ctx.local_image + fn.function_rva) = fn.ordinal > 0 ?
				this->process.get_module_export(module_handle, reinterpret_cast<const char*>(fn.ordinal)) :	// IMPORT BY ORDINAL
				this->process.get_module_export(module_handle, fn.name.c_str());							// IMPORT BY NAME
		}
	}
}

uint8_t* map_ctx::get_pe_buffer()
{
	return this->pe.get_buffer().data();
}
