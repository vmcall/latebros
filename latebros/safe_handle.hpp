#pragma once
#include "stdafx.h"

struct delete_safe_handle_t
{
	void operator()(void* handle) const noexcept
	{
		if(handle)
			CloseHandle(handle);
	}
};

using safe_handle = std::unique_ptr<void, delete_safe_handle_t>;
