#pragma once
#include "stdafx.h"

namespace rng {
	
	inline std::mt19937& get_generator()
	{
		thread_local std::mt19937 generator(std::random_device{}());
		return generator;
	}

	template<typename T>
	inline T get_int(T min, T max)
	{
		std::uniform_int_distribution<T> distribution(min, max);
		return distribution(get_generator());
	}

	template<typename T>
	inline T get_real(T min, T max)
	{
		std::uniform_real_distribution<T> distribution(min, max);
		return distribution(get_generator());
	}

}
