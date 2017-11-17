#pragma once
#include "stdafx.h"

class rng
{
public:
	template <typename T>
	static inline T get_int(T min, T max)
	{
		std::uniform_int_distribution<T> distribution(min, max);
		return distribution(rng::generator);
	}
	template <typename T>
	static inline T get_real(T min, T max)
	{
		std::uniform_real_distribution<T> distribution(min, max);
		return distribution(rng::generator);
	}
private:
	static std::mt19937 generator;
};