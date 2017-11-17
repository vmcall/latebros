#include "stdafx.h"
#include "rng.hpp"

std::random_device g_seed;
std::mt19937 rng::generator = std::mt19937(g_seed());
