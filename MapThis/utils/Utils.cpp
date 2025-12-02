#include "Utils.h"
#include <sstream>
#include <iomanip>

namespace utils
{
	std::string to_hex(const void* data, size_t size)
	{
		std::stringstream ss{};
		ss << std::setfill('0') << std::hex << std::uppercase;
		for (auto* p = static_cast<const char*>(data); size; ++p)
		{
			ss << std::setw(2) << (*(int*)p & 0xFF) << (--size ? " " : "");
		}
		return ss.str();
	}
}
