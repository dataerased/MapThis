#pragma once

namespace utils
{
	class NoCopy
	{
	public:
		NoCopy() = default;
		NoCopy(const NoCopy&) = delete;
		NoCopy& operator=(const NoCopy&) = delete;
	};
}
