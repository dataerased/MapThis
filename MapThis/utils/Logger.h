#pragma once
#include <iostream>
#include <sstream>
#include <chrono>
#include "NoMove.h"
#include "NoCopy.h"

namespace logger
{

	class LoggerManager : utils::NoCopy, utils::NoMove
	{
	public:
		class LogHelper : utils::NoCopy, utils::NoMove
		{
		public:
			LogHelper(LoggerManager& parent);
			~LogHelper();

			template<typename VAL>
			LogHelper& operator<<(const VAL& val)
			{
				m_stream << val;
				return *this;
			}

			LogHelper& operator<<(std::ostream& (*endlPar) (std::ostream& os));

		private:
			LoggerManager& m_parent;
			std::stringstream m_stream;
			static const std::chrono::steady_clock::time_point m_start;

		};

		LoggerManager();
		void safe_log(const std::string& text);
		LogHelper helper();

	};

	LoggerManager::LogHelper Log();
}
