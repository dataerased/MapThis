#include "Logger.h"
#include <mutex>
#include <iomanip>

namespace logger
{
	const std::chrono::steady_clock::time_point LoggerManager::LogHelper::m_start = std::chrono::steady_clock::now();

	LoggerManager::LoggerManager()
	{
	}

	void LoggerManager::safe_log(const std::string& text)
	{
		static std::mutex mtx;
		std::unique_lock<decltype(mtx)> lock(mtx);
		std::cout << text;
	}

	LoggerManager::LogHelper LoggerManager::helper()
	{
		return LogHelper(*this);
	}

	LoggerManager::LogHelper::LogHelper(LoggerManager& parent)
		: m_parent(parent)
	{
		auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_start).count();
		
		auto seconds = milliseconds / 1000;
		milliseconds %= 1000;

		auto minutes = seconds / 60;
		seconds %= 60;

		auto hours = minutes / 60;
		minutes %= 60;

		auto curr_fill = m_stream.fill();
		m_stream << std::setfill('0') << "[" 
			<< std::setw(2) << hours << ":" 
			<< std::setw(2) << minutes << ":" 
			<< std::setw(2) << seconds << "." 
			<< std::setw(3) << milliseconds << "] ("
			<< std::hex << std::this_thread::get_id() << std::dec << ") "
			<< std::setfill(curr_fill);
	}

	LoggerManager::LogHelper::~LogHelper()
	{
		m_parent.safe_log(m_stream.str());
	}

	LoggerManager::LogHelper& LoggerManager::LogHelper::operator<<(std::ostream& (*endlPar) (std::ostream& os))
	{
		m_stream << endlPar;
		return *this;
	}

	LoggerManager::LogHelper Log()
	{
		static LoggerManager l{};
		return l.helper();
	}
}