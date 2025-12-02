#pragma once
#include <sstream>

template<typename RESULT>
class WithText
{
public:
	WithText(RESULT result)
		: m_result(result)
	{
	}

	WithText(const WithText&o)
		: m_result(o.m_result)
	{
		m_stream << o.m_stream.str();
	}

	WithText(WithText&& o)
		: m_result(std::move(o.m_result))
		, m_stream(std::move(o.m_stream))
	{
	}

	WithText& operator=(const WithText& o)
	{
		m_result = o.m_result;
		m_stream = o.m_stream;
	}

	WithText& operator=(WithText&& o)
	{
		m_result = std::move(o.m_result);
		m_stream << o.m_stream.str();
	}

	operator RESULT()
	{
		return m_result;
	}

	operator RESULT() const
	{
		return m_result;
	}

	std::string text() const
	{
		return m_stream.str();
	}

	template<typename VAL>
	WithText& operator<<(const VAL& val)
	{
		m_stream << val;
		return *this;
	}

private:
	RESULT m_result;
	std::stringstream m_stream;
};