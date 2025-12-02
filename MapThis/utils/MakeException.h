#pragma once

#include <stdexcept>
#include <string>

#define MAKE_EXCEPTION(EX, PARENT)										\
namespace exception {													\
class EX : public PARENT												\
{																		\
public:																	\
	EX(){}																\
	EX(const std::string& what) : m_what(#EX": " + what) {}				\
	virtual char const* what() const override { return m_what.c_str(); }\
private:																\
	std::string m_what;													\
}; }