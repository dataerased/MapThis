#pragma once
#include "utils/NoCopy.h"
#include "utils/NoMove.h"
#include "utils/WithText.h"
#include "Headers.h"
#include "BinaryHelper.h"
#include <string>
#include <vector>

class MapMem : public utils::NoCopy, public utils::NoMove
{
public:
	static MapMem from_file(const std::string &file);
	static MapMem from_buffer(uint8_t* buffer);

	WithText<bool> relocate_va();
	WithText<bool> load_dependencies();
	WithText<bool> init_security_cookie();
	WithText<bool> register_exceptions();
	WithText<bool> process_tls();
	WithText<bool> run_static_constructors();
	WithText<bool> fix_page_protections();
	void execute(bool in_thread);

private:
	static MapMem from_helper(mem_bin_help::BinaryHelperBase* helper);

	MapMem(uint8_t* base, size_t size);

	uint8_t* m_base = nullptr;
	size_t m_size = 0;

	template<typename OBJECT>
	OBJECT* get_pointer_va(size_t offset)
	{
		return reinterpret_cast<OBJECT*>(normalize_offset(offset));
	}

	uint8_t* normalize_offset(size_t offset);
	std::string read_nullterminated_string(size_t offset);

	ImageNtHeaders* nt_header();
	ImageDosHeader* dos_header();
	std::vector<ImageSectionHeader*> sections();
	ImageDataDirectory* data_directory(int index);
	std::vector<ImageImportDescriptor*> imports();

};