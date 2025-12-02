#include "MapMem.h"
#include <fstream>
#include <vector>

namespace
{
	struct MappedInfo
	{
		std::uint64_t m_base;
		std::uint64_t m_size;
	};

	std::vector<MappedInfo> MAPPED_INFOS;

#define EH_MAGIC_NUMBER        0x19930520    
#define EH_PURE_MAGIC_NUMBER   0x01994000
#define EH_EXCEPTION_NUMBER     ('msc' | 0xE0000000)
	std::uint64_t MAGIC_BASE = 0;
	std::uint64_t MAGIX_SIZE = 0;

	LONG CALLBACK vectored_handler(EXCEPTION_POINTERS* ep) 
	{
		if (ep->ExceptionRecord->ExceptionCode == EH_EXCEPTION_NUMBER)
		{
			for (auto& mapped: MAPPED_INFOS)
			{
				if (ep->ExceptionRecord->ExceptionInformation[2] >= mapped.m_base &&
					ep->ExceptionRecord->ExceptionInformation[2] <= mapped.m_base + mapped.m_size)
				{
					if (ep->ExceptionRecord->ExceptionInformation[0] == EH_PURE_MAGIC_NUMBER
						&& ep->ExceptionRecord->ExceptionInformation[3] == 0)
					{
						ep->ExceptionRecord->ExceptionInformation[0] = (ULONG_PTR)EH_MAGIC_NUMBER;
						ep->ExceptionRecord->ExceptionInformation[3] = (ULONG_PTR)mapped.m_base;
						break;
					}
				}
			}
		}

		return EXCEPTION_CONTINUE_SEARCH;
	}
}

MapMem MapMem::from_file(const std::string& file)
{
	mem_bin_help::BinaryHelperFile helper(file);
	return MapMem::from_helper(&helper);
}

MapMem MapMem::from_buffer(uint8_t* buffer)
{
	mem_bin_help::BinaryHelperBuffer helper(buffer);
	return MapMem::from_helper(&helper);
}

MapMem MapMem::from_helper(mem_bin_help::BinaryHelperBase* helper)
{
	auto dos_h = helper->read_object<ImageDosHeader>(0);
	auto nt_h = helper->read_object<ImageNtHeaders>(dos_h.e_lfanew);

	auto additional_size = 0x1000;
	auto size = nt_h.OptionalHeader.SizeOfImage;
	auto base = reinterpret_cast<uint8_t*>(VirtualAlloc(reinterpret_cast<LPVOID>(nt_h.OptionalHeader.ImageBase), size + additional_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (base == nullptr)
	{
		base = reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, size + additional_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (base == nullptr)
			throw std::exception("Failed to allocate memory");
	}

	helper->read_to_memory(0, base, nt_h.OptionalHeader.SizeOfHeaders);

	for (int i = 0; i < nt_h.FileHeader.NumberOfSections; ++i)
	{
		auto section_header = helper->read_object<ImageSectionHeader>(dos_h.e_lfanew + sizeof(ImageNtHeaders) + i * sizeof(ImageSectionHeader));
		helper->read_to_memory(section_header.PointerToRawData, reinterpret_cast<char*>(base) + section_header.VirtualAddress, section_header.SizeOfRawData);
	}

	return MapMem(base, size);
}

MapMem::MapMem(uint8_t* base, size_t size)
	: m_base(base)
	, m_size(size)
{
}

ImageDosHeader* MapMem::dos_header()
{
	return get_pointer_va<ImageDosHeader>(0);
}

ImageNtHeaders* MapMem::nt_header()
{
	return get_pointer_va<ImageNtHeaders>(dos_header()->e_lfanew);
}

std::vector<ImageSectionHeader*> MapMem::sections()
{
	std::vector<ImageSectionHeader*> s{};

	for (int i = 0; i < nt_header()->FileHeader.NumberOfSections; ++i)
	{
		s.push_back(get_pointer_va<ImageSectionHeader>(dos_header()->e_lfanew + sizeof(ImageNtHeaders) + i * sizeof(ImageSectionHeader)));
	}

	return s;
}

ImageDataDirectory* MapMem::data_directory(int index)
{
	return &nt_header()->OptionalHeader.DataDirectory[index];
}

std::vector<ImageImportDescriptor*> MapMem::imports()
{
	std::vector<ImageImportDescriptor*> descrs;
	
	auto dir = data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dir->VirtualAddress == 0 || dir->Size == 0)
		return {};

	for (auto entry = get_pointer_va<ImageImportDescriptor>(dir->VirtualAddress);
		entry && entry->OriginalFirstThunk; 
		++entry)
	{
		descrs.push_back(entry);
	}

	return descrs;
}

uint8_t* MapMem::normalize_offset(size_t offset)
{
	uint64_t base_begin = reinterpret_cast<uint64_t>(m_base);
	uint64_t base_end = base_begin + m_size;

	if (offset >= base_begin && offset < base_end)
		return reinterpret_cast<uint8_t*>(offset);

	else if (offset < m_size)
		return reinterpret_cast<uint8_t*>(offset + base_begin);

	throw std::exception("pointer out of scope");
}

std::string MapMem::read_nullterminated_string(size_t offset)
{
	return std::string(reinterpret_cast<const char*>(normalize_offset(offset)));
}

WithText<bool> MapMem::relocate_va()
{
	std::int64_t delta = reinterpret_cast<int64_t>(m_base) - nt_header()->OptionalHeader.ImageBase;
	if (delta == 0)
		return WithText(true) << "Relocate not needed";

	if ((nt_header()->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
		return WithText(false) << "Relocate not allowed";

	auto dir_reloc = data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);

	if (dir_reloc->VirtualAddress == 0 || dir_reloc->Size == 0)
		return WithText(false) << "Empty relocate directory";

	auto table_reloc = get_pointer_va<ImageBaseRelocation>(dir_reloc->VirtualAddress);
	while (table_reloc->VirtualAddress != 0)
	{
		size_t relocations = (table_reloc->SizeOfBlock - sizeof(ImageBaseRelocation)) / sizeof(uint16_t);
		auto relocation_data = reinterpret_cast<uint16_t*>(&table_reloc[1]);

		for (size_t i = 0; i < relocations; ++i)
		{
			auto relocation = relocation_data[i];
			uint16_t type = relocation >> 12;
			uint16_t offset = relocation & 0xFFF;
			auto ptr = normalize_offset(table_reloc->VirtualAddress + offset);
			if (type == IMAGE_REL_BASED_DIR64)
			{
				*reinterpret_cast<uint64_t*>(ptr) += static_cast<uint64_t>(delta);
			}
			else if (type == IMAGE_REL_BASED_HIGHLOW)
			{
				*reinterpret_cast<uint32_t*>(ptr) += static_cast<uint32_t>(delta);
			}
		}
		table_reloc = reinterpret_cast<decltype(table_reloc)>(reinterpret_cast<uint8_t*>(table_reloc) + table_reloc->SizeOfBlock);
	}

	// Google says this is not necessary, but who cares (Win11 do this)
	nt_header()->OptionalHeader.ImageBase = reinterpret_cast<int64_t>(m_base);
	return WithText(true) << "Relocate sucessfull";
}

WithText<bool> MapMem::load_dependencies()
{
	for (auto import : imports())
	{
		auto lib_name = read_nullterminated_string(import->Name);
		auto lib = LoadLibraryA(lib_name.c_str());
		if (!lib)
			return WithText(false) << "Failed to load library: [" << lib_name << "] gle = " << GetLastError();

		auto addr_orig_thunk = import->OriginalFirstThunk;
		auto addr_thunk = import->FirstThunk;

		while (true)
		{
			auto orig_thunk = get_pointer_va<ImageThunkData>(addr_orig_thunk);
			auto thunk = get_pointer_va<ImageThunkData>(addr_thunk);

			if (thunk->u1.AddressOfData == 0)
				break;

			LPCSTR func_name = nullptr;
			if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				func_name = reinterpret_cast<LPCSTR>(orig_thunk->u1.Ordinal & ~IMAGE_ORDINAL_FLAG);
			}
			else
			{
				func_name = reinterpret_cast<LPCSTR>(normalize_offset(orig_thunk->u1.Ordinal + sizeof(ImageImportByName::Hint)));
			}

			FARPROC address = GetProcAddress(lib, func_name);
			if (!address)
			{
				return WithText(false) << "Failed to get function: "
					<< ((orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
						? "@" + std::to_string(reinterpret_cast<decltype(ImageThunkData::u1.Ordinal)>(func_name))
						: std::string(func_name));
			}

			thunk->u1.Function = reinterpret_cast<decltype(ImageThunkData::u1.Function)>(address);

			addr_thunk += sizeof(ImageThunkData);
			addr_orig_thunk += sizeof(ImageThunkData);
		}
	}
	return WithText(true) << "Dependencies loaded";
}

WithText<bool> MapMem::init_security_cookie()
{
	auto dir_config = data_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	if (dir_config->VirtualAddress == 0 || dir_config->Size == 0)
		return WithText(true) << "Empty config directory";

	auto config_table = get_pointer_va<ImageLoadConfigDirectory>(dir_config->VirtualAddress);
	if (config_table->SecurityCookie == 0)
		return WithText(true) << "No security cookie address";

	auto p_cookie = normalize_offset(config_table->SecurityCookie);

	LARGE_INTEGER perf{};
	QueryPerformanceCounter(&perf);

	uint64_t value = GetTickCount64() ^ reinterpret_cast<uint64_t>(m_base) ^ GetCurrentProcessId();
	value ^= static_cast<uint64_t>((perf.QuadPart << 32) ^ perf.QuadPart);

	if ((value & 0xFF) == 0)
	{
		value |= 0x0000A5A5A5A5A5A5ULL;
	}

#ifdef _M_X64
	value &= 0x0000FFFFFFFFFFFF;

	if (value == 0x2B992DDFA232)
		value++;

	auto p_cookie_value = reinterpret_cast<uint64_t*>(p_cookie);
	auto p_cookie_compliment = reinterpret_cast<uint64_t*>(p_cookie + sizeof(uint64_t) * 8);

	if (*p_cookie_compliment == ~(*p_cookie))
		*p_cookie_compliment = static_cast<uint64_t>(~value);
	*p_cookie_value = static_cast<uint64_t>(value);

#else
	if (value == 0xBB40E64E)
		value++;

	auto p_cookie_value = reinterpret_cast<uint32_t*>(p_cookie);
	auto p_cookie_compliment = reinterpret_cast<uint32_t*>(p_cookie + sizeof(uint64_t) * 8);

	if (*p_cookie_compliment == ~(*p_cookie))
		*p_cookie_compliment = static_cast<uint32_t>(~value);
	*p_cookie_value = static_cast<uint32_t>(value);
#endif

	return WithText(true) << "Security cookie initialized";
}

WithText<bool> MapMem::register_exceptions()
{
#ifdef _M_X64
	auto dir_except = data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
	if (dir_except->VirtualAddress == 0 || dir_except->Size == 0)
	{
		return WithText(true) << "Empty exception directory";
	}

	auto p_function = get_pointer_va<RuntimeFunction>(dir_except->VirtualAddress);
	DWORD count = dir_except->Size / sizeof(RuntimeFunction);

	auto res = RtlAddFunctionTable(p_function, count, reinterpret_cast<DWORD64>(m_base));
	if (res == FALSE)
		return WithText(false) << "RtlAddFunctionTable failed";

	MAPPED_INFOS.emplace_back(MappedInfo{ reinterpret_cast<uint64_t>(m_base), m_size });
	AddVectoredExceptionHandler(0, vectored_handler);
	return WithText(true) << "Exception registered [" << count << "] functions";
#else
	return WithText(true) << "Skip register exceptions for x86";
#endif
}

WithText<bool> MapMem::process_tls()
{
	auto dir_tls = data_directory(IMAGE_DIRECTORY_ENTRY_TLS);
	if (dir_tls->VirtualAddress == 0 || dir_tls->Size == 0)
		return WithText(true) << "Empty tls directory";

	auto table = get_pointer_va<ImageTlsDirectory>(dir_tls->VirtualAddress);

	if (table->StartAddressOfRawData == 0 || table->EndAddressOfRawData == 0)
		return WithText(false) << "Start or end of raw data is null";

	int counter = {};
	for (auto pcb = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(normalize_offset(table->AddressOfCallBacks)); *pcb; ++pcb, ++counter)
		(*pcb)(m_base, DLL_PROCESS_ATTACH, nullptr);
	
	return WithText(true) << "Total called TLS: " << counter;
}

WithText<bool> MapMem::run_static_constructors()
{
	std::vector<std::pair<std::string, ImageSectionHeader*>> crt_sections{};
	for (auto s : sections())
	{
		if (strncmp(reinterpret_cast<const char*>(s->Name), ".CRT$", sizeof(".CRT$")) == 0)
			crt_sections.push_back({std::string(reinterpret_cast<const char*>(s->Name), sizeof(s->Name)), s});
	}

	if (crt_sections.empty())
		return WithText(true) << "No static constructions secions";

	/* Something like that
	
		std::sort(crt.begin(), crt.end(), [](auto &a, auto &b){ return a.first < b.first; });

	for (auto &p : crt) {
		auto &sec = p.second;
		uint8_t* ptr = imageBase + sec.VirtualAddress;
		size_t cnt = sec.Misc.VirtualSize / sizeof(void*);
		for (size_t i = 0; i < cnt; ++i) {
			auto fn = reinterpret_cast<void(*)()>( reinterpret_cast<void**>(ptr)[i] );
			if (fn) {
				__try { fn(); }
				__except(EXCEPTION_EXECUTE_HANDLER) {
				}
			}
		}
	}
	
	*/

	return WithText(false) << "not implemented";
}

WithText<bool> MapMem::fix_page_protections()
{
	for (auto s : sections())
	{
		auto c = s->Characteristics;
		DWORD protect = PAGE_READONLY;

		if (s->Characteristics & IMAGE_SCN_MEM_WRITE &&
			s->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			protect = PAGE_EXECUTE_READWRITE;
		}
		else if (s->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			protect = PAGE_EXECUTE_READ;
		}
		else if (s->Characteristics & IMAGE_SCN_MEM_WRITE)
		{
			protect = PAGE_READWRITE;
		}

		auto size = (std::max)(s->Misc.VirtualSize, s->SizeOfRawData);
		if (size)
		{
			DWORD dummy{};
			if (VirtualProtect(normalize_offset(s->VirtualAddress), size, protect, &dummy) == FALSE)
				return WithText(false) << "VirtualProtect failed [" << std::string(reinterpret_cast<char*>(s->Name), sizeof(s->Name)) << "] gle: " << GetLastError();
		}
	}
	return WithText(true) << "Page protections fixed";
}

namespace
{ 
	typedef BOOL(WINAPI* Type_DllMain)(HMODULE, DWORD, LPVOID);

	DWORD WINAPI thread_stub_execute(LPVOID entrypoint)
	{
		reinterpret_cast<void(*)()>(entrypoint)();
		return 0;
	}
}

void MapMem::execute(bool in_thread)
{
	auto ep = nt_header()->OptionalHeader.AddressOfEntryPoint;
	if (ep == 0)
	{
		throw std::exception("AddressOfEntryPoint is null");
	}

	auto entrypoint = normalize_offset(ep);
	if (in_thread)
	{
		HANDLE h = CreateThread(NULL, 0, thread_stub_execute, reinterpret_cast<LPVOID>(entrypoint), 0, NULL);
		WaitForSingleObject(h, INFINITE);
	}
	else
	{
		reinterpret_cast<void(*)()>(entrypoint)();
	}
}
