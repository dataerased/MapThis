#include <iostream>

#define LOG(log) std::cout << log << std::endl;

#include <Windows.h>
extern "C" IMAGE_DOS_HEADER __ImageBase;

#include <fstream>
#include <Psapi.h>
LPVOID GetProcessBaseAddress(HANDLE hProcess) {
	HMODULE hMods[1024];
	DWORD cbNeeded;
	LPVOID baseAddress = nullptr;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		if (cbNeeded > 0) {
			MODULEINFO mi;
			if (GetModuleInformation(hProcess, hMods[0], &mi, sizeof(mi))) {
				baseAddress = mi.lpBaseOfDll;
			}
		}
	}
	return baseAddress;
}

int main(int argc, char* argv[])
{
	for (int i = 0; i < argc; ++i)
	{
		std::cout << argv[i] << std::endl;
	}

	auto h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
	std::cout << std::hex << (uint64_t)GetProcessBaseAddress(h) << std::endl;

	auto p = &__ImageBase;
	auto cope = *p;
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((uint64_t)p + cope.e_lfanew);

	std::cout << "IMAGE_BASE: " << std::hex << (uint64_t)p << std::endl;
	std::cout << "NT:  " << std::hex << (uint64_t)nt << std::endl;
	std::cout << "smth " << std::hex << *(uint64_t*)((uint64_t)p + 0x128) << std::endl;
	std::cout << "img  " << std::hex << nt->OptionalHeader.ImageBase << std::endl;

	std::cout << std::dec;

	//{
	//	std::ofstream full_dump("D:/temp/tesa.dmp", std::ios::binary);
	//	full_dump.write((const char*)p, nt->OptionalHeader.SizeOfCode);
	//	std::cout << "dumped" << std::endl;
	//}
	//std::cout << std::hex << &__ImageBase << std::endl;
	//auto dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	//std::cout << "IMAGE_DIRECTORY_ENTRY_EXCEPTION : "  << dir->VirtualAddress << " / " << (dir->Size / sizeof(RUNTIME_FUNCTION)) << std::endl;

	//auto pf = (RUNTIME_FUNCTION*)((uint8_t*)p + dir->VirtualAddress);
	//for (int i = 0; i < dir->Size / sizeof(RUNTIME_FUNCTION); ++i, ++pf)
	//{
	//	std::cout << i << " " << std::hex << pf->BeginAddress << "  -  " << pf->EndAddress << "  -  " << pf->UnwindInfoAddress << std::endl;
	//}

	//std::cout << "Cookie " << std::hex << __security_cookie << std::endl;

	//std::cout << "Ani co " << * reinterpret_cast<uint64_t*>((uint64_t)&__security_cookie + sizeof(uint64_t) * 8) << std::endl;

	LOG("Enter main");

	try
	{
		LOG("    throw: 42");
		throw 42;
	}
	catch (...)
	{
		LOG("    throw: catched");
	}


	LOG("  Enter throw");
	try
	{
		LOG("    throw: throw");
		throw std::exception("exception");
	}
	catch (const std::exception&)
	{
		LOG("    throw: catched");
	}
	LOG("    throw: done");

	LOG("  main: done");
}