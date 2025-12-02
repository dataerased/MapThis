#include "utils/Logger.h"
#include "utils/Utils.h"
using namespace logger;

#include "map_mem/MapMem.h"
#include <filesystem>

//#define DEBUG_PRINT

#ifdef DEBUG_PRINT
#define CALL_CHECK(command) { auto res = command; if (!res) { Log() << #command << " -- " << res.text() << std::endl; return -1; } else { Log() << #command << " -- " << res.text() << std::endl; } }
#else
#define CALL_CHECK(command) { auto res = command; if (!res) { Log() << #command << " -- " << res.text() << std::endl; return -1; } }
#endif

int main(int argc, char* argv[])
{
	try
	{
        constexpr auto mapper_prefix = "mapper_";
        std::string current = argv[0];
        if (std::filesystem::path(current).filename().string().find(mapper_prefix) != 0)
        {
            Log() << "Invalid mapper name" << std::endl;
            return -1;
        }

        auto victim = std::filesystem::path(current).parent_path() / (std::filesystem::path(current).filename().string().substr(sizeof(mapper_prefix) - 1));
        if (!std::filesystem::exists(victim))
        {
            Log() << "Victim [" << victim << "] doesnt exist" << std::endl;
            return -1;
        }

		auto map_mem = MapMem::from_file(victim.string());
		CALL_CHECK(map_mem.relocate_va());
		CALL_CHECK(map_mem.load_dependencies());
		CALL_CHECK(map_mem.fix_page_protections());
		CALL_CHECK(map_mem.init_security_cookie());
		CALL_CHECK(map_mem.process_tls());
		CALL_CHECK(map_mem.register_exceptions());
		CALL_CHECK(map_mem.run_static_constructors());

		Log() << "It's Execute Time!" << std::endl;
		map_mem.execute(false);
		return 0;
	}
	catch (const std::exception& ex)
	{
		Log() << "Exception: " << ex.what() << std::endl;
	}
	return 0;
}
