# CMakeList.txt : CMake project for PackThis, include source and define
# project specific logic here.
#

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ..
    .
)

include_directories(${KERNEL_INCLUDE})

# Add source to this project's executable.
add_executable (PackThis 
    "main.cpp"
    "utils/Logger.h" 
    "utils/Logger.cpp" 
    "utils/MakeException.h" 
    "utils/NoCopy.h" 
    "utils/NoMove.h" 
    "utils/WithText.h" 
    "utils/Utils.cpp" 
    "utils/Utils.h" 
    "map_mem/MapMem.h" 
    "map_mem/MapMem.cpp" 
    "map_mem/Headers.h" 
    "map_mem/BinaryHelper.h"   )

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET PackThis PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
