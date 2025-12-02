
include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ..
    .
)

# Add source to this project's executable.
add_executable (TestProject 
    "test_main.cpp"
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET TestProject PROPERTY CXX_STANDARD 20)
endif()