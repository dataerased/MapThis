#include <Windows.h>

using ImageDosHeader = IMAGE_DOS_HEADER;
using ImageSectionHeader = IMAGE_SECTION_HEADER;
using ImageImportDescriptor = IMAGE_IMPORT_DESCRIPTOR;
using ImageExportDirectory = IMAGE_EXPORT_DIRECTORY;
using ImageImportByName = IMAGE_IMPORT_BY_NAME;
using ImageTlsDirectory = IMAGE_TLS_DIRECTORY;
using ImageBaseRelocation = IMAGE_BASE_RELOCATION;
using ImageDataDirectory = IMAGE_DATA_DIRECTORY;

#ifdef _M_X64
constexpr auto ImageFileMachine = IMAGE_FILE_MACHINE_AMD64;
using ImageNtHeaders = IMAGE_NT_HEADERS64;
using ImageThunkData = IMAGE_THUNK_DATA64;
using ImageLoadConfigDirectory = IMAGE_LOAD_CONFIG_DIRECTORY64;
using RuntimeFunction = RUNTIME_FUNCTION;
#else 
constexpr auto ImageFileMachine = IMAGE_FILE_MACHINE_I386;
using ImageNtHeaders = IMAGE_NT_HEADERS32;
using ImageThunkData = IMAGE_THUNK_DATA32;
using ImageLoadConfigDirectory = IMAGE_LOAD_CONFIG_DIRECTORY32;
#endif
