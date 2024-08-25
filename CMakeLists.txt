# CMakeList.txt: файл проекта CMake верхнего уровня
#
cmake_minimum_required (VERSION 3.8)

# Включение горячей перезагрузки для компиляторов MSVC, если поддерживается.
if (POLICY CMP0141)
	cmake_policy(SET CMP0141 NEW)
	set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("W2E" VERSION 0.2 LANGUAGES C)

# Common
include_directories(
	"w2e_common"
	"inih"
	"w2e_crypto"
	"w2e_conntrack" # TODO remove this in release: should only be used in Linux server
)
link_directories(
	"inih"
	"w2e_crypto"
	"w2e_conntrack" # TODO remove this in release: should only be used in Linux server
)

# Windows-specific
if (MSVC)
include_directories(
	"WinDivert/include"
)
link_directories("WinDivert/x64")  # 64bit
# link_directories("WinDivert/x86")  # 32bit
endif ()

# Linux-specific # TODO uncomment this in release
#if(UNIX)
#include_directories(
#	"w2e_conntrack"
#)
#link_directories(
#	"w2e_conntrack"
#)
#endif(UNIX)


#if (MSVC)
## CMocka download
#include(FetchCMocka.cmake)
#endif ()


# CONFIG
include(DefineOptions.cmake)


# Подпроекты

add_subdirectory ("w2e_crypto")  # Cryptographic library (Windows & Linux)
add_subdirectory ("inih")  # INI parser library (Windows & Linux)

add_subdirectory ("w2e_conntrack")  # Conntrack (Linux) //@TODO move to Linux

if (MSVC)
add_subdirectory ("w2e_client")  # Client application (Windows)
endif ()

if (UNIX)
add_subdirectory ("w2e_server")  # Server application (Linux)
endif()

