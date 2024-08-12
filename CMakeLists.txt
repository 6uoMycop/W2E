# CMakeList.txt: файл проекта CMake верхнего уровня
#
cmake_minimum_required (VERSION 3.8)

# Включение горячей перезагрузки для компиляторов MSVC, если поддерживается.
if (POLICY CMP0141)
	cmake_policy(SET CMP0141 NEW)
	set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("W2E" VERSION 0.1 LANGUAGES C)

include_directories(
	"w2e_common"
	"WinDivert/include"
)

link_directories("WinDivert/x64")  # 64bit
# link_directories("WinDivert/x86")  # 32bit

# CMocka download
include(FetchCMocka.cmake)


# CONFIG
add_compile_definitions(W2E_DEBUG)


# Подпроекты
add_subdirectory ("w2e_common")  # Common library, linked to all apps
add_subdirectory ("w2e_client")  # Client application
add_subdirectory ("w2e_server")  # Server application
