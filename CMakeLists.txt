# CMakeList.txt: файл проекта CMake верхнего уровня
#
cmake_minimum_required (VERSION 3.8)

# Включение горячей перезагрузки для компиляторов MSVC, если поддерживается.
if (POLICY CMP0141)
	cmake_policy(SET CMP0141 NEW)
	set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("W2E" VERSION 0.1 LANGUAGES C)

include_directories("WinDivert/include")

if(CMAKE_SIZE_OF_VOID_P EQUAL 8)  # 64bit
	link_directories("WinDivert/x64")
else()  # 32bit
	link_directories("WinDivert/x86")
endif()

# CMocka download
include(FetchCMocka.cmake)

# Подпроекты
add_subdirectory ("w2e_client")
add_subdirectory ("w2e_server")
