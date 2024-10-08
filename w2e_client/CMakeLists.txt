﻿# CMakeList.txt: проект CMake для w2e_client (Windows)
#

add_executable (w2e_client "w2e_client.c" "w2e_client.h")

if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET w2e_client PROPERTY C_STANDARD 17)
endif()

# Copy DLL and SYS to be near EXE
file(COPY "${CMAKE_HOME_DIRECTORY}/deps/WinDivert/x64/WinDivert.dll" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY "${CMAKE_HOME_DIRECTORY}/deps/WinDivert/x64/WinDivert64.sys" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
# Copy configs to be near EXE
file(GLOB G_VAR_CONFIGS "${CMAKE_HOME_DIRECTORY}/w2e_client/*.config") # For wildcard COPY
file(COPY ${G_VAR_CONFIGS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
# Copy scripts to be near EXE
file(GLOB G_VAR_CONFIGS "${CMAKE_HOME_DIRECTORY}/misc/scripts_win/*") # For wildcard COPY
file(COPY ${G_VAR_CONFIGS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
# Copy tests to be near EXE
file(COPY "${CMAKE_HOME_DIRECTORY}/misc/tests/" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/tests/")
# Add resource
target_sources(w2e_client PRIVATE w2e_client.rc)


#if(MSVC)
#	target_compile_options(w2e_client PRIVATE /Wall /we4702 /we4505)
#else()
#	message(FATAL_ERROR "w2e_client is a Windows app")
#endif()


target_link_libraries(w2e_client
	PUBLIC inih
	PUBLIC w2e_crypto
	PUBLIC WinDivert
	PUBLIC wsock32
	PUBLIC Ws2_32
#	PRIVATE cmocka-static
)

#
#enable_testing()
#add_test(NAME w2e_client COMMAND w2e_client)
