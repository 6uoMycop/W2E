# CMakeList.txt: проект CMake для w2e_client (Windows)
#

add_executable (w2e_client "w2e_client.c" "w2e_client.h")

if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET w2e_client PROPERTY C_STANDARD 17)
endif()

# Copy DLL and SYS to be near EXE
file(COPY "${CMAKE_HOME_DIRECTORY}/WinDivert/x64/WinDivert.dll" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY "${CMAKE_HOME_DIRECTORY}/WinDivert/x64/WinDivert64.sys" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
# Add resource
target_sources(w2e_client PRIVATE w2e_client.rc)


if(MSVC)
	target_compile_options(w2e_crypto PRIVATE /Wall /we4702)
else()
	message(FATAL_ERROR "w2e_client is a Windows app")
endif()


target_link_libraries(w2e_client
	PUBLIC w2e_crypto
	PUBLIC WinDivert
	PUBLIC wsock32
	PRIVATE cmocka-static
)


enable_testing()
add_test(NAME w2e_client COMMAND w2e_client)
