# CMakeList.txt: проект CMake для w2e_client
#

add_executable (w2e_client "w2e_client.c" "w2e_client.h")

if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET w2e_client PROPERTY C_STANDARD 17)
endif()

# Copy DLL to be near EXE
file(COPY "${CMAKE_HOME_DIRECTORY}/WinDivert/x64/WinDivert.dll" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(w2e_client
	PUBLIC WinDivert
	PRIVATE cmocka-static
)


enable_testing()
add_test(NAME w2e_client COMMAND w2e_server)
