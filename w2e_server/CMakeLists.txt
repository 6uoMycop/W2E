# CMakeList.txt: проект CMake для w2e_server
#

add_executable (w2e_server "w2e_server.c" "w2e_server.h")

if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET w2e_client PROPERTY C_STANDARD 17)
endif()

target_link_libraries(w2e_server
	PUBLIC WinDivert
	PRIVATE cmocka-static
)


enable_testing()
add_test(NAME w2e_server COMMAND w2e_server)
