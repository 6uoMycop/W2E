# CMakeList.txt: проект CMake для w2e_client
#

add_executable (w2e_client "w2e_client.c" "w2e_client.h")

if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET w2e_client PROPERTY C_STANDARD 17)
endif()

target_link_libraries(w2e_client WinDivert)
