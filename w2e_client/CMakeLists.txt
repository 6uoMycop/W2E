# CMakeList.txt: проект CMake для w2e_client
#

add_executable (w2e_client "w2e_client.c" "w2e_client.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
	set_property(TARGET w2e_client PROPERTY CXX_STANDARD 20)
endif()

