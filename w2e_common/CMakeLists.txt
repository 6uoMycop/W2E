# CMakeList.txt: проект CMake для библиотеки w2e_common
#

add_library (w2e_common STATIC "w2e_common.c" "w2e_common.h")

if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET w2e_common PROPERTY C_STANDARD 17)
endif()
