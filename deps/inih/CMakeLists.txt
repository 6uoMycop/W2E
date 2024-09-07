# CMakeList.txt: проект CMake для inih (cross-platform) (static lib)
# Copy from https://github.com/benhoyt/inih
#

add_library (inih STATIC "inih.c" "inih.h")


if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET inih PROPERTY C_STANDARD 17)
elseif (CMAKE_VERSION VERSION_GREATER 3.1)
	set_property(TARGET inih PROPERTY C_STANDARD 11)
endif()


#if (MSVC)
#	target_compile_options(inih PRIVATE /Wall /we4702 /we4505)
#else()
#	target_compile_options(inih PRIVATE -Wall -Wextra -Wpedantic -Werror)
#endif()
