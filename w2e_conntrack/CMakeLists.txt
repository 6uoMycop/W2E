# CMakeList.txt: проект CMake для w2e_conntrack (static lib). Used by Linux server
#

add_library (w2e_conntrack STATIC "w2e_conntrack.c" "w2e_conntrack.h")


if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET w2e_conntrack PROPERTY C_STANDARD 17)
elseif (CMAKE_VERSION VERSION_GREATER 3.1)
	set_property(TARGET w2e_conntrack PROPERTY C_STANDARD 11)
endif()


#if (MSVC)
#	#target_compile_options(w2e_conntrack PRIVATE /Wall /we4702 /we4505)
#else()
#	target_compile_options(w2e_conntrack PRIVATE -Wall -Wextra -Wpedantic -Werror)
#endif()
