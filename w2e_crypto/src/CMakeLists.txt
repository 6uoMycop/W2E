# CMakeList.txt: проект CMake для w2e_crypto (static lib)
#

add_library (w2e_crypto STATIC
	"w2e_crypto.c"
)
target_include_directories(w2e_crypto
	PUBLIC "../include/"
)
target_link_libraries(w2e_crypto
	PUBLIC crypto
)

if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET w2e_crypto PROPERTY C_STANDARD 17)
elseif (CMAKE_VERSION VERSION_GREATER 3.1)
	set_property(TARGET w2e_crypto PROPERTY C_STANDARD 11)
endif()


#if (MSVC)
#	target_compile_options(w2e_crypto PRIVATE /Wall /we4702 /we4505)
#else()
#	target_compile_options(w2e_crypto PRIVATE -Wall -Wextra -Wpedantic -Werror)
#endif()

