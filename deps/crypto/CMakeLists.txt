# CMakeList.txt: проект CMake для crypto (cross-platform) (static lib)
# AES implementation taken from:
# https://github.com/freebsd/freebsd-src/tree/main/contrib/wpa/src/crypto
#

add_library (crypto STATIC
	"common.h"
	"aes.h"
	"aes_i.h"
	"aes-gcm.c"
	"aes-internal-enc.c"
	"aes-internal-dec.c"
)


if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET crypto PROPERTY C_STANDARD 17)
elseif (CMAKE_VERSION VERSION_GREATER 3.1)
	set_property(TARGET crypto PROPERTY C_STANDARD 11)
endif()


#if (MSVC)
#	target_compile_options(crypto PRIVATE /Wall /we4702 /we4505)
#else()
#	target_compile_options(crypto PRIVATE -Wall -Wextra -Wpedantic -Werror)
#endif()
