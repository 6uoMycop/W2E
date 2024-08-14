# CMakeList.txt: проект CMake для w2e_crypto (static lib)
#

add_library (w2e_crypto STATIC
	"w2e_crypto.h"
	"aes.h"
	"aes_i.h"
	"aes-gcm.c"
	"common.h"
	"aes-internal-enc.c"
	"aes-internal-dec.c"
	"w2e_crypto.c"
)

if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET w2e_crypto PROPERTY C_STANDARD 17)
elseif (CMAKE_VERSION VERSION_GREATER 3.1)
	set_property(TARGET w2e_crypto PROPERTY C_STANDARD 11)
endif()


if (MSVC)
	target_compile_options(w2e_crypto PRIVATE /Wall /we4702 /we4505)
else()
	target_compile_options(w2e_crypto PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
