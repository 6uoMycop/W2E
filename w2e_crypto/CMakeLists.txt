# CMakeList.txt: проект CMake для w2e_crypto (static lib)
#

add_library (w2e_crypto STATIC
	"w2e_crypto.h"
	"aes.h"
	"aes_i.h"
	"aes_wrap.h"
	"aes-wrap.c"
	"aes-gcm.c"
	"common.h"
	"common.c"
	"includes.h"
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
add_compile_definitions(CONFIG_NATIVE_WINDOWS)
add_compile_definitions(_MSC_VER)
endif ()
