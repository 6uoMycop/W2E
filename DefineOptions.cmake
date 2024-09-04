add_compile_definitions(W2E_VERSION="${CMAKE_PROJECT_VERSION}")
add_compile_definitions(W2E_LINK="https://github.com/6uoMycop/W2E")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_compile_definitions(W2E_DEBUG)
endif()

# Unit tests enable
set(UNIT_TESTING ON CACHE BOOL "CMocka: Build with unit testing" FORCE)

add_compile_definitions(W2E_DEBUG_NO_HEX)
add_compile_definitions(W2E_VERBOSE)

add_compile_definitions(W2E_INI_DEFAULT_NAME="default.config")
add_compile_definitions(W2E_MAX_CLIENTS=10)

#add_compile_definitions(W2E_CT_SESSION_TTL=600)
add_compile_definitions(W2E_CT_SESSION_TTL=100)

# cmocka
set(WITH_STATIC_LIB ON CACHE BOOL "CMocka: Build with a static library" FORCE)
set(WITH_CMOCKERY_SUPPORT OFF CACHE BOOL "CMocka: Install a cmockery header" FORCE)
set(WITH_EXAMPLES OFF CACHE BOOL "CMocka: Build examples" FORCE)
set(PICKY_DEVELOPER OFF CACHE BOOL "CMocka: Build with picky developer flags" FORCE)
