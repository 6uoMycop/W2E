add_compile_definitions(W2E_VERSION="${CMAKE_PROJECT_VERSION}")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_compile_definitions(W2E_DEBUG)
endif()

add_compile_definitions(W2E_DEBUG_NO_HEX)
add_compile_definitions(W2E_VERBOSE)

add_compile_definitions(W2E_INI_DEFAULT_NAME="default.config")
add_compile_definitions(W2E_MAX_CLIENTS=10)

#add_compile_definitions(W2E_CT_SESSION_TTL=600)
add_compile_definitions(W2E_CT_SESSION_TTL=100)
