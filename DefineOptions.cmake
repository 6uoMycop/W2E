add_compile_definitions(W2E_VERSION="${CMAKE_PROJECT_VERSION}")
add_compile_definitions(W2E_LINK="https://github.com/6uoMycop/W2E")


if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_compile_definitions(W2E_DEBUG)
endif()

add_compile_definitions(W2E_DEBUG_NO_HEX)
add_compile_definitions(W2E_VERBOSE)


add_compile_definitions(W2E_INI_DEFAULT_NAME="default.config")
add_compile_definitions(W2E_MAX_CLIENTS=10)

add_compile_definitions(W2E_CT_SESSION_TTL=600)


# Number of NFQUEUEs (and threads - 1 per queue) on server. IN RANGE [1,99]
add_compile_definitions(W2E_SERVER_NFQUEUE_NUM=2)

# Write server counters to shared memory
add_compile_definitions(W2E_SERVER_WITH_SHMM_CTRS)

# Interval in seconds for shared memory counters update.
# (only usable if W2E_SERVER_WITH_SHMM_CTRS is defined)
add_compile_definitions(W2E_SERVER_SHMM_CTRS_UPD_INTERVAL=5)

