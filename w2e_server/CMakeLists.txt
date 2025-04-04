# CMakeList.txt: проект CMake для w2e_server (Linux)
#

add_executable (w2e_server "w2e_server.c" "w2e_server.h")

set_property(TARGET w2e_server PROPERTY C_STANDARD 17)

if(MSVC)
	message(FATAL_ERROR "w2e_server is a Linux app")
else()
#	target_compile_options(w2e_server PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Copy configs to be near executable
file(GLOB G_VAR_CONFIGS "${CMAKE_HOME_DIRECTORY}/w2e_server/*.config") # For wildcard COPY
file(COPY ${G_VAR_CONFIGS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
# Copy scripts to be near EXE
file(GLOB G_VAR_CONFIGS "${CMAKE_HOME_DIRECTORY}/misc/scripts_lin/*") # For wildcard COPY
file(COPY ${G_VAR_CONFIGS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(w2e_server
	PUBLIC -lw2e_crypto
	PUBLIC -lcrypto
	PUBLIC -lnetfilter_queue
	PUBLIC -lrt
	PUBLIC -lm
	PUBLIC -linih
	PUBLIC -lw2e_conntrack
	PUBLIC -pthread
	PUBLIC -lnfnetlink
#	PRIVATE cmocka-static
)


#enable_testing()
#add_test(NAME w2e_server COMMAND w2e_server)
