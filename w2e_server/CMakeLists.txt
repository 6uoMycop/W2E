# CMakeList.txt: проект CMake для w2e_server (Linux)
#

add_executable (w2e_server "w2e_server.c" "w2e_server.h")

if (CMAKE_VERSION VERSION_GREATER 3.21)
	set_property(TARGET w2e_server PROPERTY C_STANDARD 17)
elseif (CMAKE_VERSION VERSION_GREATER 3.1)
	set_property(TARGET w2e_server PROPERTY C_STANDARD 11)
endif()

if(MSVC)
	message(FATAL_ERROR "w2e_server is a Linux app")
else()
	target_compile_options(w2e_crypto PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Copy configs to be near executable
file(GLOB G_VAR_CONFIGS "${CMAKE_HOME_DIRECTORY}/w2e_server/*.config") # For wildcard COPY
file(COPY ${G_VAR_CONFIGS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(w2e_server
	PUBLIC -lw2e_crypto
	PUBLIC -lnetfilter_queue
	PUBLIC -lpthread
	PUBLIC -lrt
	PUBLIC -lm
	PUBLIC -linih
	PUBLIC -lw2e_conntrack
#	PRIVATE cmocka-static
)


#enable_testing()
#add_test(NAME w2e_server COMMAND w2e_server)
