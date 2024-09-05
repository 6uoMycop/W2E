# CMakeList.txt: w2e_crypto lib tests

add_cmocka_test(w2e_crypto_test
	SOURCES "w2e_crypto_test.c"
	LINK_LIBRARIES
		cmocka
		w2e_crypto
)
add_cmocka_test_environment(w2e_crypto_test)
target_include_directories(w2e_crypto_test PUBLIC "../src" "../include")

if (MSVC)
	# Copy cmocka DLL to be near EXE
	file(COPY "${cmocka-library_BINARY_DIR}/cmocka.dll" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
endif (MSVC)
