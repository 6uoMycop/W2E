

add_cmocka_test(w2e_crypto_test
	SOURCES "w2e_crypto_test.c"
	LINK_LIBRARIES
		cmocka-static
		w2e_crypto
)
add_cmocka_test_environment(w2e_crypto_test)
target_include_directories(w2e_crypto_test PUBLIC "../")
