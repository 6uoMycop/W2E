#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "w2e_crypto.h"


void test_do_something(void** state)
{
	(void)state; /* unused */
}

int main(int argc, char* argv[])
{
	const struct CMUnitTest tests[] = {
	  cmocka_unit_test(test_do_something),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}