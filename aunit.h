// Because these macros do some printing on their own, we need stdio
#include <stdio.h>

#define AU_VERSION "0.0.1"

// If you want to use your own main() function, or you want to test outside of main(), use au_init and au_end
// au_init declares some variables that are used for storing passed and failed counts.
// Strictly speaking, au_end is not necessary - it simply prints the passed and failed stats and then returns an integer.
// If any tests fail, au_end returns 0, otherwise it returns 1 to indicate complete success.
#define au_init unsigned int au_tests_run = 0, au_tests_failed = 0; puts("");
#define au_end printf("\n   \033[36m%u\033[0m tests run - ", au_tests_run); if (au_tests_failed == 0) { puts("\033[32mall tests passed\033[0m\n"); return 0; } else { printf("\033[31;1m%u test(s) failed\n\033[0m\n", au_tests_failed); return 1; }

// If you are using a standalone unit test file with no main(), use these macros.
#define au_main int main() { au_init
#define au_endmain au_end }

// The most general test, if nothing else fits. Takes an expression, and evals.
// If the expression evaluates to C's idea of 'true', the test passes. Otherwise, the test fails.
// Do not use this unless necessary - no expected and actual values are displayed if the test fails.
#define au_assert(description, test) do { printf("%5u ", ++au_tests_run); if (!(test)) { ++au_tests_failed; printf("\033[31;1m[F]\033[0m %s [\033[36m%s\033[0m]\n", #description, #test); } else printf("\033[32m[P]\033[0m %s [\033[36m%s\033[0m]\n", #description, #test); } while (0);

// Assert that an expression is either equal to or !equal (respectively) to another expression.
// au_eq is used for integer comparisons - on failure, displays the hex, signed, and unsigned values of the expected and actual values
#define au_eq(description, expression, expected) do { +printf("%5u ", ++au_tests_run); if ((expression) != (expected)) { ++au_tests_failed; printf("\033[31;1m[F]\033[0m %s [expression: \033[36m%s\033[0m] [expected: \033[36m0x%X (%%d=%+d, %%u=%u)\033[0m] [actual: \033[31m0x%X (%%d=%+d, %%u=%u)\033[0m]\n", #description, #expression, (expected), (expected), (expected), (expression), (expression), (expression)); } else printf("\033[32m[P]\033[0m %s [\033[36m%s == %s\033[0m]\n", #description, #expression, #expected); } while (0);
#define au_neq(description, expression, expected) do { +printf("%5u ", ++au_tests_run); if ((expression) == (expected)) { ++au_tests_failed; printf("\033[31;1m[F]\033[0m %s [expression: \033[36m%s\033[0m] [expected: \033[33mnot\033[0m \033[36m0x%X (%%d=%+d, %%u=%u)\033[0m] [actual: \033[31m0x%X (%%d=%+d, %%u=%u)\033[0m]\n", #description, #expression, (expected), (expected), (expected), (expression), (expression), (expression)); } else printf("\033[32m[P]\033[0m %s [\033[36m%s != %s\033[0m]\n", #description, #expression, #expected); } while (0);

// au_eq_float is specifically for floating-point comparisons. Uses %g for the shortest reasonable printing of the number
#define au_eq_float(description, expression, expected) do { +printf("%5u ", ++au_tests_run); if ((expression) != (expected)) { ++au_tests_failed; printf("\033[31;1m[F]\033[0m %s [expression: \033[36m%s\033[0m] [expected: \033[36m%g\033[0m] [actual: \033[31m%g\033[0m]\n", #description, #expression, (expected), (expression)); } else printf("\033[32m[P]\033[0m %s [\033[36m%s == %s\033[0m]\n", #description, #expression, #expected); } while (0);
#define au_neq_float(description, expression, expected) do { +printf("%5u ", ++au_tests_run); if ((expression) == (expected)) { ++au_tests_failed; printf("\033[31;1m[F]\033[0m %s [expression: \033[36m%s\033[0m] [expected: \033[33mnot\033[0m \033[36m%g\033[0m] [actual: \033[31m%g\033[0m]\n", #description, #expression, (expected), (expression)); } else printf("\033[32m[P]\033[0m %s [\033[36m%s != %s\033[0m]\n", #description, #expression, #expected); } while (0);
