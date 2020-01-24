#include <stdlib.h>

int foo (int x)
{
	return x + 42;
}

int main (int argc, char *argv[])
{
	int x = atoi (argv[1]);
	foo(x);
	return EXIT_SUCCESS;
}
