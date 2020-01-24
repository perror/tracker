#include <stdlib.h>

int main (int argc, char *argv[])
{
	int x = atoi(argv[1]);
	if (x == 0)
		x = x + 42;
	else if (x < 0)
		x = -x;
	else
		x++;
	return EXIT_SUCCESS;
}
