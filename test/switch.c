#include <stdlib.h>

int main (int argc, char *argv[])
{
	int x = atoi(argv[1]);
	switch (x % 3)
	{
		case 0:
			x++;
			break;
		case 1:
			x--;
			break;
		case 2:
			x *= 2;
			break;
	}
	return EXIT_SUCCESS;
}
