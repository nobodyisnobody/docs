#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static void setup() {
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
}

uint64_t getint(char *msg)
{
char buf[64];

	printf("%s", msg);
	fgets(buf,64,stdin);
	return strtoul(buf,0,10);
}

int main()
{
uint64_t choice;
uint64_t addr;
uint64_t size;

	setup();
	printf("libc stdout leak: %p\n", stdout);
	while(1)
	{
		puts("1. write data to addr");
		puts("2. exit");
		choice = getint("choice> ");
		if (choice == 2)
			break;
		else if (choice == 1)
		{
			addr = getint("address> ");
			size = getint("size> ");
			printf("data> ");
			fread((void *)addr,size,1,stdin);
		}
		else
			continue;
	}
	return(0);
}

