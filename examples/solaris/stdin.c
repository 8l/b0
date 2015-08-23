#include <stdio.h>
#include <stdlib.h>

void* __stdin = stdin;
void* __stdout = stdout;
void* __stderr = stderr;

int main(int argc, char *argv[]){

	fprintf(__stdout, "Stdout = %lx, stdin = %lx, stderr = %lx\n", __stdout, __stdin, __stderr);
	fprintf(__stdout, "Sizeof(stdin) = %lx\n", sizeof(stdin));
	fprintf(__stdout, "SizeOf(_NFile) = %lx\n", (__stdin - __stdout));
	exit(1);
}
