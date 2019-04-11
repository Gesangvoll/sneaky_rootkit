#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() { printf("sneaky_process pid = %d\n", getpid()); }
