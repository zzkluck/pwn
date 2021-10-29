#include<stdio.h>
#include<stdlib.h>
int main()
{
	srand(0);
	for(int i = 0; i < 100; i++)
	{
		printf("%d", rand() % 6 + 1);
	}
}
