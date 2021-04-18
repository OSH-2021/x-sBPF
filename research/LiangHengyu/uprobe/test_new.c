#include<stdio.h>

void odd(){
	printf("odd number!\n");
}

void even(){
	printf("even number!\n");
}

int main(){
	int i;
	scanf("%d", &i);
	if (i%2 == 0){
		even();
	} else {
		odd();
	}
	return 0;
}
