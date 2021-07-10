#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
    
   char test_space[1024];
   
     
    
    printf("这个程序的PID为: %d\n", getpid());
    getchar();  
    
    int start=clock();
    
    char buffer[1024];
    FILE * fp;
    
    for(int i=0;i<=10000;i++){
	    fp = fopen ("file.txt", "w");
	    fprintf(fp, "%s\n", "test_message_11111");
	    fclose(fp);
	    
	    fp = fopen ("file.txt", "r");
	    fscanf(fp,"%s",buffer);
	    
	    fclose(fp);
    }
    printf("time:%d\n",clock()-start);
    
    return 0;
}

