#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
    
   char test_space[1024];
   
     
    
    char buffer[1024];
    FILE * fp;

    
    
    printf("swap_space %lu\n",(unsigned long)test_space);
    printf("这个程序的PID为: %d\n", getpid());
    getchar();  
    
    fp = fopen ("./../file.txt", "w");
    if(!fp){
	return 0;
    }
    fprintf(fp, "%s\n", "test_message_11111");
    fclose(fp);
    
    fp = fopen ("./../../file.txt", "w");
    if(!fp){
	return 0;
    }
    fprintf(fp, "%s\n", "test_message_11111");
    fclose(fp);
    
    fp = fopen ("./../../../file.txt", "w");
    if(!fp){
	return 0;
    }
    fprintf(fp, "%s\n", "test_message_11111");
    fclose(fp);
    
    fp = fopen ("./../../../../file.txt", "w");
    if(!fp){
	return 0;
    }
    fprintf(fp, "%s\n", "test_message_11111");
    fclose(fp);
    
    return 0;
}

