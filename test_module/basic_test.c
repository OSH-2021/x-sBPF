#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
    
    char buffer[1024];
    FILE * fp;
    
    fp = fopen ("./../file.txt", "w");
    if (fp != NULL) {
    	fprintf(fp, "%s\n", "test_message_11111");
    } else {
    	printf("1: NULL!\n");
    }
    
    fclose(fp);
    
    fp = fopen ("./../file.txt", "r");
    if (fp != NULL) {
    	fscanf(fp,"%s",buffer);
    	printf("%s\n",buffer);
    } else {
    	printf("2: NULL!\n");
    }
    
    
    fclose(fp);
    
    fp = fopen ("./../file.txt", "w");
    if (fp != NULL) {
    	fprintf(fp, "%s\n", "test_message_222222");
    } else {
    	printf("3: NULL!\n");
    }
    
    fclose(fp);
    
    fp = fopen ("./../file.txt", "r");
    if (fp != NULL) {
    	fscanf(fp,"%s",buffer);
    	printf("%s\n",buffer);
    } else {
    	printf("4: NULL!\n");
    }
    
    fclose(fp);
    
    return 0;
}

