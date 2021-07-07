#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
main()
{
	char test_space[1024];
	printf("swap_space %lu\n",(unsigned long)test_space);
    printf("这个程序的PID为: %d\n", getpid());
    getchar();   
	 
    int fd, size;
    char s[] = "Linux Programmer!\n", buffer[80];
    fd = open("./test.txt", O_WRONLY|O_CREAT);
    write(fd, s, sizeof(s)-1);
    printf("%u\n",fd);
    close(fd);
    //fd = open("~/coding/test3/test.txt", O_RDONLY);
    //size = read(fd, buffer, sizeof(buffer));
    //close(fd);
    //printf("%s", buffer);
    fd = open("/home/kk2048/coding/test_cow/test.txt", O_RDONLY);
    size = read(fd, buffer, sizeof(buffer));
    printf("%u\n",fd);
    close(fd);
    printf("%s\n", buffer);
    
    fd = open("test.txt", O_RDONLY);
    size = read(fd, buffer, sizeof(buffer));
    printf("%u\n",fd);
    close(fd);
    printf("%s\n", buffer);
}

