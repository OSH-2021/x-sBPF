#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
main()
{
    printf("这个程序的PID为: %d\n", getpid());
    getchar();        
    int fd, size;
    char s[] = "Linux Programmer!\n", buffer[80];
    fd = open("/home/kk2048/coding/test3/test.txt", O_WRONLY|O_CREAT);
    write(fd, s, sizeof(s));
    close(fd);
    fd = open("/home/kk2048/coding/test3/test.txt", O_RDONLY);
    size = read(fd, buffer, sizeof(buffer));
    close(fd);
    printf("%s", buffer);
}
