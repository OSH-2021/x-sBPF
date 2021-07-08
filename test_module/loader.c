#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>

//argv[1] path2program  argv[2] path2kmod.ko    argv[3] sandbox_path
int main(int argc, char *argv[]){
    pid_t pid = fork();
    //child process to sandboxed_program
    if(pid == 0){
        //blocking  
        puts("press enter to start running:");
        getchar();  

        execl(argv[1], argv[1], NULL);
    }
    

    //insmod
        //pid
    char arg_pid[20];
    sprintf(arg_pid, "pid=%d", pid);
        //u_mem
    char arg_u_mem[50];
    char test_space[1024];
    sprintf(arg_u_mem, "u_mem=%lu", (unsigned long)test_space);
        //sdir
    char arg_sdir[50];
    sprintf(arg_sdir, "sdir=%s", argv[3]);
        //insmod
    if(fork()==0){
        execl("/sbin/insmod", "insmod", argv[2], arg_pid, arg_u_mem, arg_sdir, NULL);
    }

    waitpid(pid, NULL, 0);

    //rmmod
    argv[2][strlen(argv[2])-3] = '\0';
    execl("/sbin/rmmod", "rmmod", argv[2], NULL);

    //cgroup

}