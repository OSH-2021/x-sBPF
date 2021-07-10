#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//  argv[1] path2kmod.ko    argv[2] sandbox_path    argv[3] path2program
int main(int argc, char *argv[]){
    pid_t pid1 = fork();
    //child process to sandboxed_program
    if(pid1 == 0){
        kill(getpid(), SIGSTOP);        //blocking 
        
        execvp(argv[3], argv + 3);
    }
    

    //insmod
        //pid
    char arg_pid[20];
    sprintf(arg_pid, "pid=%d", pid1);
        //u_mem
    char arg_u_mem[50];
    char test_space[1024];
    sprintf(arg_u_mem, "u_mem=%lu", (unsigned long)test_space);
        //sdir
    char arg_sdir[50];
    sprintf(arg_sdir, "sdir=%s", argv[2]);
        //insmod
    pid_t pid2 = fork();
    if(pid2 == 0){
        execl("/usr/bin/sudo", "sudo", "insmod", argv[1], arg_pid, arg_u_mem, arg_sdir, NULL);
    }
    waitpid(pid2, NULL, 0);
    
    kill(pid1, SIGCONT);        //restarting pid1

    waitpid(pid1, NULL, 0);


    //rmmod
    argv[1][strlen(argv[1])-3] = '\0';
    execl("/usr/bin/sudo", "sudo", "rmmod", argv[1], NULL);

    return 0;
}
