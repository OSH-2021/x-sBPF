// 必备头函数
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/fs_struct.h>
// 该模块的LICENSE
MODULE_LICENSE("GPL");
// 该模块的作者
MODULE_AUTHOR("sBPF");
// 该模块的说明
MODULE_DESCRIPTION("sBPF file space sandbox/n");

// 该模块需要传递的参数
static int pid = 0;
module_param(pid, int, 0644);

static unsigned long u_mem = 140728901785488;
module_param(u_mem, ulong, 0644);

static char sdir[256]="/home/kk2048/coding/sBPF_testdir";
module_param_string(sdir,sdir,256,0);


static char homedir[256]="/home/kk2048";
module_param_string(homedir,homedir,256,0);

static char static_str[5]="/";

// 初始化入口
// 模块安装时执行
// 这里的__init 同样是宏定义，主要的目的在于
// 告诉内核，加载该模块之后，可以回收init.text的区间

static int count = 10;   

static const char* sBPF_sandbox_process(const char* filename){
	
	if (pid == current->pid) {
		char pwd_str[256];
		struct path pwd;
		get_fs_pwd(current->fs,&pwd);
		char * pwd_head= dentry_path_raw(pwd.dentry,pwd_str,256);
		
		
		char input_str[256];
		copy_from_user(input_str,filename,255);
		input_str[255]=0;
		
		char targetdir[1024];
		//if(input_str[0]=='~'){
		//	strcpy(targetdir,sdir);
		//	strcat(targetdir,homedir);
		//	strcat(targetdir,input_str+2);
			
		//}else 
		if(input_str[0]=='.'){
			strcpy(targetdir,sdir);
			strcat(targetdir,pwd_head);
			strcat(targetdir,input_str+1);
		}else if(input_str[0]=='/'||input_str[0]=='\\'){
			strcpy(targetdir,sdir);
			strcat(targetdir,input_str);
		}else{
			strcpy(targetdir,sdir);
			strcat(targetdir,pwd_head);
			strcat(targetdir,static_str);
			strcat(targetdir,input_str);
		}
	
		printk("Get sys_openat, input=:%s, output=%s\n",input_str,targetdir);
		
		int len = strlen(targetdir);
		copy_to_user((char*)u_mem, targetdir, len+1);
		
		return (char*)u_mem;
	}
	return filename;
}


static int __init sBPF_init(void)
{
    
    printk(KERN_ALERT" module init!\n");
    
    print_flag = 0;
    sBPF_hook_openat_prog = sBPF_sandbox_process;
    flag_openat_sBPF = 1;

    return 0;
}


// 模块卸载时执行
// 同上
static void __exit sBPF_exit(void)
{
	flag_openat_sBPF = 0;
	
    	printk(KERN_ALERT" module has exitedi!\n");
}

// 模块初始化宏，用于加载该模块
module_init(sBPF_init);
// 模块卸载宏，用于卸载该模块
module_exit(sBPF_exit);
