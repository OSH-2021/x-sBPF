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

//extern int flag_openat_sBPF;
//extern static const char* (*sBPF_hook_openat_prog) (const char* filename);

// 初始化入口
// 模块安装时执行
// 这里的__init 同样是宏定义，主要的目的在于
// 告诉内核，加载该模块之后，可以回收init.text的区间

static int count = 10;

static u64 print_flag = 18446744071867247648;
static u64 openat_sBPF = 18446744071867247664;
static u64 openat_prog = 18446744071867247656;
    

static const char* sBPF_sandbox_process(const char* filename){
	char kstr[256];
	char pwd_str[256];
	struct path pwd;
	get_fs_pwd(current->fs,&pwd);
	char * pwd_head= dentry_path_raw(pwd.dentry,pwd_str,256);
	
	
	copy_from_user(kstr,filename,255);
	kstr[255]=0;
	if (count > 0) {
		printk("Get sys_openat, pwd=: %s, dir=%s\n",pwd_head,kstr);
		count--;
	}
	return filename;
}


static int __init sBPF_init(void)
{
    
    printk(KERN_ALERT" module init!\n");
    printk("test fs flag: %d\n",flag_openat_sBPF);
    
    sBPF_hook_openat_prog=sBPF_sandbox_process;
    
    flag_openat_sBPF=1;
    
    printk("test fs flag: %d\n",flag_openat_sBPF);
    
    
    int *flag = (int *)print_flag;
    
    *flag = 0;
    
    
    int *flag_openat_sBPF_ptr = (int *)openat_sBPF;
    const char* (**sBPF_hook_openat_prog)(const char * filename) = (void *)openat_prog;
    
    *sBPF_hook_openat_prog = sBPF_sandbox_process;
    *flag_openat_sBPF_ptr = 1;
    
    return 0;
}


// 模块卸载时执行
// 同上
static void __exit sBPF_exit(void)
{
	//u64 openat_sBPF = 18446603336521911768;
	int *flag_openat_sBPF_ptr = (int *)openat_sBPF;
	*flag_openat_sBPF_ptr = 0;
	
    	//flag_openat_sBPF=0;
    	printk(KERN_ALERT" module has exitedi!\n");
}

// 模块初始化宏，用于加载该模块
module_init(sBPF_init);
// 模块卸载宏，用于卸载该模块
module_exit(sBPF_exit);
