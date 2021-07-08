// 必备头函数
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/fs_struct.h>

#include <linux/security.h>
#include <linux/namei.h>
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

static char pdir[256]="/home/kk2048/coding/";
module_param_string(pdir,pdir,256,0);

static char trashdir[]="/tmp/trash";

static char static_str[5]="/";

// 初始化入口
// 模块安装时执行
// 这里的__init 同样是宏定义，主要的目的在于
// 告诉内核，加载该模块之后，可以回收init.text的区间

static get_abs_path(char* abs_str,char* input_str){
    
    char pwd_str[256];
	struct path pwd;
	get_fs_pwd(current->fs,&pwd);
	char * pwd_head= dentry_path_raw(pwd.dentry,pwd_str,256);
	
	//this is a note heiheihei
	
	int i;
	if(input_str[0]=='.'){
		strcpy(abs_str,pwd_head);
		strcat(abs_str,"/");
		i=2;
	}else if(input_str[0]=='/'||input_str[0]=='\\'){
		strcpy(abs_str,"/");
		i=1;
	}else{
		strcpy(abs_str,pwd_head);
		strcat(abs_str,"/");
		i=0;
	}
	int size=strlen(input_str);
	int j=strlen(abs_str)-1;
	while(i<size){
	    if(input_str[i]=='.'){// go back folder
	        j--;
	        while(j>=0&&abs_str[j]!='/'&&abs_str[j]!='\\'){
	            j--;
	        }
	        if(j<0){
                j=0;
                abs_str[1]=0;
            }else{
                abs_str[j+1]=0;
            }
            i+=3;
	    }else{
	        
            while(input_str[i]!='\\'&&input_str[i]!='/'&&input_str[i]!=0){
                j++;
                abs_str[j]=input_str[i];
                i++;
            }
            
            j++;
            abs_str[j]=input_str[i];
            i++;
        }
	}
}

static const char* sBPF_sandbox_process(const char* filename,int flag){
	
	if (pid == current->pid) {
		char pwd_str[256];
		struct path pwd;
		get_fs_pwd(current->fs,&pwd);
		char * pwd_head= dentry_path_raw(pwd.dentry,pwd_str,256);
		
		
		char input_str[256];
		copy_from_user(input_str,filename,255);
		input_str[255]=0;
		
		
		char absolute_str[256];
		get_abs_path(absolute_str,input_str);
		printk("ori=:%s new=:%s\n",input_str,absolute_str);
		
		
		int flag=0;//0=match
		if(strlen(pdir)>strlen(absolute_str)){
			flag=1;
		}else{
			int i;
			int size=strlen(pdir);
			for(i=0;i<size;i++){
				if(pdir[i]!=absolute_str[i]){
					flag=1;
				}
			}
		}
		if(flag==0){	
			printk("sBPF msg: permission proved, ret dir %s\n",input_str);
			
			return filename;
		}
		else { //not match
			printk("sBPF msg: permission denied, ret dir %s\n",trashdir);
			
			int len = strlen(trashdir);
			copy_to_user((char*)u_mem, trashdir, len+1);
			return (char*)u_mem;
			
		}
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
