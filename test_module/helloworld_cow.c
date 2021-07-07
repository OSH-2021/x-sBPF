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

static char sdir[256]="/home/kk2048/coding/sBPF_testdir";
module_param_string(sdir,sdir,256,0);

static char static_str[5]="/";

// 初始化入口
// 模块安装时执行
// 这里的__init 同样是宏定义，主要的目的在于
// 告诉内核，加载该模块之后，可以回收init.text的区间
struct hash_list{
	struct hash_list *next;
	char* file_ori_name;
	int hash_key;
};

static struct hash_list hash_head;
static int hash_gen_key(char *str){
	int i=0;
	int ret=0;
	int M=2181271;
	int N=2908361;
	while(str[i]!=0){
		ret=ret*M+str[i]*N;
		i++;
	}
	return ret;
}
static int hash_test(char * str){
	struct hash_list *ptr=hash_head.next;
	int hash_key=hash_gen_key(str);
	while(ptr!=NULL){
		if(ptr->hash_key==hash_key){
			if(strcmp(ptr->file_ori_name,str)){
				return 1;
			}
		}
		ptr=ptr->next;
	}
	return 0;
}
static void hash_add(char * str){
	int hash_key=hash_gen_key(str);
	char * filename=(char*)kmalloc(strlen(str),GFP_KERNEL);
	strcpy(filename,str);
	struct hash_list *new_node=(struct hash_list *)kmalloc(sizeof(struct hash_list),GFP_KERNEL);
	new_node->hash_key=hash_key;
	new_node->next=hash_head.next;
	hash_head.next=new_node;
	new_node->file_ori_name=filename;
}
static int my_mkdir(const char *name, umode_t mode)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;
	retry:
	dentry = kern_path_create(AT_FDCWD, name, &path, lookup_flags);
	if (IS_ERR(dentry)) {
		return PTR_ERR(dentry);
	}
	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	error = security_path_mkdir(&path, dentry, mode);
	if (!error) {
		error = vfs_mkdir(path.dentry->d_inode, dentry, mode);
	}

	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}

	return error;
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
		if(input_str[0]=='.'){
			strcpy(absolute_str,pwd_head);
			strcat(absolute_str,input_str+1);
		}else if(input_str[0]=='/'||input_str[0]=='\\'){
			strcpy(absolute_str,input_str);
		}else{
			strcpy(absolute_str,pwd_head);
			strcat(absolute_str,static_str);
			strcat(absolute_str,input_str);
		}
		
		char targetdir[1024];
		strcpy (targetdir,sdir);
		strcat(targetdir,absolute_str);
		//if(input_str[0]=='~'){
		//	strcpy(targetdir,sdir);
		//	strcat(targetdir,homedir);
		//	strcat(targetdir,input_str+2);
			
		//}else 
		/*
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
		*/
		printk("Get sys_openat, input=:%s, output=%s\n",input_str,targetdir);
		
		int len = strlen(targetdir);
		copy_to_user((char*)u_mem, targetdir, len+1);
		
		char newpath[128];
		int i;
		for(i=1;i<strlen(targetdir);i++){
	    	if(targetdir[i]=='/'||targetdir[i]=='\\'){
	    		strcpy(newpath,targetdir);
	    		newpath[i]=0;
	    		//printk("new_dir:%s\n",newpath);
	    		my_mkdir(newpath,0777);
	    	}
	    }
    
		if(!hash_test(absolute_str)){
			printk("hash miss!!\n");
			hash_add(absolute_str);
		}else{
			printk("hash hit!!\n");
		}
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
    hash_head.next=NULL;

    return 0;
}


// 模块卸载时执行
// 同上
static void __exit sBPF_exit(void)
{
	flag_openat_sBPF = 0;
	/*
	struct hash_list *ptr1=hash_head.next;
	struct hash_list *ptr2;
	while(ptr1!=NULL){
		ptr2=ptr1->next;
		kfree(ptr1->file_ori_name);
		kfree(ptr1);
		ptr1=ptr2;
	}
	*/
    printk(KERN_ALERT" module has exitedi!\n");
}

// 模块初始化宏，用于加载该模块
module_init(sBPF_init);
// 模块卸载宏，用于卸载该模块
module_exit(sBPF_exit);
