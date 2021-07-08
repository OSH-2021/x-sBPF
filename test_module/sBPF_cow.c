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
			if(strcmp(ptr->file_ori_name,str)==0){
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



static void get_abs_path(char* abs_str,char* input_str){
    
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
		
		
		if((flag & O_RDWR) || (flag & O_WRONLY)){
			if(!hash_test(absolute_str)){
				printk("hash miss!!\n");
				hash_add(absolute_str);
				
				//do COW
				char targetdir[1024];
				strcpy (targetdir,sdir);
				strcat(targetdir,absolute_str);
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
				struct file * fptr1=filp_open(input_str,O_RDONLY,0777);
				struct file * fptr2=filp_open(targetdir,O_RDWR|O_CREAT,0777);
				if(IS_ERR(fptr1)){
					printk("openat: file not exist!");
					printk("fptr1 err: %ld\n", PTR_ERR(fptr1));
				}else{
					vfs_copy_file_range(fptr1,0,fptr2,0,1024,0);
				}
				if(IS_ERR(fptr2)){
					printk("fptr2 err: %ld\n", PTR_ERR(fptr2));
				}
				
				if (!IS_ERR(fptr1)) {
					i = filp_close(fptr1, NULL);
					if (i != 0) {
						printk("fptr1 close err: %d\n", i);
					}
				}
				
				if (!IS_ERR(fptr2)) {
					i = filp_close(fptr2, NULL);
					if (i != 0) {
						printk("fptr2 close err: %d\n", i);
					}
				}
			}else{
				printk("hash hit!!\n");
			}
			char targetdir[1024];
			strcpy (targetdir,sdir);
			strcat(targetdir,absolute_str);
			printk("Get sys_openat, input=:%s, output=%s\n",input_str,targetdir);
			
			int len = strlen(targetdir);
			copy_to_user((char*)u_mem, targetdir, len+1);
			return (char*)u_mem;
		}else{
			if(hash_test(absolute_str)){//hit and sandbox
				char targetdir[1024];
				strcpy (targetdir,sdir);
				strcat(targetdir,absolute_str);
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
			
				
				return (char*)u_mem;
			}
			else{//miss and not sandbox
				return filename;
			}
		}
		
	}
	return filename;
}


static int __init sBPF_init(void)
{
    
    printk(KERN_ALERT" module init!\n");
    
    hash_head.next=NULL;
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
