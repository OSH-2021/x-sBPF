# Linux Syscall
有关Linux所有的syscall可查看<https://syscalls64.paolostivanin.com>
在该网页上可以看到现在有358种syscall（编号为0~368，部分编号无对应syscall）。
## 例子——不使用printf的hello world
实际上，直接使用系统调用并不困难，以下是一个例子：
```C
#include<unistd.h>

int main(){
	char str[] = "hello world!\n";
	write(1, str, sizeof(str));
	return 0;
}
```
在Linux下编译运行后可看到：
```text
$ gcc test.c
$ ./a.out
hello world!
```
可以进一步查看系统调用：
```text
$ strace ./a.out
execve("./a.out", ["./a.out"], 0xffffd41190e0 /* 50 vars */) = 0
brk(NULL)                               = 0xaaaaf496e000
faccessat(AT_FDCWD, "/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=70955, ...}) = 0
mmap(NULL, 70955, PROT_READ, MAP_PRIVATE, 3, 0) = 0xffffa2fd6000
close(3)                                = 0
openat(AT_FDCWD, "/lib/aarch64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0\267\0\1\0\0\0`B\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=1450008, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xffffa3015000
mmap(NULL, 1518680, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xffffa2e63000
mprotect(0xffffa2fbe000, 61440, PROT_NONE) = 0
mmap(0xffffa2fcd000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x15a000) = 0xffffa2fcd000
mmap(0xffffa2fd3000, 11352, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xffffa2fd3000
close(3)                                = 0
mprotect(0xffffa2fcd000, 12288, PROT_READ) = 0
mprotect(0xaaaac156a000, 4096, PROT_READ) = 0
mprotect(0xffffa3019000, 4096, PROT_READ) = 0
munmap(0xffffa2fd6000, 70955)           = 0
write(1, "hello world!\n\0", 14hello world!
)        = 14
exit_group(0)                           = ?
+++ exited with 0 +++
```
大部分输出都不重要，最重要的是最后出现了`write`（strace的输出和程序的输出是重叠的，所以`write`那里换了一行）。可以说明用此方法能够直接进行系统调用，而不是使用`printf`来间接进行系统调用。
## BPF
详细的`BPF`文档位于linux源码`Documentation/networking/filter.txt`中。
一些相关`BPF`代码样例位于linux源码`samples/bpf`中。
### 系统调用
可以在该网页上看到，bpf也是一种系统调用（编号为321）。这里可以看到bpf的[使用手册](https://man7.org/linux/man-pages/man2/bpf.2.html)。（也可以在Linux环境下的shell中使用`man bpf`查看）

如果跟踪执行我们先前写的`Hello world!`BPF程序：
```bash
$ sudo strace ./monitor-exec
```
可以看到如下结果（有省略）：
```bash
execve("./monitor-exec", ["./monitor-exec"], 0xffffd38a88e0 /* 16 vars */) = 0
brk(NULL)                               = 0x2be02000
faccessat(AT_FDCWD, "/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=70955, ...}) = 0
mmap(NULL, 70955, PROT_READ, MAP_PRIVATE, 3, 0) = 0xffff829d2000
close(3)                                = 0
openat(AT_FDCWD, "/lib/aarch64-linux-gnu/libelf.so.1", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0\267\0\1\0\0\0\240.\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0644, st_size=117176, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xffff82a11000
mmap(NULL, 180616, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xffff829a5000
mprotect(0xffff829c0000, 65536, PROT_NONE) = 0
mmap(0xffff829d0000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1b000) = 0xffff829d0000
close(3)                                = 0
openat(AT_FDCWD, "/lib/aarch64-linux-gnu/libbpf.so", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0\267\0\1\0\0\0@#\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=91168, ...}) = 0
mmap(NULL, 111184, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xffff82989000
mprotect(0xffff82994000, 61440, PROT_NONE) = 0
mmap(0xffff829a3000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0xa000) = 0xffff829a3000
close(3)                                = 0
openat(AT_FDCWD, "/lib/aarch64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0\267\0\1\0\0\0`B\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=1450008, ...}) = 0
mmap(NULL, 1518680, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xffff82816000
mprotect(0xffff82971000, 61440, PROT_NONE) = 0
mmap(0xffff82980000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x15a000) = 0xffff82980000
mmap(0xffff82986000, 11352, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xffff82986000
close(3)                                = 0
openat(AT_FDCWD, "/lib/aarch64-linux-gnu/libz.so.1", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0\267\0\1\0\0\0` \0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0644, st_size=104608, ...}) = 0
mmap(NULL, 168112, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xffff827ec000
mprotect(0xffff82805000, 61440, PROT_NONE) = 0
mmap(0xffff82814000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18000) = 0xffff82814000
close(3)                                = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xffff82a0f000
mprotect(0xffff82980000, 12288, PROT_READ) = 0
mprotect(0xffff82814000, 4096, PROT_READ) = 0
mprotect(0xffff829a3000, 4096, PROT_READ) = 0
mprotect(0xffff829d0000, 4096, PROT_READ) = 0
mprotect(0x414000, 4096, PROT_READ)     = 0
mprotect(0xffff82a15000, 4096, PROT_READ) = 0
munmap(0xffff829d2000, 70955)           = 0
openat(AT_FDCWD, "bpf_program.o", O_RDONLY) = 3
fcntl(3, F_GETFD)                       = 0
fstat(3, {st_mode=S_IFREG|0664, st_size=928, ...}) = 0
pread64(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\1\0\367\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 64, 0) = 64
brk(NULL)                               = 0x2be02000
brk(0x2be23000)                         = 0x2be23000
rt_sigaction(SIGINT, {sa_handler=SIG_IGN, sa_mask=[], sa_flags=0}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGQUIT, {sa_handler=SIG_IGN, sa_mask=[], sa_flags=0}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0
mmap(NULL, 36864, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0) = 0xffff82a06000
rt_sigprocmask(SIG_BLOCK, ~[], [CHLD], 8) = 0
clone(child_stack=0xffff82a0f000, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 63269
munmap(0xffff82a06000, 36864)           = 0
rt_sigprocmask(SIG_SETMASK, [CHLD], NULL, 8) = 0
wait4(63269, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 63269
rt_sigaction(SIGINT, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, NULL, 8) = 0
rt_sigaction(SIGQUIT, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, NULL, 8) = 0
rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=63269, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 512, 416) = 512
pread64(3, "\0.text\0bpf_prog\0.llvm_addrsig\0tr"..., 121, 290) = 121
pread64(3, "\267\1\0\0!\0\0\0k\32\374\377\0\0\0\0\267\1\0\0orldc\32\370\377\0\0\0\0"..., 104, 64) = 104
pread64(3, "Hello, World!\0", 14, 168)  = 14
pread64(3, "GPL\0", 4, 182)             = 4
pread64(3, "\3\2", 2, 288)              = 2
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0L\0\0\0\4\0\361\377"..., 96, 192) = 96
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_TRACEPOINT, insn_cnt=13, insns=0x2be02cd0, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(0, 0, 0), prog_flags=0, prog_name="", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS}, 72) = 4
openat(AT_FDCWD, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/id", O_RDONLY) = 5
read(5, "599\n", 256)                   = 4
close(5)                                = 0
perf_event_open({type=PERF_TYPE_TRACEPOINT, size=0 /* PERF_ATTR_SIZE_??? */, config=599, ...}, -1, 0, -1, 0) = 5
ioctl(5, PERF_EVENT_IOC_ENABLE, 0)      = 0
ioctl(5, PERF_EVENT_IOC_SET_BPF, 4)     = 0
close(3)                                = 0
...
```
在最后几行可以明显看到，该程序执行了bpf系统调用。
### 头文件
#### `bpf`系统调用的定义
```C
#include <linux/bpf.h>
int bpf(int cmd, union bpf_attr *attr, unsigned int size);
```
#### `cmd`
```C
enum bpf_cmd {
	BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD,
	BPF_OBJ_PIN,
	BPF_OBJ_GET,
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD,
	BPF_BTF_GET_FD_BY_ID,
	BPF_TASK_FD_QUERY,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM,
	BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID,
};
```
#### `bpf_attr`
```C
union bpf_attr {
	struct { /* anonymous struct used by BPF_MAP_CREATE command */
		__u32	map_type;	/* one of enum bpf_map_type */
		__u32	key_size;	/* size of key in bytes */
		__u32	value_size;	/* size of value in bytes */
		__u32	max_entries;	/* max number of entries in a map */
		__u32	map_flags;	/* BPF_MAP_CREATE related
					 * flags defined above.
					 */
		__u32	inner_map_fd;	/* fd pointing to the inner map */
		__u32	numa_node;	/* numa node (effective only if
					 * BPF_F_NUMA_NODE is set).
					 */
		char	map_name[BPF_OBJ_NAME_LEN];
		__u32	map_ifindex;	/* ifindex of netdev to create on */
		__u32	btf_fd;		/* fd pointing to a BTF type data */
		__u32	btf_key_type_id;	/* BTF type_id of the key */
		__u32	btf_value_type_id;	/* BTF type_id of the value */
	};

	struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
		__u32		map_fd;
		__aligned_u64	key;
		union {
			__aligned_u64 value;
			__aligned_u64 next_key;
		};
		__u64		flags;
	};

	struct { /* anonymous struct used by BPF_PROG_LOAD command */
		__u32		prog_type;	/* one of enum bpf_prog_type */
		__u32		insn_cnt;
		__aligned_u64	insns;
		__aligned_u64	license;
		__u32		log_level;	/* verbosity level of verifier */
		__u32		log_size;	/* size of user buffer */
		__aligned_u64	log_buf;	/* user supplied buffer */
		__u32		kern_version;	/* not used */
		__u32		prog_flags;
		char		prog_name[BPF_OBJ_NAME_LEN];
		__u32		prog_ifindex;	/* ifindex of netdev to prep for */
		/* For some prog types expected attach type must be known at
		 * load time to verify attach type specific parts of prog
		 * (context accesses, allowed helpers, etc).
		 */
		__u32		expected_attach_type;
		__u32		prog_btf_fd;	/* fd pointing to BTF type data */
		__u32		func_info_rec_size;	/* userspace bpf_func_info size */
		__aligned_u64	func_info;	/* func info */
		__u32		func_info_cnt;	/* number of bpf_func_info records */
		__u32		line_info_rec_size;	/* userspace bpf_line_info size */
		__aligned_u64	line_info;	/* line info */
		__u32		line_info_cnt;	/* number of bpf_line_info records */
	};

	struct { /* anonymous struct used by BPF_OBJ_* commands */
		__aligned_u64	pathname;
		__u32		bpf_fd;
		__u32		file_flags;
	};

	struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
		__u32		target_fd;	/* container object to attach to */
		__u32		attach_bpf_fd;	/* eBPF program to attach */
		__u32		attach_type;
		__u32		attach_flags;
	};

	struct { /* anonymous struct used by BPF_PROG_TEST_RUN command */
		__u32		prog_fd;
		__u32		retval;
		__u32		data_size_in;	/* input: len of data_in */
		__u32		data_size_out;	/* input/output: len of data_out
						 *   returns ENOSPC if data_out
						 *   is too small.
						 */
		__aligned_u64	data_in;
		__aligned_u64	data_out;
		__u32		repeat;
		__u32		duration;
		__u32		ctx_size_in;	/* input: len of ctx_in */
		__u32		ctx_size_out;	/* input/output: len of ctx_out
						 *   returns ENOSPC if ctx_out
						 *   is too small.
						 */
		__aligned_u64	ctx_in;
		__aligned_u64	ctx_out;
	} test;

	struct { /* anonymous struct used by BPF_*_GET_*_ID */
		union {
			__u32		start_id;
			__u32		prog_id;
			__u32		map_id;
			__u32		btf_id;
		};
		__u32		next_id;
		__u32		open_flags;
	};

	struct { /* anonymous struct used by BPF_OBJ_GET_INFO_BY_FD */
		__u32		bpf_fd;
		__u32		info_len;
		__aligned_u64	info;
	} info;

	struct { /* anonymous struct used by BPF_PROG_QUERY command */
		__u32		target_fd;	/* container object to query */
		__u32		attach_type;
		__u32		query_flags;
		__u32		attach_flags;
		__aligned_u64	prog_ids;
		__u32		prog_cnt;
	} query;

	struct {
		__u64 name;
		__u32 prog_fd;
	} raw_tracepoint;

	struct { /* anonymous struct for BPF_BTF_LOAD */
		__aligned_u64	btf;
		__aligned_u64	btf_log_buf;
		__u32		btf_size;
		__u32		btf_log_size;
		__u32		btf_log_level;
	};

	struct {
		__u32		pid;		/* input: pid */
		__u32		fd;		/* input: fd */
		__u32		flags;		/* input: flags */
		__u32		buf_len;	/* input/output: buf len */
		__aligned_u64	buf;		/* input/output:
						 *   tp_name for tracepoint
						 *   symbol for kprobe
						 *   filename for uprobe
						 */
		__u32		prog_id;	/* output: prod_id */
		__u32		fd_type;	/* output: BPF_FD_TYPE_* */
		__u64		probe_offset;	/* output: probe_offset */
		__u64		probe_addr;	/* output: probe_addr */
	} task_fd_query;
} __attribute__((aligned(8)));
```
**可以看出不同`cmd`要传入的`attr`类型是不一样的。**
加载程序需要关注这一段：
```C
struct { /* anonymous struct used by BPF_PROG_LOAD command */
	__u32		prog_type;	/* one of enum bpf_prog_type */
	__u32		insn_cnt;
	__aligned_u64	insns;
	__aligned_u64	license;
	__u32		log_level;	/* verbosity level of verifier */
	__u32		log_size;	/* size of user buffer */
	__aligned_u64	log_buf;	/* user supplied buffer */
	__u32		kern_version;	/* not used */
	__u32		prog_flags;
	char		prog_name[BPF_OBJ_NAME_LEN];
	__u32		prog_ifindex;	/* ifindex of netdev to prep for */
	/* For some prog types expected attach type must be known at
	 * load time to verify attach type specific parts of prog
	 * (context accesses, allowed helpers, etc).
	 */
	__u32		expected_attach_type;
	__u32		prog_btf_fd;	/* fd pointing to BTF type data */
	__u32		func_info_rec_size;	/* userspace bpf_func_info size */
	__aligned_u64	func_info;	/* func info */
	__u32		func_info_cnt;	/* number of bpf_func_info records */
	__u32		line_info_rec_size;	/* userspace bpf_line_info size */
	__aligned_u64	line_info;	/* line info */
	__u32		line_info_cnt;	/* number of bpf_line_info records */
};
```
其中`prog_name`部分稍显不同，其他的字符串都是指针，这里是一个**数组**。数组长度在代码中定义为：
```C
#define BPF_OBJ_NAME_LEN 16U
```
在`manual`部分，可以看到`bpf_attr`如下的定义：
```C
union bpf_attr {
    struct {    /* Used by BPF_MAP_CREATE */
       __u32         map_type;
       __u32         key_size;    /* size of key in bytes */
       __u32         value_size;  /* size of value in bytes */
       __u32         max_entries; /* maximum number of entries
                                     in a map */
   };

   struct {    /* Used by BPF_MAP_*_ELEM and BPF_MAP_GET_NEXT_KEY
                  commands */
       __u32         map_fd;
       __aligned_u64 key;
       union {
           __aligned_u64 value;
           __aligned_u64 next_key;
       };
       __u64         flags;
   };

   struct {    /* Used by BPF_PROG_LOAD */
       __u32         prog_type;
       __u32         insn_cnt;
       __aligned_u64 insns;      /* 'const struct bpf_insn *' */
       __aligned_u64 license;    /* 'const char *' */
       __u32         log_level;  /* verbosity level of verifier */
       __u32         log_size;   /* size of user buffer */
       __aligned_u64 log_buf;    /* user supplied 'char *'
                                    buffer */
       __u32         kern_version;
                                 /* checked when prog_type=kprobe
                                    (since Linux 4.1) */
   };
} __attribute__((aligned(8)));
```
`manual`里面对`BPF_PROG_LOAD`的`struct`定义相比头文件里面的少了一部分东西。
该段可以与先前`strace`中的系统调用结合起来看：
```bash
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_TRACEPOINT, insn_cnt=13, insns=0x2be02cd0, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(0, 0, 0), prog_flags=0, prog_name="", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS}, 72) = 4
```
这一段基本是与头文件里面的定义相吻合的，但还是缺少了一部分东西。
#### `size`
`manual`中对`size`的说明：
The size argument is the `size` of the union pointed to by `attr`.
## seccomp
`seccomp`实际上也属于一种系统调用，编号为317。
### 注意⚠️
设置`seccomp`不是只能使用`seccomp`系统调用才行，也可以使用`prctl`系统调用。
```C
#include <sys/prctl.h>
int prctl(int option, unsigned long arg2, unsigned long arg3,
         unsigned long arg4, unsigned long arg5);
```
例如，先前使用的`seccomp`程序使用了如下系统调用来设置`seccomp`程序（`strace`跟踪结果）：
```bash
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=6, filter=0xffffc6b535a0}) = 0
```