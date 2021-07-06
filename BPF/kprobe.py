from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
	char buf[256]; // PATHLEN is defined to 256
	int res = bpf_probe_read_user_str(buf, sizeof(buf), filename);
	bpf_trace_printk("dir: %s\\n", buf);
	return 0;
}
"""

bpf = BPF(text=bpf_source)
execve_function = bpf.get_syscall_fnname("openat")
bpf.attach_kprobe(event=execve_function, fn_name="syscall__openat")
bpf.trace_print()
