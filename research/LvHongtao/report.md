# 调研记录 吕泓涛  
## 4月7日调研记录    

- [BPF和sandbox结合的现有解决方案](https://wiki.mozilla.org/Security/Sandbox/Seccomp#:~:text=Seccomp-BPF%20is%20a%20more%20recent%20extension%20to%20seccomp%2C,%28numeric%20values%20only%3B%20pointer%20arguments%20can%27t%20be%20dereferenced%29)
名为seccomp-bpf，利用了BPF程序来描述了sandbox的安全策略（主要是描述了允许程序执行哪些syscall），用BPF来kill不安全的进程或者收集此进程的活动记录，已经包含在linux内核中  


- 主流沙盒的实现方式如下（来自rVisor的结题报告）  
  - 虚拟机： 优点在于不用对软件硬件做改动，缺点在于性能较低维护较困难  
  - unikernel： 给应用带上自己的核，减小开销并且难以被攻击，缺点在于需要单独设计应用  
  - MicroVM: 把另一个剪裁过的内核暴露给应用程序，安全高效且兼容性强  
  - 进程虚拟化： 使用虚拟化的linux运行环境（这里详细概念还没懂）  保证安全且高效（gviser的实现方法）  


- [虚拟化技术的主要实现方式](https://zhuanlan.zhihu.com/p/69629212)  
    - 完全虚拟化的主要思想：虚拟机筛选guestOS试图运行的指令，普通指令允许他直接在CPU上运行，危险指令（如读写时钟或中断寄存器）被虚拟机管理器截获并且通过模拟的方式返回给gusetOS  
    - hypervisor模型：主机运行的OS直接负责执行虚拟化，VMM同时负责管理虚拟机和管理系统硬件  
    - host OS模型： VMM作为通用OS的一个模块被加载,VMM通过请求系统调用来满足虚拟机的请求，VMM在OS来看类似于一个进程。随着linux的虚拟化功能越来越多，他正在从Host模型发展为Hypervisor模型  
    - 混合模型： VMM作为最底层调度硬件，但是额外运行了一个虚拟的操作系统用来做为IO的适配软件，优点在于减轻了VMM的开发难度，缺点在于guestOS的请求需要多次转发才能得到满足  


- 计算引擎的概念如下  
  - [优秀的专栏](http://www.itbear.com.cn/html/2021-03/401258.html)
  - 类似于游戏引擎，计算引擎将复杂的底层代码完备的实现好，让开发者可以专注于实际的计算部分。以热门大数据计算引擎Flink为例，Flink将数据输入系统 数据处理系统 数据输出系统，分别抽象出来提供了完备的框架，开发者只需要给框架附加上最重要的核心计算代码，就可以简单的实现一个高效的数据处理系统，并且可以简单的部署到各种计算集群上。  
  - 计算引擎的核心发展在于分布式技术和基于数据流的实时化，值得参考的主流框架是Spark，Flink和Ray


- 杂项（主要是关于rVisor组报告的一些想法）  
   - rVisor组使用了名为zCore的轻量化Rust语言linux内核并且在其上进行构造，可以参考  
   - rVisor组的报告中完全没有涉及到重要的安全性问题，只做了IO读写和建立文件目录的压力测试，这个地方其实是存在漏洞的，只要沙盒的监管足够弱，想要实现类似于原生的性能其实应该很容易，只有这个测试完全不能说明他们的成果  
   - rVisor组的报告中提到了使用Rust no_std的一些功能来规避了有风险的linux系统调用  

- 点子记录  
   - eBPF构成的沙盒也许没有升级的必要，但是如果是ebpf构成的容器管理程序就会对热升级有需求，比如一个云计算平台在升级部分代码的时候肯定不希望其中的容器里面的进程重启，这个可以是核心卖点
   - eBPF构成的沙盒也许可以和rviser组一样实现类似于原生的性能，但是这个要我们仔细的分析沙盒的详细实现，也许需要读一下rviser组的代码

## 4月8日调研记录
- 读了有关MBOX的一篇paper [论文链接](https://www.usenix.org/system/files/conference/atc13/atc13-kim.pdf)
此论文中详细介绍了此沙盒面对的使用场景与其解决方案，此沙盒使用了上文提到的seccomp-bpf作为工具增强其安全性。  
MBOX是一个为非root用户提供的沙盒环境，主要面对filesystem进行保护

  - 面对的使用场景如下
    1. 为非管理员用户构造虚拟的root权限，vlab提供的fakeroot即为此类应用。
    2. 安全的运行不可信的二进制文件
    3. 为文件系统提供检查点（check point)。当用户需要处理危险的文件的时候，传统上一旦文件出现错误就需要使用专用工具修复文件系统。使用MBOX则可以在开始处理前把运行环境转移到虚拟的文件系统中，这样在发生错误后可以提取sandbox中剩余的错误信息，并且可以正常的时候原理的文件系统，如果运行成功了也可以直接把sandbox的系统与原文件系统合并(听起来很像git)。
    4. 使用MBOX，用户可以简单的构建开发环境。
    5. 细化权限管理：通用os如linux中用户建立的进程有权限访问用户的所有个人文件，使用MBOX可以使用户进程只能访问有必要的文件，保护了用户的其他文件。

  - 其大致上的实现原理如下  
    1. 给文件系统增加了一个private layer，位于原生文件系统的上层，每个sandbox会对应生成一个MBOX文件系统，用于服务沙盒中的进程。此文件系统的储存结构从原生文件系统的角度来看只是普通的目录，但是沙盒中的程序必须通过MBOX获得服务。
    2. 虚拟文件系统中的文件变动不会实时更新到host文件系统，但是host文件系统中的变动可以反映在虚拟文件系统中，当两个系统出现冲突的时候请求用户决定保留哪一个版本。
    3. 使用了**seccomp-bpf**和**ptrace** (这个可能还要再查是怎么回事) 干预系统调用并且实现fakeroot。具体的，其作为过滤器来干预沙盒中进程的syscall，如限制某进程对socket的调用。
    4. 其对sefccomp-bpf的使用与我们的设想相同，将每个syscall的进入调用挂在某个bpf程序上，bpf程序接受syscall的类型，进程的属性等信息，计算是否有相应权限。
   
   - 4.2节中涉及了这个课题组在使用ptrace和seccomp-bpf时规避了哪些问题，太具体了没有看懂，日后有需要的时候应该回来再查阅。

   - 文章的参考文献部分提到了seccomp-bpf的原始论文，但是似乎链接已经死了，由于此成果是2012年的，故不太可能基于ebpf结构，因此使用ebpf重新实现此功能仍然
  
- 调查了linux对sandebox的现有支持，linux主要提供了如下几个可以用于sandebox的工具： Seccomp、cgroups、Linux namespaces。
  - seccomp：[wiki页面](https://en.wikipedia.org/wiki/Seccomp)   
  传统seccomp可以让某个进程进入安全模式，并且阻止其调用所有除了exit(), sigreturn(), read(), write()外的所有对file descriptor (FD) 的调用，一旦发现此类调用就立即kill进程。后来引入bpf后可以更灵活的设置拦截的规则。
  - Cgroups: [wiki页面](https://en.wikipedia.org/wiki/Cgroups)   
  主要支持四个功能：
    1. 限制某些groups的资源使用量(包括CPU，IO，内存等) 
    2. 调整优先级，使某些group可以分配到更多的资源
    3. 记录某些group的资源使用量
    4. 控制某些group的运行，具体的可以冻结，快照，重启。
  - Linux namespaces：[wiki页面](https://en.wikipedia.org/wiki/Linux_namespaces)   
  可以将资源分配的不同的namespace，每个namespace
  可以包括若干进程，共享namespace下的资源，每份资源也可以重复出现在多个namespace下(具体内容需要再研究)

- JVM和eBPF的结构似乎很像，核心区别可能是JVM运行在用户态而eBPF运行在内核态，同时eBPF出于安全原因有更多的安全限制，也许可以通过学习JVM的相关知识来理解eBPF的实现。或者可以参考JVM的结构让eBPF可以执行更多的功能。
  
# 4月9日

- 需要研究gviser的结构和问题     

  gviser的性能分析[ The True Cost of Containing: A gVisor Case Study](https://www.usenix.org/system/files/hotcloud19-paper-young.pdf)  
  概括的来说，文章提出来了如下观点：
  - 传统来说，hyperviser模式的虚拟化容器有着更好的安全性，但是难以保证性能。hostOS结构的容器(如docker)的性能更好可能是由于其运行的若干的虚拟机通过一个统一的完善的通用OS来调度各类资源。但是由于hostOS结构中hostOS本身没有运行在容器中，其本身的内核bug容易成为被攻击的目标 (详细分析见此文[Are Docker containers really secure?](https://opensource.com/business/14/7/docker-security-selinux)) (此文章主要分析在下面单独写了)
  - gviser的性能非常差，打开关闭文件比传统容器慢了216倍，其他操作也普遍慢了很多（2倍到11倍）
  - gVisor支持OCI(Open Container Initiative),因此docker用户可以自己配置使用默认引擎，runc或者gvisor作为runtime engine
  - gVisor结构如下 guestApp-Sentry( VMM+guestOS(linux) )-hostOS,多层结构确保程序难以同时攻克每一层的安全缺陷，损害hostOS的安全。 sentry提供两种工作模式，第一种模式中其追踪并且翻译gusetAPP的系统调用，第二种模式中其更像是虚拟机中工作的guestOS，直接服务guestAPP
  - gVisor为guestAPP提供了211个syscall(标准linux提供了319种)，gVisor只需要向hostOS请求55种syscall，这些syscall的种类都是通过seccomp技术限制和约束的，当sentry被guestAPP劫持并且申请了超出允许范围的syscall时，seccomp过滤器会把gVisor杀死从而确保hostOS的安全。诸如OPEN和SOCKET这样的操作被设计者认为是极端危险的，因此没有被列入许可的syscall，这两个功能是通过复杂的结构设计出来的，从而保证可以在不调用hostOS的对应syscall的前提下安全的为guestAPP提供服务。**这就是为什么gVisor的文件性能如此差**
  - gVisor对文件服务的实现：  
  sentry搞了若干个不同的内置文件系统来尽可能满足guestAPP的请求  
  当不得不去读取hostOS文件系统时，他调用Gofer来替他进行文件访问，访问结果（文件句柄）通过一个p9Channel返回给sentry（进程间通讯），所以非常慢但是很安全。  
  sentry得到句柄后需要进行用户态到内核态的转化和上下文切换才能进行读取。
  - 本文后面包含了如何对此类容器进行性能测试，回头可以再看。
  
  
    


- [Are Docker containers really secure?](https://opensource.com/business/14/7/docker-security-selinux)的笔记。
  - " Currently, Docker uses five namespaces to alter processes view of the system: Process, Network, Mount, Hostname, Shared Memory."  
  linux中的namespace到底是什么样的概念，docker是如何使用这五个namespace的？
  - 文章中提到了说linux中很多组件是没有结合namespace的，然后其上运行的容器为了运行这些组件，将会有必要获得在hostOS中获得一定的权限，此类权限范围很广因此存在很多潜在的可攻击点。


- 需要研究docker的基本结构
- 需要研究hyperviser模型和hostOS模型的虚拟化各自的性能缺陷

























