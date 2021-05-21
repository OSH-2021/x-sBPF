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
  
## 4月9日

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


## 4月10日
- 有关eBPF详细概念的paper [文章链接](https://www.researchgate.net/profile/Marcos-Vieira/publication/339084847_Fast_Packet_Processing_with_eBPF_and_XDP_Concepts_Code_Challenges_and_Applications/links/5e4145f592851c7f7f2c28eb/Fast-Packet-Processing-with-eBPF-and-XDP-Concepts-Code-Challenges-and-Applications.pdf)  
  




## 4月13日
- 有关恶意进程的常见行为分析  
  - [安全相关的文章分享站](https://paper.seebug.org/)
  
  - 知名恶意程序 beacon，Zeus、Asprox
  -  [360写的zenus变种木马分析](https://www.freebuf.com/articles/paper/171820.html) 推荐看看
  - [一个zeus变种木马的结构和功能分析 ](https://cloud.tencent.com/developer/article/1036506)  
  - 此木马功能非常丰富，包括使用VNC远程桌面控制电脑，截屏并发送，读取本地数据并发送，读取用户所有操作并发送，通过注册表开机自动启动，监测是否处于沙盒环境并且在沙盒中自动停止活动，监测注册表以防止自己的自动启动被清除。
  - 此木马通过邮件分发， 邮件中包含一个doc文件链接，打开后offic会提示需要启用宏来查看完整信息，启用宏后此木马会自动解码并且将自己复制进svchost.exe(windows下用于加载动态链接库的通用进程)，然后会开始运行各种功能，包括剩余模块的下载，劫持浏览器，窃取本地数据等。
  - 木马通过读取进程列表以判断是否有正在打开的浏览器，然后当存在浏览器的时其会通过浏览器的安全漏洞劫持网页，修改用户正在访问的银行网页，截取其输入的密码、账号、pin、等内容并且发送给服务器。
  - 此类木马对沙盒有有特殊的监测机制，运行在沙盒内的时候系统中会出现若干特征性的监控类设备驱动，当发现自己运行在沙盒中时，木马停止活动以防止自己被安全人员监测出来。
  - 抵御此木马需要的安全措施包括如下  
    好吧这个木马基本上都各种层面上利用了windows莫名其妙的安全漏洞，office的漏洞这么多年没有得到好好的处理，svchost对动态链接库的调用机制决定了这个玩意很可能难以简单的处理。其对应的解决方案可能只有虚拟化内核并且将局部的svchost或注册表暴露给恶意进程，可能核心是需要考虑如何隐藏沙盒环境的特征。

- [wiki 计算机病毒](https://en.wikipedia.org/wiki/Computer_virus#First_examples)  
  - 本文介绍了计算机病毒的一些基本概念，如病毒的感染机制、运行机制、隐藏机制等
  - 病毒可能通过word或outlook的微程序植入恶意进程，word或outlook允许在文档里附带短小的程序以在开启时自动运行，可能缺少安全性考量。
  - 病毒可以在boot section中存在，以u盘病毒为典型例子，在这种物理媒体刚被插到电脑上时，一段boot代码会自动被转移到系统中并执行，其中可能潜藏了恶意代码。

- gVisor的使用场景
  - gVisor是google开发的，用于实现在云上的安全容器或APP Engine(某一个云上的计算平台)或作为docker的底层实现。

## 4月14日
- docker  
  [docerk结构介绍的专栏](https://draveness.me/docker/)
  - 通过namespace，不同docker容器无法访问其他的进程，在容器位置向系统请求进程列表会只能看到少数几个局部的容器内进程，无法发现主机的其他进程。  
  通过这种技术，类似于zeus的劫持浏览器进程的木马难以危害主机安全。
  
  - 通过namespace，每个docker会被置入隔离的网络环境中，对外的网络功能是通过在每个docker上运行虚拟的网卡并且以桥接模式（默认）与主机网卡链接来实现的。  
  在这种情况下可以通过网络安全策略的方式直接控制容器进程的非法网络访问。  
  libnetwork：docker的网络功能实现的具体技术
  
  - 利用libcontainer（以及namespace）来实现了对文件系统的保护，libcontainer中的chroot技术可以限制某个子系统对应的根目录（rootFS），即在容器内的进程来看，当前FS的root就是实际所在的子目录，因而其无法读取或访问主机上的其他文件。

  - cgroup（控制组）是用于限制进程对CPU、内存、网络带宽等运行资源的占用强度的，其也可以用来限制容器内程序对设备的访问。不同的进程被组合成一个cgroup，作为一个整体参与资源的调度，并且可以通过cgroup组策略来限制当前group可以占用多少资源。且cgroup可以嵌套，一个cgroup里面可以包含多个子cgroup。  
  如整个docker可能被放在一个cgroup中以限制总资源使用量，然后docker里面的每个容器中的进程也各自建立cgroup，参与划分docekr-group分配到的总的资源。

  - 联合文件系统（Unionfs），实质上概念很简单，此文件系统不管理物理存储，只是依赖于某一个通用的文件系统，并且把不同文件夹的内容映射到同一个文件目录内。似乎是docker的重要组成部分。
  - 如何搭建docker镜像 [网页链接](https://yeasy.gitbook.io/docker_practice/image/build)
  - docker相关的没有太大用处的paper [An introduction to docker and analysis of its performance](https://d1wqtxts1xzle7.cloudfront.net/52736106/IJCSNS-20170327.pdf?1492765779=&response-content-disposition=inline%3B+filename%3DAn_Introduction_to_Docker_and_Analysis_o.pdf&Expires=1618388924&Signature=bOduLUrH0SNe~XVDBuQLpbGL6vJWuCC7RjI7IB2X6yhUMuNooLVd-hlu2aUclyjXbI087-oo8lP0aQLlGBLovVnG9gGxNFbtxJSogwXwDYyQD3LFwPaM-zvHfU3R3tuF1chkXHX0DKPZIO~qYOiOJnNufuEMgzonShQV1LsalPWq4g6kmoVNd~FZxx9EFRDyV0TyKtIJODffxD~PKZ-KHhDQT-vJI~G3165Oooy-numRj6lPS2Pzq-0SJVpK6aISee3qXpWfK2pqMehN4B4ZNhgmFCnHwd0WPDaThOj-DU6sUo8tb0FCV2O~MXhkjQNCnkNO67qYuiphX0vYdH2z5A__&Key-Pair-Id=APKAJLOHF5GGSLRBV4ZA)
  
  - 分析了docker安全性的文章 [Analysis of docker security](https://arxiv.org/pdf/1501.02967.pdf)  
  文章指出了如下观点 
    - 模型如下：当hostOS中运行的docker容器中有一部分被恶意进程完全控制了，其可以对系统进行如下的攻击如Denial-of-Service 和 Privilege escalation
    - 为了在这种情况下保护系统安全，容器应当做到如下几点：
      - process isolation
      - filesystem isolation
      - device isolation 
      - IPC isolation
      - network isolation
      - limiting of resources 

  - 对于路线1或路线3，我们可以参考docker的安全策略，此策略在各个角度上都有较好的安全性，而且性能相当的高。


- linux下的常见病毒 [专栏](https://segmentfault.com/a/1190000022761270)  
  - BillGates DDOS攻击
  - DDG 蠕虫式挖矿
  - SystemdMiner 蠕虫式挖矿
  - StartMiner 蠕虫式挖矿
  - WatchdogsMiner 挖矿
  - XorDDos 传播感染的机器构成僵尸网络，用于DDos
  - RainbowMiner 挖矿 
- linux恶意进程现状分析 [病毒必须死网站](https://blog.malwaremustdie.org/p/linux-malware-research-list-updated.html)
- 某个天朝开发的ddos僵尸网络恶意进程源码分析[链接](https://blog.malwaremustdie.org/2016/01/mmd-0048-2016-ddostf-new-elf-windows.html)  
特征  
  - ELF文件作为攻击的起点
  - CNC(这个是啥？)
  - 使用的攻击逻辑为SYN, DNS, TCP and ACK 以及HTTP header。
- [介绍了经典的几种攻击方法](https://www.inforsec.org/wp/?p=389)
  - 操作系统中的一个用户态组件——动态装载器，负责装载二进制文件以及它们依赖的库文件到内存中。二进制文件使用动态装载器来支持导入符号的解析功能。有趣的是，这恰好就是一个面对加固应用的攻击者通过泄漏库地址与内容尝试“重塑”一个符号的表现。windows下的svchost.exe攻击或者linux下的elf攻击都是利用了这个组件进行的攻击。
  - 早期的栈溢出利用依赖于向缓冲区中注入二进制代码(称为shellcode)的能力，并需要覆盖在栈上的一个返回地址使其指向这个缓冲区。随后，当程序从当前函数返回时，执行流就会被重定向到攻击者的shellcode，接着攻击者就能取得程序的控制权。
  - 动态装载器是一个用户执行环境的组件，它能够帮助在开始时加载应用需要的库并解析库导出的动态符号(函数和全局变量)供应用程序使用。在这一节中，我们将会阐述动态符号解析的过程在基于ELF的系统上是如何工作的 [33]


- 三条技术路线
  - 在seccomp结构上优化制作更好的系统调用的拦截和判断机制，实现只通过一个简单的过滤器就能保证较强安全性的轻量级安全沙盒。
  - 尝试将一个基于虚拟化技术的安全沙盒通过bpf程序的方式制作出来并且诸如OS内运行，可能需要修改现有的ebpf认证与导入机制。
  - 仅将bpf程序作为劫持和修改系统调用的小模块，将其结合到某个现有的用户态沙盒中，从而优化某个用户态沙盒应用的效率


## 4月15日
- Open Container Initiative（OCI） 为docker和gvisor之类的容器技术所支持的接口


## 4月16日
- 对linux源码的阅读结果
  - verifier的主要代码位于linux/kernel/bpf/verifier.c
  - 我们计划进行简单修改的MAXSIZE项来自于linux/kernel/bpf/bpf.c
  - 


- https://www.zhihu.com/question/25357707 如何修改linux
- https://xz.aliyun.com/t/8482 linux kernel bpf模块的漏洞和其利用方式。

## 5月21日
- linux内bpf program type的实现方式相关源码分析  
  - 调研从 syscall标准入口函数开始，源代码内容如下，主要工作流程为检查权限（或者capable),检查传入内容的合法性，然后对cmd的内容进行分支，决定调用具体的功能函数    
  ``` C++
  SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
  {
    union bpf_attr attr;
    int err;

    if (sysctl_unprivileged_bpf_disabled && !bpf_capable())
      return -EPERM;

    err = bpf_check_uarg_tail_zero(uattr, sizeof(attr), size);
    if (err)
      return err;
    size = min_t(u32, size, sizeof(attr));

    /* copy attributes from user space, may be less than sizeof(bpf_attr) */
    memset(&attr, 0, sizeof(attr));
    if (copy_from_user(&attr, uattr, size) != 0)
      return -EFAULT;

    err = security_bpf(cmd, &attr, size);
    if (err < 0)
      return err;

    switch (cmd) {
    case BPF_MAP_CREATE:
      err = map_create(&attr);
      break;
    case BPF_MAP_LOOKUP_ELEM:
      err = map_lookup_elem(&attr);
      break;
    case BPF_MAP_UPDATE_ELEM:
      err = map_update_elem(&attr);
      break;
    case BPF_MAP_DELETE_ELEM:
      err = map_delete_elem(&attr);
      break;
    case BPF_MAP_GET_NEXT_KEY:
      err = map_get_next_key(&attr);
      break;
    case BPF_MAP_FREEZE:
      err = map_freeze(&attr);
      break;
    case BPF_PROG_LOAD:
      err = bpf_prog_load(&attr, uattr);
      break;
    case BPF_OBJ_PIN:
      err = bpf_obj_pin(&attr);
      break;
    case BPF_OBJ_GET:
      err = bpf_obj_get(&attr);
      break;
    case BPF_PROG_ATTACH:
      err = bpf_prog_attach(&attr);
      break;
    case BPF_PROG_DETACH:
      err = bpf_prog_detach(&attr);
      break;
    case BPF_PROG_QUERY:
      err = bpf_prog_query(&attr, uattr);
      break;
    case BPF_PROG_TEST_RUN:
      err = bpf_prog_test_run(&attr, uattr);
      break;
    case BPF_PROG_GET_NEXT_ID:
      err = bpf_obj_get_next_id(&attr, uattr,
              &prog_idr, &prog_idr_lock);
      break;
    case BPF_MAP_GET_NEXT_ID:
      err = bpf_obj_get_next_id(&attr, uattr,
              &map_idr, &map_idr_lock);
      break;
    case BPF_BTF_GET_NEXT_ID:
      err = bpf_obj_get_next_id(&attr, uattr,
              &btf_idr, &btf_idr_lock);
      break;
    case BPF_PROG_GET_FD_BY_ID:
      err = bpf_prog_get_fd_by_id(&attr);
      break;
    case BPF_MAP_GET_FD_BY_ID:
      err = bpf_map_get_fd_by_id(&attr);
      break;
    case BPF_OBJ_GET_INFO_BY_FD:
      err = bpf_obj_get_info_by_fd(&attr, uattr);
      break;
    case BPF_RAW_TRACEPOINT_OPEN:
      err = bpf_raw_tracepoint_open(&attr);
      break;
    case BPF_BTF_LOAD:
      err = bpf_btf_load(&attr);
      break;
    case BPF_BTF_GET_FD_BY_ID:
      err = bpf_btf_get_fd_by_id(&attr);
      break;
    case BPF_TASK_FD_QUERY:
      err = bpf_task_fd_query(&attr, uattr);
      break;
    case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
      err = map_lookup_and_delete_elem(&attr);
      break;
    case BPF_MAP_LOOKUP_BATCH:
      err = bpf_map_do_batch(&attr, uattr, BPF_MAP_LOOKUP_BATCH);
      break;
    case BPF_MAP_LOOKUP_AND_DELETE_BATCH:
      err = bpf_map_do_batch(&attr, uattr,
                BPF_MAP_LOOKUP_AND_DELETE_BATCH);
      break;
    case BPF_MAP_UPDATE_BATCH:
      err = bpf_map_do_batch(&attr, uattr, BPF_MAP_UPDATE_BATCH);
      break;
    case BPF_MAP_DELETE_BATCH:
      err = bpf_map_do_batch(&attr, uattr, BPF_MAP_DELETE_BATCH);
      break;
    case BPF_LINK_CREATE:
      err = link_create(&attr);
      break;
    case BPF_LINK_UPDATE:
      err = link_update(&attr);
      break;
    case BPF_LINK_GET_FD_BY_ID:
      err = bpf_link_get_fd_by_id(&attr);
      break;
    case BPF_LINK_GET_NEXT_ID:
      err = bpf_obj_get_next_id(&attr, uattr,
              &link_idr, &link_idr_lock);
      break;
    case BPF_ENABLE_STATS:
      err = bpf_enable_stats(&attr);
      break;
    case BPF_ITER_CREATE:
      err = bpf_iter_create(&attr);
      break;
    default:
      err = -EINVAL;
      break;
    }
  ```
  - 下面引用的代码是bpf内定义的各种枚举类型，通过枚举类型定义了bpf内会需要使用到的各种程序类型、链接类型、map类型、cmd类型等。
  ``` C++
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
    BPF_MAP_LOOKUP_BATCH,
    BPF_MAP_LOOKUP_AND_DELETE_BATCH,
    BPF_MAP_UPDATE_BATCH,
    BPF_MAP_DELETE_BATCH,
    BPF_LINK_CREATE,
    BPF_LINK_UPDATE,
    BPF_LINK_GET_FD_BY_ID,
    BPF_LINK_GET_NEXT_ID,
    BPF_ENABLE_STATS,
    BPF_ITER_CREATE,
  };

  enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
    BPF_MAP_TYPE_PROG_ARRAY,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_PERCPU_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BPF_MAP_TYPE_STACK_TRACE,
    BPF_MAP_TYPE_CGROUP_ARRAY,
    BPF_MAP_TYPE_LRU_HASH,
    BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BPF_MAP_TYPE_LPM_TRIE,
    BPF_MAP_TYPE_ARRAY_OF_MAPS,
    BPF_MAP_TYPE_HASH_OF_MAPS,
    BPF_MAP_TYPE_DEVMAP,
    BPF_MAP_TYPE_SOCKMAP,
    BPF_MAP_TYPE_CPUMAP,
    BPF_MAP_TYPE_XSKMAP,
    BPF_MAP_TYPE_SOCKHASH,
    BPF_MAP_TYPE_CGROUP_STORAGE,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    BPF_MAP_TYPE_QUEUE,
    BPF_MAP_TYPE_STACK,
    BPF_MAP_TYPE_SK_STORAGE,
    BPF_MAP_TYPE_DEVMAP_HASH,
    BPF_MAP_TYPE_STRUCT_OPS,
    BPF_MAP_TYPE_RINGBUF,
  };

  /* Note that tracing related programs such as
  * BPF_PROG_TYPE_{KPROBE,TRACEPOINT,PERF_EVENT,RAW_TRACEPOINT}
  * are not subject to a stable API since kernel internal data
  * structures can change from release to release and may
  * therefore break existing tracing BPF programs. Tracing BPF
  * programs correspond to /a/ specific kernel which is to be
  * analyzed, and not /a/ specific kernel /and/ all future ones.
  */
  enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_CGROUP_SOCK,
    BPF_PROG_TYPE_LWT_IN,
    BPF_PROG_TYPE_LWT_OUT,
    BPF_PROG_TYPE_LWT_XMIT,
    BPF_PROG_TYPE_SOCK_OPS,
    BPF_PROG_TYPE_SK_SKB,
    BPF_PROG_TYPE_CGROUP_DEVICE,
    BPF_PROG_TYPE_SK_MSG,
    BPF_PROG_TYPE_RAW_TRACEPOINT,
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    BPF_PROG_TYPE_LWT_SEG6LOCAL,
    BPF_PROG_TYPE_LIRC_MODE2,
    BPF_PROG_TYPE_SK_REUSEPORT,
    BPF_PROG_TYPE_FLOW_DISSECTOR,
    BPF_PROG_TYPE_CGROUP_SYSCTL,
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
    BPF_PROG_TYPE_CGROUP_SOCKOPT,
    BPF_PROG_TYPE_TRACING,
    BPF_PROG_TYPE_STRUCT_OPS,
    BPF_PROG_TYPE_EXT,
    BPF_PROG_TYPE_LSM,
  };

  enum bpf_attach_type {
    BPF_CGROUP_INET_INGRESS,
    BPF_CGROUP_INET_EGRESS,
    BPF_CGROUP_INET_SOCK_CREATE,
    BPF_CGROUP_SOCK_OPS,
    BPF_SK_SKB_STREAM_PARSER,
    BPF_SK_SKB_STREAM_VERDICT,
    BPF_CGROUP_DEVICE,
    BPF_SK_MSG_VERDICT,
    BPF_CGROUP_INET4_BIND,
    BPF_CGROUP_INET6_BIND,
    BPF_CGROUP_INET4_CONNECT,
    BPF_CGROUP_INET6_CONNECT,
    BPF_CGROUP_INET4_POST_BIND,
    BPF_CGROUP_INET6_POST_BIND,
    BPF_CGROUP_UDP4_SENDMSG,
    BPF_CGROUP_UDP6_SENDMSG,
    BPF_LIRC_MODE2,
    BPF_FLOW_DISSECTOR,
    BPF_CGROUP_SYSCTL,
    BPF_CGROUP_UDP4_RECVMSG,
    BPF_CGROUP_UDP6_RECVMSG,
    BPF_CGROUP_GETSOCKOPT,
    BPF_CGROUP_SETSOCKOPT,
    BPF_TRACE_RAW_TP,
    BPF_TRACE_FENTRY,
    BPF_TRACE_FEXIT,
    BPF_MODIFY_RETURN,
    BPF_LSM_MAC,
    BPF_TRACE_ITER,
    BPF_CGROUP_INET4_GETPEERNAME,
    BPF_CGROUP_INET6_GETPEERNAME,
    BPF_CGROUP_INET4_GETSOCKNAME,
    BPF_CGROUP_INET6_GETSOCKNAME,
    BPF_XDP_DEVMAP,
    __MAX_BPF_ATTACH_TYPE
  };

  #define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE

  enum bpf_link_type {
    BPF_LINK_TYPE_UNSPEC = 0,
    BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
    BPF_LINK_TYPE_TRACING = 2,
    BPF_LINK_TYPE_CGROUP = 3,
    BPF_LINK_TYPE_ITER = 4,
    BPF_LINK_TYPE_NETNS = 5,

    MAX_BPF_LINK_TYPE,
  };

  ```
  - 然后我们从load段开始研究，下面是bpf_porg_load相关源码，load段获得了一个bpf程序的attr，bpf的prog_type是作为attr的一个属性出现并且传递给变量type的，
  这段代码在完成了基本的权限检查和合法性检查后的主要功能函数如下
    - license_is_gpl_compatible
    - bpf_prog_load_fixup_attach_type
    - bpf_prog_load_check_attach
    - bpf_prog_alloc
    - bpf_prog_get
    - security_bpf_prog_alloc
    - bpf_prog_charge_memlock
    - copy_from_user
    - atomic64_set
    - bpf_prog_is_dev_bound
    - bpf_prog_offload_init
    - find_prog_type
    - ktime_get_boottime_ns
    - bpf_obj_name_cpy
    - bpf_check
    - bpf_prog_select_runtime
    - bpf_prog_alloc_id
    - bpf_prog_kallsyms_add
    - perf_event_bpf_event
    - bpf_audit_prog
    - bpf_prog_new_fd
    - bpf_prog_put  
    在检查权限和合法性之后，这段程序给bpf程序分配了空间，给prog进行各种初始化，检查了bpf程序本身的安全性（bpf_check)，然后将bpf程序加载完成。
  ``` C++
  static int bpf_prog_load(union bpf_attr *attr, union bpf_attr __user *uattr)
  {
    enum bpf_prog_type type = attr->prog_type;
    struct bpf_prog *prog;
    int err;
    char license[128];
    bool is_gpl;

    if (CHECK_ATTR(BPF_PROG_LOAD))
      return -EINVAL;

    if (attr->prog_flags & ~(BPF_F_STRICT_ALIGNMENT |
          BPF_F_ANY_ALIGNMENT |
          BPF_F_TEST_STATE_FREQ |
          BPF_F_TEST_RND_HI32))
      return -EINVAL;

    if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) &&
        (attr->prog_flags & BPF_F_ANY_ALIGNMENT) &&
        !bpf_capable())
      return -EPERM;

    /* copy eBPF program license from user space */
    if (strncpy_from_user(license, u64_to_user_ptr(attr->license),
              sizeof(license) - 1) < 0)
      return -EFAULT;
    license[sizeof(license) - 1] = 0;

    /* eBPF programs must be GPL compatible to use GPL-ed functions */
    is_gpl = license_is_gpl_compatible(license);

    if (attr->insn_cnt == 0 ||
        attr->insn_cnt > (bpf_capable() ? BPF_COMPLEXITY_LIMIT_INSNS : BPF_MAXINSNS))
      return -E2BIG;
    if (type != BPF_PROG_TYPE_SOCKET_FILTER &&
        type != BPF_PROG_TYPE_CGROUP_SKB &&
        !bpf_capable())
      return -EPERM;

    if (is_net_admin_prog_type(type) && !capable(CAP_NET_ADMIN) && !capable(CAP_SYS_ADMIN))
      return -EPERM;
    if (is_perfmon_prog_type(type) && !perfmon_capable())
      return -EPERM;

    bpf_prog_load_fixup_attach_type(attr);
    if (bpf_prog_load_check_attach(type, attr->expected_attach_type,
                attr->attach_btf_id,
                attr->attach_prog_fd))
      return -EINVAL;

    /* plain bpf_prog allocation */
    prog = bpf_prog_alloc(bpf_prog_size(attr->insn_cnt), GFP_USER);
    if (!prog)
      return -ENOMEM;

    prog->expected_attach_type = attr->expected_attach_type;
    prog->aux->attach_btf_id = attr->attach_btf_id;
    if (attr->attach_prog_fd) {
      struct bpf_prog *tgt_prog;

      tgt_prog = bpf_prog_get(attr->attach_prog_fd);
      if (IS_ERR(tgt_prog)) {
        err = PTR_ERR(tgt_prog);
        goto free_prog_nouncharge;
      }
      prog->aux->linked_prog = tgt_prog;
    }

    prog->aux->offload_requested = !!attr->prog_ifindex;

    err = security_bpf_prog_alloc(prog->aux);
    if (err)
      goto free_prog_nouncharge;

    err = bpf_prog_charge_memlock(prog);
    if (err)
      goto free_prog_sec;

    prog->len = attr->insn_cnt;

    err = -EFAULT;
    if (copy_from_user(prog->insns, u64_to_user_ptr(attr->insns),
          bpf_prog_insn_size(prog)) != 0)
      goto free_prog;

    prog->orig_prog = NULL;
    prog->jited = 0;

    atomic64_set(&prog->aux->refcnt, 1);
    prog->gpl_compatible = is_gpl ? 1 : 0;

    if (bpf_prog_is_dev_bound(prog->aux)) {
      err = bpf_prog_offload_init(prog, attr);
      if (err)
        goto free_prog;
    }

    /* find program type: socket_filter vs tracing_filter */
    err = find_prog_type(type, prog);
    if (err < 0)
      goto free_prog;

    prog->aux->load_time = ktime_get_boottime_ns();
    err = bpf_obj_name_cpy(prog->aux->name, attr->prog_name,
              sizeof(attr->prog_name));
    if (err < 0)
      goto free_prog;

    /* run eBPF verifier */
    err = bpf_check(&prog, attr, uattr);
    if (err < 0)
      goto free_used_maps;

    prog = bpf_prog_select_runtime(prog, &err);
    if (err < 0)
      goto free_used_maps;

    err = bpf_prog_alloc_id(prog);
    if (err)
      goto free_used_maps;

    /* Upon success of bpf_prog_alloc_id(), the BPF prog is
    * effectively publicly exposed. However, retrieving via
    * bpf_prog_get_fd_by_id() will take another reference,
    * therefore it cannot be gone underneath us.
    *
    * Only for the time /after/ successful bpf_prog_new_fd()
    * and before returning to userspace, we might just hold
    * one reference and any parallel close on that fd could
    * rip everything out. Hence, below notifications must
    * happen before bpf_prog_new_fd().
    *
    * Also, any failure handling from this point onwards must
    * be using bpf_prog_put() given the program is exposed.
    */
    bpf_prog_kallsyms_add(prog);
    perf_event_bpf_event(prog, PERF_BPF_EVENT_PROG_LOAD, 0);
    bpf_audit_prog(prog, BPF_AUDIT_LOAD);

    err = bpf_prog_new_fd(prog);
    if (err < 0)
      bpf_prog_put(prog);
    return err;

  free_used_maps:
    /* In case we have subprogs, we need to wait for a grace
    * period before we can tear down JIT memory since symbols
    * are already exposed under kallsyms.
    */
    __bpf_prog_put_noref(prog, prog->aux->func_cnt);
    return err;
  free_prog:
    bpf_prog_uncharge_memlock(prog);
  free_prog_sec:
    security_bpf_prog_free(prog->aux);
  free_prog_nouncharge:
    bpf_prog_free(prog);
    return err;
  }

  ```

  - 这是上文bpf_prog_load中的一个子函数，主要功能就是检查传入的bpf attr中所存的type属性是否和定义一致。具体的来说，find_prog_type上方简单的通过全局静态变量定义了bpf_prog_types数组，这个数组的构建方式会在后面马上提到。程序中只要检查传入的type是否在数组范围内，检查数组内对应type的内容是否合法，如果通过了检查则将type内的op域内容直接传递给prog的属性aux->ops，将传入的type内容直接传递给prog作为属性存下。
  ``` C++
  static const struct bpf_prog_ops * const bpf_prog_types[] = {
  #define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
    [_id] = & _name ## _prog_ops,
  #define BPF_MAP_TYPE(_id, _ops)
  #define BPF_LINK_TYPE(_id, _name)
  #include <linux/bpf_types.h>
  #undef BPF_PROG_TYPE
  #undef BPF_MAP_TYPE
  #undef BPF_LINK_TYPE
  };

  static int find_prog_type(enum bpf_prog_type type, struct bpf_prog *prog)
  {
    const struct bpf_prog_ops *ops;

    if (type >= ARRAY_SIZE(bpf_prog_types))
      return -EINVAL;
    type = array_index_nospec(type, ARRAY_SIZE(bpf_prog_types));
    ops = bpf_prog_types[type];
    if (!ops)
      return -EINVAL;

    if (!bpf_prog_is_dev_bound(prog->aux))
      prog->aux->ops = ops;
    else
      prog->aux->ops = &bpf_offload_prog_ops;
    prog->type = type;
    return 0;
  }
  
  ```
  - 这段内容是bpf_prog_types数组的定义和定义中用到的内部头文件bpf_types.h，结合起来就可以看出这里是如何使用头文件简化代码内容的。
  这里的调用include前define的`#define BPF_MAP_TYPE(_id, _ops)`此类空的宏定义会将符合对应格式的内容直接忽视（效果类似于条件注释），`#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) [_id] = & _name ## _prog_ops,`这样一个宏定义会将BPF_PROG_TYPE(A,B,C,D)转义成 [A]=&B_prog_ops,由于id是枚举型，可以直接转义成下标，B的_name项则是会加上后缀_prog_ops作为一个整体的结构体名字用来定位实际的内容，实际的结构体内容则是在bpf.h中通过类似的方法结合外部引用而来，具体定义则是分布在其他各个模块的源代码中。比较奇怪的事情在于这个prog_ops结构体的内容只有一个函数指针用于test_run，可能此部分代码的测试性质高于实际功能。

  ``` C++
  static const struct bpf_prog_ops * const bpf_prog_types[] = {
  #define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
    [_id] = & _name ## _prog_ops,
  #define BPF_MAP_TYPE(_id, _ops)
  #define BPF_LINK_TYPE(_id, _name)
  #include <linux/bpf_types.h>
  #undef BPF_PROG_TYPE
  #undef BPF_MAP_TYPE
  #undef BPF_LINK_TYPE
  };
  ```
  ``` C++
  /* SPDX-License-Identifier: GPL-2.0 */
  /* internal file - do not include directly */

  #ifdef CONFIG_NET
  BPF_PROG_TYPE(BPF_PROG_TYPE_SOCKET_FILTER, sk_filter,
          struct __sk_buff, struct sk_buff)
  BPF_PROG_TYPE(BPF_PROG_TYPE_SCHED_CLS, tc_cls_act,
          struct __sk_buff, struct sk_buff)
  BPF_PROG_TYPE(BPF_PROG_TYPE_SCHED_ACT, tc_cls_act,
          struct __sk_buff, struct sk_buff)
  BPF_PROG_TYPE(BPF_PROG_TYPE_XDP, xdp,
          struct xdp_md, struct xdp_buff)
  #ifdef CONFIG_CGROUP_BPF
  BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SKB, cg_skb,
          struct __sk_buff, struct sk_buff)
  BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCK, cg_sock,
          struct bpf_sock, struct sock)
  BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, cg_sock_addr,
          struct bpf_sock_addr, struct bpf_sock_addr_kern)
  #endif
  BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_IN, lwt_in,
          struct __sk_buff, struct sk_buff)
  BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_OUT, lwt_out,
          struct __sk_buff, struct sk_buff)
  BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_XMIT, lwt_xmit,
          struct __sk_buff, struct sk_buff)
  BPF_PROG_TYPE(BPF_PROG_TYPE_LWT_SEG6LOCAL, lwt_seg6local,
          struct __sk_buff, struct sk_buff)
  BPF_PROG_TYPE(BPF_PROG_TYPE_SOCK_OPS, sock_ops,
          struct bpf_sock_ops, struct bpf_sock_ops_kern)
  BPF_PROG_TYPE(BPF_PROG_TYPE_SK_SKB, sk_skb,
          struct __sk_buff, struct sk_buff)
  BPF_PROG_TYPE(BPF_PROG_TYPE_SK_MSG, sk_msg,
          struct sk_msg_md, struct sk_msg)
  BPF_PROG_TYPE(BPF_PROG_TYPE_FLOW_DISSECTOR, flow_dissector,
          struct __sk_buff, struct bpf_flow_dissector)
  #endif
  #ifdef CONFIG_BPF_EVENTS
  BPF_PROG_TYPE(BPF_PROG_TYPE_KPROBE, kprobe,
          bpf_user_pt_regs_t, struct pt_regs)
  BPF_PROG_TYPE(BPF_PROG_TYPE_TRACEPOINT, tracepoint,
          __u64, u64)
  BPF_PROG_TYPE(BPF_PROG_TYPE_PERF_EVENT, perf_event,
          struct bpf_perf_event_data, struct bpf_perf_event_data_kern)
  BPF_PROG_TYPE(BPF_PROG_TYPE_RAW_TRACEPOINT, raw_tracepoint,
          struct bpf_raw_tracepoint_args, u64)
  BPF_PROG_TYPE(BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, raw_tracepoint_writable,
          struct bpf_raw_tracepoint_args, u64)
  BPF_PROG_TYPE(BPF_PROG_TYPE_TRACING, tracing,
          void *, void *)
  #endif
  #ifdef CONFIG_CGROUP_BPF
  BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_DEVICE, cg_dev,
          struct bpf_cgroup_dev_ctx, struct bpf_cgroup_dev_ctx)
  BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SYSCTL, cg_sysctl,
          struct bpf_sysctl, struct bpf_sysctl_kern)
  BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCKOPT, cg_sockopt,
          struct bpf_sockopt, struct bpf_sockopt_kern)
  #endif
  #ifdef CONFIG_BPF_LIRC_MODE2
  BPF_PROG_TYPE(BPF_PROG_TYPE_LIRC_MODE2, lirc_mode2,
          __u32, u32)
  #endif
  #ifdef CONFIG_INET
  BPF_PROG_TYPE(BPF_PROG_TYPE_SK_REUSEPORT, sk_reuseport,
          struct sk_reuseport_md, struct sk_reuseport_kern)
  #endif
  #if defined(CONFIG_BPF_JIT)
  BPF_PROG_TYPE(BPF_PROG_TYPE_STRUCT_OPS, bpf_struct_ops,
          void *, void *)
  BPF_PROG_TYPE(BPF_PROG_TYPE_EXT, bpf_extension,
          void *, void *)
  #ifdef CONFIG_BPF_LSM
  BPF_PROG_TYPE(BPF_PROG_TYPE_LSM, lsm,
          void *, void *)
  #endif /* CONFIG_BPF_LSM */
  #endif

  BPF_MAP_TYPE(BPF_MAP_TYPE_ARRAY, array_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_PERCPU_ARRAY, percpu_array_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_PROG_ARRAY, prog_array_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_PERF_EVENT_ARRAY, perf_event_array_map_ops)
  #ifdef CONFIG_CGROUPS
  BPF_MAP_TYPE(BPF_MAP_TYPE_CGROUP_ARRAY, cgroup_array_map_ops)
  #endif
  #ifdef CONFIG_CGROUP_BPF
  BPF_MAP_TYPE(BPF_MAP_TYPE_CGROUP_STORAGE, cgroup_storage_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE, cgroup_storage_map_ops)
  #endif
  BPF_MAP_TYPE(BPF_MAP_TYPE_HASH, htab_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_PERCPU_HASH, htab_percpu_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_LRU_HASH, htab_lru_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_LRU_PERCPU_HASH, htab_lru_percpu_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_LPM_TRIE, trie_map_ops)
  #ifdef CONFIG_PERF_EVENTS
  BPF_MAP_TYPE(BPF_MAP_TYPE_STACK_TRACE, stack_trace_map_ops)
  #endif
  BPF_MAP_TYPE(BPF_MAP_TYPE_ARRAY_OF_MAPS, array_of_maps_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_HASH_OF_MAPS, htab_of_maps_map_ops)
  #ifdef CONFIG_NET
  BPF_MAP_TYPE(BPF_MAP_TYPE_DEVMAP, dev_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_DEVMAP_HASH, dev_map_hash_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_SK_STORAGE, sk_storage_map_ops)
  #if defined(CONFIG_BPF_STREAM_PARSER)
  BPF_MAP_TYPE(BPF_MAP_TYPE_SOCKMAP, sock_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_SOCKHASH, sock_hash_ops)
  #endif
  BPF_MAP_TYPE(BPF_MAP_TYPE_CPUMAP, cpu_map_ops)
  #if defined(CONFIG_XDP_SOCKETS)
  BPF_MAP_TYPE(BPF_MAP_TYPE_XSKMAP, xsk_map_ops)
  #endif
  #ifdef CONFIG_INET
  BPF_MAP_TYPE(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY, reuseport_array_ops)
  #endif
  #endif
  BPF_MAP_TYPE(BPF_MAP_TYPE_QUEUE, queue_map_ops)
  BPF_MAP_TYPE(BPF_MAP_TYPE_STACK, stack_map_ops)
  #if defined(CONFIG_BPF_JIT)
  BPF_MAP_TYPE(BPF_MAP_TYPE_STRUCT_OPS, bpf_struct_ops_map_ops)
  #endif
  BPF_MAP_TYPE(BPF_MAP_TYPE_RINGBUF, ringbuf_map_ops)

  BPF_LINK_TYPE(BPF_LINK_TYPE_RAW_TRACEPOINT, raw_tracepoint)
  BPF_LINK_TYPE(BPF_LINK_TYPE_TRACING, tracing)
  #ifdef CONFIG_CGROUP_BPF
  BPF_LINK_TYPE(BPF_LINK_TYPE_CGROUP, cgroup)
  #endif
  BPF_LINK_TYPE(BPF_LINK_TYPE_ITER, iter)
  #ifdef CONFIG_NET
  BPF_LINK_TYPE(BPF_LINK_TYPE_NETNS, netns)
  #endif

  ```
  - 这个程序是bpf_prog_attach，通过各种安全检查之后，将attach_type转换成prog_type,进入一个大的switch,分支决定在attach过程中需要进行哪些工作。
  ``` C++
  static int bpf_prog_attach(const union bpf_attr *attr)
  {
    enum bpf_prog_type ptype;
    struct bpf_prog *prog;
    int ret;

    if (CHECK_ATTR(BPF_PROG_ATTACH))
      return -EINVAL;

    if (attr->attach_flags & ~BPF_F_ATTACH_MASK)
      return -EINVAL;

    ptype = attach_type_to_prog_type(attr->attach_type);
    if (ptype == BPF_PROG_TYPE_UNSPEC)
      return -EINVAL;

    prog = bpf_prog_get_type(attr->attach_bpf_fd, ptype);
    if (IS_ERR(prog))
      return PTR_ERR(prog);

    if (bpf_prog_attach_check_attach_type(prog, attr->attach_type)) {
      bpf_prog_put(prog);
      return -EINVAL;
    }

    switch (ptype) {
    case BPF_PROG_TYPE_SK_SKB:
    case BPF_PROG_TYPE_SK_MSG:
      ret = sock_map_get_from_fd(attr, prog);
      break;
    case BPF_PROG_TYPE_LIRC_MODE2:
      ret = lirc_prog_attach(attr, prog);
      break;
    case BPF_PROG_TYPE_FLOW_DISSECTOR:
      ret = netns_bpf_prog_attach(attr, prog);
      break;
    case BPF_PROG_TYPE_CGROUP_DEVICE:
    case BPF_PROG_TYPE_CGROUP_SKB:
    case BPF_PROG_TYPE_CGROUP_SOCK:
    case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
    case BPF_PROG_TYPE_CGROUP_SOCKOPT:
    case BPF_PROG_TYPE_CGROUP_SYSCTL:
    case BPF_PROG_TYPE_SOCK_OPS:
      ret = cgroup_bpf_prog_attach(attr, ptype, prog);
      break;
    default:
      ret = -EINVAL;
    }

    if (ret)
      bpf_prog_put(prog);
    return ret;
  }
  ```
  - 以cgroup的实际最终调用函数为例，下面的内容__cgroup_bpf_attach是完成安全检查，设置完mutex之后，最终调用的功能函数。这个功能函数的运作流程是，首先检查各种权限和合法性，然后为了将bpf程序attach到cgroup上，需要分配若干的空间，加载若干的数据，最后通过修改cgroup的某个标志来完成bpf程序的加载，此后cgroup会在运行过程中检查此类标志来确定自己的行为以及调用bpf程序。
  ``` C++
  /**
  * __cgroup_bpf_attach() - Attach the program or the link to a cgroup, and
  *                         propagate the change to descendants
  * @cgrp: The cgroup which descendants to traverse
  * @prog: A program to attach
  * @link: A link to attach
  * @replace_prog: Previously attached program to replace if BPF_F_REPLACE is set
  * @type: Type of attach operation
  * @flags: Option flags
  *
  * Exactly one of @prog or @link can be non-null.
  * Must be called with cgroup_mutex held.
  */
  int __cgroup_bpf_attach(struct cgroup *cgrp,
        struct bpf_prog *prog, struct bpf_prog *replace_prog,
        struct bpf_cgroup_link *link,
        enum bpf_attach_type type, u32 flags)
  {
    u32 saved_flags = (flags & (BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI));
    struct list_head *progs = &cgrp->bpf.progs[type];
    struct bpf_prog *old_prog = NULL;
    struct bpf_cgroup_storage *storage[MAX_BPF_CGROUP_STORAGE_TYPE] = {};
    struct bpf_cgroup_storage *old_storage[MAX_BPF_CGROUP_STORAGE_TYPE] = {};
    struct bpf_prog_list *pl;
    int err;

    if (((flags & BPF_F_ALLOW_OVERRIDE) && (flags & BPF_F_ALLOW_MULTI)) ||
        ((flags & BPF_F_REPLACE) && !(flags & BPF_F_ALLOW_MULTI)))
      /* invalid combination */
      return -EINVAL;
    if (link && (prog || replace_prog))
      /* only either link or prog/replace_prog can be specified */
      return -EINVAL;
    if (!!replace_prog != !!(flags & BPF_F_REPLACE))
      /* replace_prog implies BPF_F_REPLACE, and vice versa */
      return -EINVAL;

    if (!hierarchy_allows_attach(cgrp, type))
      return -EPERM;

    if (!list_empty(progs) && cgrp->bpf.flags[type] != saved_flags)
      /* Disallow attaching non-overridable on top
      * of existing overridable in this cgroup.
      * Disallow attaching multi-prog if overridable or none
      */
      return -EPERM;

    if (prog_list_length(progs) >= BPF_CGROUP_MAX_PROGS)
      return -E2BIG;

    pl = find_attach_entry(progs, prog, link, replace_prog,
              flags & BPF_F_ALLOW_MULTI);
    if (IS_ERR(pl))
      return PTR_ERR(pl);

    if (bpf_cgroup_storages_alloc(storage, prog ? : link->link.prog))
      return -ENOMEM;

    if (pl) {
      old_prog = pl->prog;
      bpf_cgroup_storages_unlink(pl->storage);
      bpf_cgroup_storages_assign(old_storage, pl->storage);
    } else {
      pl = kmalloc(sizeof(*pl), GFP_KERNEL);
      if (!pl) {
        bpf_cgroup_storages_free(storage);
        return -ENOMEM;
      }
      list_add_tail(&pl->node, progs);
    }

    pl->prog = prog;
    pl->link = link;
    bpf_cgroup_storages_assign(pl->storage, storage);
    cgrp->bpf.flags[type] = saved_flags;

    err = update_effective_progs(cgrp, type);
    if (err)
      goto cleanup;

    bpf_cgroup_storages_free(old_storage);
    if (old_prog)
      bpf_prog_put(old_prog);
    else
      static_branch_inc(&cgroup_bpf_enabled_key);
    bpf_cgroup_storages_link(pl->storage, cgrp, type);
    return 0;

  cleanup:
    if (old_prog) {
      pl->prog = old_prog;
      pl->link = NULL;
    }
    bpf_cgroup_storages_free(pl->storage);
    bpf_cgroup_storages_assign(pl->storage, old_storage);
    bpf_cgroup_storages_link(pl->storage, cgrp, type);
    if (!old_prog) {
      list_del(&pl->node);
      kfree(pl);
    }
    return err;
  }
  ```