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