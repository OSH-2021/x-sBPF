# **调研记录 陈思睿**
- 沙盒及安全控制  
  - Linux系统[seccomp()](https://www.man7.org/linux/man-pages/man2/seccomp.2.html)。使用它可以向内通报一个程序将要向内核发出的指令。如果程序发出了不在通报内的指令，它会被终结。一种具体使用方式是写BPF指令，关联到seccomp的函数中，由BPF去捕捉程序的违规操作，在内核中终结进程。有方法不在源代码设定通报就实现控制，基本就是个沙盒。这种内核中的沙盒只是利用BPF限制了系统调用，沙盒内外的程序运行环境好像没有其他区别。具体见文章[sandboxing-in-linux-with-zero-lines-of-code](https://blog.cloudflare.com/sandboxing-in-linux-with-zero-lines-of-code/)  
  - 内核中运行程序。哪怕有户空间的程序的源码，想把它编译成一个内核模块去装载也是基本不可能的。内核模块的源代码不能包含通常程序的头文件，因为编译后的程序调用的接口是特供给用户态的。只能使用作为内核一部分的函数，比如<linux/module.h>。
    - “本发明提供了基于嵌入式Linux操作系统的内核级线程库的实现方法，提供了内核线程的管理、信号量同步机制、内存的动态分配和回收和日志管理功能……并且还提供标准C库的功能子集，如基本输入输出，字符串操作，文件操作和网络套接字等。”[一份专利书](https://patents.google.com/patent/CN101226487A/zh)。
    -  内核动态编译机制：BPF的JIT。
  - Linux Namespace机制。资源隔离方案，将 Linux 的全局资源，划分为 namespace 范围内的资源，而且不同 namespace 间的资源彼此透明，不同 namespace 里的进程无法感知到其它 namespace 里面的进程和资源。但是namespace机制有缺陷。 
    -  Non-namespace-aware system call interface facilitates the adversary to compromise applications running in containers and further exploit
kernel vulnerabilities to elevate privileges, bypass access control policy enforcement, and
escape isolation mechanisms. 
    - [某种沙盒的安全方案](https://xueshu.baidu.com/usercenter/paper/show?paperid=1f4p04r0mh3j0td04s1j0r5013162640&site=xueshu_se)。用自动测试锁定一个container中程序的系统调用。然后在实际运行中阻止非锁定的任何系统调用。但是锁定系统调用不算特别理想。程序调用的是API，间接执行系统调用，不容易直接发现。有的程序将近一半的可能系统调用都没被发掘。对于开发者来说，可以加入自己的测试过程来辅助锁定。
- 计算引擎
  - [谷歌计算引擎](https://zh.m.wikipedia.org/wiki/Google%E8%AE%A1%E7%AE%97%E5%BC%95%E6%93%8E)——云计算服务。重点在于云端计算，不是特化的计算工具库，偏服务性质。
  - [matlab引擎](https://zh.m.wikipedia.org/wiki/Google%E8%AE%A1%E7%AE%97%E5%BC%95%E6%93%8E)。这个链接介绍了了适用于C的API（用于操纵matlab程序）。matlab显然是一个计算引擎。就像游戏引擎提供了侦测、渲染等预制工具，matlab提供了积分、矩阵乘法等计算接口。
  - 我觉得math.h，STL也是计算引擎。  
-  BPF   
   - 源码在Linux源码的kernel/bpf中。阅读不同linux版本的源码可以访问 https://elixir.bootlin.com/linux/v4.20.17/source/kernel/bpf  
     早期版本(如4.0.9)的bpf比后期的(如5.x.x)结构简单很多，代码量差距很大。也许可以先看以前的。
   - Verifier：可能是BPF最复杂的部分。要拓展BPF得大量修改。
   - 内核态与用户态的数据交流通道：用户通过bpf helpers syscalls创建bpf map。bpf map有别于bpf程序在内核中的堆栈，是无限制的，存任何数据都行，自由指定大小。内核态可以直接访问map，写入数据。用户态需要得到map's file descriptor，间接访问。访问都需调用bpf helpers函数。
   -  Fast Packet Processing with eBPF and XDP: Concept, Code, Challenges, and Applications 部分内容：  
      - 快速数据包处理，如控制分发操作(IoT)
      - 网络路由，子节点的路径管理(InKeV)
      - Container技术，将一套应用程序所需的执行环境打包起来。将BPF程序放进每个Container，对每个应用程序做出更强的管理(Cilium)


- 杂项  
  - OJ也是种沙盒。我们做的算法练习题依靠的只有很基本的库函数，程序组成也比较简单，但是计算量可以很大。而BPF有限的Stack Space，为了防止死循环（时间问题）而对循环的敏感性……有点般配