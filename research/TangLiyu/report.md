# 调研记录

## Docker容器

### 结构

[docker技术介绍](https://www.seltzer.com/margo/teaching/CS508.19/papers/merkel14.pdf)

- Docker是一种操作系统级别的虚拟化技术，具有以下特点
  - Docker Engine直接运行在Linux Kernel之上
  - 多个containers(若有)共享同一个Linux Kernel
  - 从内部来看,container内部的进程只能看到给他分配的资源
  - 从外部来看,多个container就是一个个普通的进程

- 进程隔离技术:采用了Linux内核所实现的cgroup,namespace
    - Linux namespace
      - 为每个container分配自己独立的资源
      - 进程不可访问别人namespace内的资源
      - 包括5种：mount,hostname,IPC,PID,network
    - CGroups
      - 分配和管理container内部的进程可以使用的资源
    - POSIX Capabilities
      - 细化进程权限
    - Seccomp
      - 限定系统调用

- 一些概念
  - Docker Image
    - 构建container的模板,一般包含应用程序及其依赖
  - Docker Container
    - Image的实例,相当于进程至于程序的概念
  - Dockers Registry
    - 可信镜像的仓库
  - Docker Engine (一般主指Dockers Daemon)
    - 负责创建和管理containers(如分配其对应的namespace)
  - Kubernetes
    - 编排多个containers,如提供containers间通信等复杂功能





### 安全问题
根本问题
- docker直接共享内核,减少的抽象层次带来比vm更轻量而高效
- 同时恶意进程也更容易的攻破Host系统(需要攻破的层次更少)

当关闭selinux时，container通过攻击不受namespace限制的kernel keyring取得其他容器的存于此的key
[Yet Another Reason Containers Don't Contain: Kernel Keyrings](https://www.projectatomic.io/blog/2014/09/yet-another-reason-containers-don-t-contain-kernel-keyrings/)



[深度解析 AWS Firecracker 原理篇 – 虚拟化与容器运行时技术](https://aws.amazon.com/cn/blogs/china/deep-analysis-aws-firecracker-principle-virtualization-container-runtime-technology/)

由于操作系统内核漏洞，Docker 组件设计缺陷，以及不当的配置都会导致 Docker 容器发生逃逸，从而获取宿主机权限

docker daemon
- Docker 守护进程也可能成为安全隐患。Docker 守护进程需要根权限，所以我们需要特别留意谁可以访问该进程，以及进程驻留在哪个位置



折中解决方案
-  由于频发的安全及逃逸漏洞，在公有云环境容器应用不得不也运行在虚拟机中，从而满足多租户安全隔离要求。而分配、管理、运维这些传统虚拟机与容器轻量、灵活、弹性的初衷背道而驰，同时在资源利用率、运行效率上也存浪费。

## 引用
@article{merkel2014docker,
  title={Docker: lightweight linux containers for consistent development and deployment},
  author={Merkel, Dirk},
  journal={Linux journal},
  volume={2014},
  number={239},
  pages={2},
  year={2014}
}


@article{combe2016docker,
  title={To docker or not to docker: A security perspective},
  author={Combe, Theo and Martin, Antony and Di Pietro, Roberto},
  journal={IEEE Cloud Computing},
  volume={3},
  number={5},
  pages={54--62},
  year={2016},
  publisher={IEEE}
}


当处于非特权模式，并启用SELinux时较为安全

cgroup和namespace能提供较为安全的保障

特权模式下运行容器,则可以访问任意设备:当攻击/dev/mem, /dev/sd∗，/dev/tty导致严重后果
@article{bui2015analysis,
  title={Analysis of docker security},
  author={Bui, Thanh},
  journal={arXiv preprint arXiv:1501.02967},
  year={2015}
}