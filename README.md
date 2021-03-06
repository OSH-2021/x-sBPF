# x-sBPF

## Sandbox with BPF

本组的项目是一个轻量级的文件系统沙盒，通过劫持文件访问相关的系统调用，实现对文件的保护。项目的特色在于本项目的沙盒程序是一段动态植入内核空间的kernel代码，可以最小化反复切换特权级别带来的性能损失，并且保留了用户态程序级别的自由度和灵活性。本项目目前已经在同一个框架下实现了三种不同的文件保护模式，可以灵活地为使用者选择，满足不同类型的数据保护需要。本项目还通过引入cgroup，实现了进程资源分配的限制，提高了对系统的整体保护。

## Group Members
- 陈思睿
- 梁恒宇
- 吕泓涛
- 汤力宇

## 文件夹说明
- `BPF`: 存放一个可用于读取`openat`系统调用传入参数`filename`的`BPF`程序
- `feasibility`: 可行性报告
- `final`: 结题答辩+结题报告
- `lab4`: 实验四仓库
- `mid`: 中期报告PPT
- `report`: 调研报告
- `research`: 调研内容存放的文件夹
- `test_module`: 内核模块、测试程序源代码、加载程序源代码存放文件夹

## LaTex文档的编译
文档的编译需要用到`XeLaTeX`，如果文档中使用了`BibTeX`做文献引用，则需要使用`XeLaTeX->BibTeX->XeLaTeX->XeLaTeX`进行四遍编译。

`beamer`类型可能需要使用`XeLaTeX`进行两次以上的编译以校正页码等信息。

## 使用说明
要正确运行这个项目，首先需要编译并更换Linux内核。本仓库的Linux修改源代码位于`OSH-2021/linux-stable`，从Linux`5.8.18`版本修改而来。

### 编译并更换内核
`sBPF`仓库中的内核模块不断在更新，模块相对应的内核代码也在更新。要想正确运行内核模块，需要编译并更换相对应的内核。使用`git log`可查看comment，部分涉及对内核模块修改的comment中包含内核模块对应的内核提交版本。

编译内核与更换内核不属于本项目的核心重点，所以这里不介绍编译内核以及更换内核的步骤。不同的运行环境下更换内核的方法可能是不同的。但是如果你没有做过这件事的话，完成这个步骤还是会比较困难的。

这个步骤结束后，键入`uname -r`会显示`5.8.18+`。

### 编译内核模块
`sBPF_*.c`为内核模块，直接键入`make`编译。例如，如果要编译`sBPF_cow.c`，需将`Makefile`对应的`obj_m`后改为`sBPF_cow.o`，再使用`make`即可编译。

### 载入内核模块
这一步是将沙盒代码载入到内核中，让沙盒代码运行在内核态，减少用户态、内核态之间切换带来的开销。
#### 手动载入
使用`insmod`即可载入内核模块，让沙盒程序运行在内核态。注意需手动填入`pid`、`u_mem`、`sdir`信息。

手动载入内核模块后，若想结束沙盒的运行，需要使用`rmmod`。
#### 自动载入
编译好`loader.c`，如`gcc loader.c -o loader`。运行`loader`的参数依次为模块地址、沙盒地址、运行的程序及参数，`loader`运行的参数在`loader.c`中也有说明。自动载入后不需要再手动卸载内核模块。

`loader`的运行示例如：`./loader sBPF_cow.ko /home/xxx/sandbox_test ./a.out`