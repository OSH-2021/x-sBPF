
## 1.树莓派单节点部署
---
安装方式：ceph-deploy

硬件：树莓派 model 3，sd卡

软件：raspbian os

---

**磁盘分区**

将sd卡分出3个逻辑分区用于osd(如mmcblk0p5,mmcblk0p6,mmcblk0p7)
```
$ fdisk /dev/mmcblk0
```
*PS：若sd卡中的启动分区和根文件系统分区占用了所有空间，则需要在另一台拥有gui的Linux环境下使用gparted来重新规划sd卡的分区*


**配置ip地址**
- 查看本机ip地址
```
$ ifconfig
```
- 修改{hostname}对应地址项
```
$ sudo vim /etc/hosts
```
- 其中{hostname}可以通过uname命令查看
```
$ uname -n
raspberrypi
```

**安装ceph-deploy**
```
$ wget -q -O- 'https://download.ceph.com/keys/release.asc' | sudo apt-key add -
$ echo deb https://download.ceph.com/debian-luminous/ $(lsb_release -sc) main | sudo tee /etc/apt/sources.list.d/ceph.list
$ sudo apt update
$ sudo apt -y install ceph-deploy
```
---

**开始部署新集群**
```
$ mkdir myceph
$ cd myceph
$ ceph-deploy new {hostname}
```

**修改配置文件**
```
$ echo "osd pool default size = 1" >> ceph.conf
$ echo "osd pool default min size = 1" >> ceph.conf
```
**安装ceph**
```
$ ceph-deploy install --release luminous {hostname}
```
**部署 mon**
```
$ ceph-deploy mon create-initial
```
**分发配置和密钥**
```
$ ceph-deploy admin {hostname}
```
**部署mgr**
```
$ ceph-deploy mgr create {hostname}
```
**部署osd**
```
$ pvcreate /dev/mmcblk0p5
$ vgcreate ceph-pool5 /dev/mmcblk0p5
$ lvcreate -n osd0.wal -L 1G ceph-pool5
$ lvcreate -n osd0.db -L 1G ceph-pool5
$ lvcreate -n osd0 -l 100%FREE ceph-pool5

$ ceph-deploy osd create \
--data ceph-pool5/osd0 \
--block-db ceph-pool5/osd0.db \
--block-wal ceph-pool5/osd0.wal \
--bluestore {hostname}
```

**部署rgw**
```
ceph-deploy rgw create {hostname}
```
**部署mds**
```
ceph-deploy mds create {hostname}
```


**查看部署状态**
```
# ceph -s
# ceph osd tree
```


---
## 2.树莓派分布式部署
---
安装方式：ceph-deploy

硬件：3x树莓派model3，sd卡

软件：raspbian os

---
**磁盘分区**

同单机版，在3个树莓派上的sd卡分区出mmcblk0p3作为osd

**配置ip地址**

为了方便，先修改3块树莓派的hostname为node0,node1,node2
```
# echo node0 > /etc/hostname
```
通过ifconfig查看3台树莓派ip地址，例如

```
192.168.137.141     node0
192.168.137.36      node1
192.168.137.21      node2
```
将上述3项添加入/etc/hosts文件
```
# vim /etc/hosts
```
重启使得新hostname生效
```
# reboot
```
*PS：可以相互ping node0/1/2来测试是否修改成功*

**添加辅助用户ceph-sbpf**
```
# useradd -d /home/ceph-sbpf -m ceph-sbpf
# passwd ceph-sbpf
# echo "ceph-sbpf ALL = (root) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/ceph-sbpf
# chmod 0440 /etc/sudoers.d/ceph-sbpf
```
因为ceph-deploy需要一个无需输入密码即可sudo的用户，所以添加此辅助用户

**配置ssh**

```
$ ssh-keygen
$ vim ~/.ssh/config
```
将以下内容下入ssh配置文件
```
Host node0
	Hostname node0
	User ceph-sbpf
Host node1
	Hostname node1
	User ceph-sbpf
Host node2
	Hostname node2
	User ceph-sbpf
```
拷贝公钥至各个节点
```
ssh-copy-id ceph-sbpf@node0
ssh-copy-id ceph-sbpf@node1
ssh-copy-id ceph-sbpf@node2

```

---
**初始化集群**
```
$ mkdir myceph
$ cd myceph
$ ceph-deploy new node2
```

**修改配置文件**
```
echo "osd pool default size = 2" >> ceph.conf
```

**安装ceph**
```
ceph-deploy install node0 node1 node2 
```

**部署mon**
```
$ ceph-deploy mon create-initial
```
在node2上进行（node2为mon节点）

**分发配置和密钥**
```
$ ceph-deploy admin node0 node1 node2
```

**部署mgr**
```
$ ceph-deploy mgr create node2
```

**部署osd**

对3个树莓派上的分区分别进行格式化
```
# sudo parted -s /dev/mmcblk0p3 mklabel gpt mkpart primary xfs 0% 100%
# reboot
# mkfs.xfs /dev/mmcblk0p3 -f
```
创建为osd
```
ceph-deploy osd create --bluestore node0 --data /dev/mmcblk0p3
ceph-deploy osd create --bluestore node1 --data /dev/mmcblk0p3
ceph-deploy osd create --bluestore node2 --data /dev/mmcblk0p3

```

**查看部署状态**
```
# ceph -s
# ceph osd tree
```

---