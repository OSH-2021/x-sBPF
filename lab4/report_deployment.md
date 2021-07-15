# Ceph 部署说明文档

## 1.单机版部署（树莓派版本）
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


**修改/etc/hosts**
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
## 2.分布式部署（树莓派版本）



