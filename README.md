# Linux Privilege Escalation

## 项目介绍

### 1.我的初衷

关于本项目 `Linux Privilege Escalation` 基于`Python`编写，其中调用了大量的`os`模块，在执行效果方面望海涵！

由于网上的提权程序均存在纰漏(至少我这么认为)，因此想自己开发一个程序，对`SUID` `SUDO` `内核溢出`三种权限进行检测，在Linux中寻找可进行提权的方式（存在可能性的方式）

本程序参考以下程序的开发

[*PEASS-ng*](https://github.com/carlospolop/PEASS-ng)
[*smart-en*](https://github.com/diego-treitos/linux-smart-enumeration)
[*CVE*](https://github.com/SecWiki/linux-kernel-exploits)
[*les-res*](https://github.com/mzet-/les-res/tree/master/)
[*les*](https://github.com/mzet-/linux-exploit-suggester)

---

### 2.文件架构 

```shell
-[+]-main.py{提供主程序调用}
 [+]-exploit.json{记录各种漏洞的文献资料，方便查阅利用}
 [+]-SUID.py{SUID权限文件的搜索查找}
```

---

### 3.功能性（初期开发）

- 本地对 `Kernel Linux` `SUID` 版本进行检测，尝试寻找存在的漏洞，并输出下载地址，利用文章
- 调用`githubAPI`查询可能存在的漏洞（并不一定准确）
- 本地寻找 `SUID` `Logs` `Backup` `Server`，逐一查找可用于进行提权的文件，服务，日志泄露

### 4.参数介绍

```shell
➜ python3 main.py --help | more
   -V	--version	#输出当前程序的版本信息
   -H	--help		#输出此页面信息
   -C	--CVE-check #只检测CVE漏洞
   -G	--GithubAPI <args>	#调用githubapi进行漏洞探测 调用github可能需要进行FQ服务
   -I	--info		#输出操作系统版本信息，默认打开
   -A	--All		#进行所有的探测
   -LS	--Local-SUID	#本地进行SUID检测
   -LB	--Local-Backups	#本地进行备份文件检测
   -LL	--Local-logs	#本地寻找日志文件
   -LE	--Local-Server	#本地寻找启动服务
   -LA	--Local-ALL 	#本地启动所有的文件检测
```

`-V`:print（程序版本）即可

`-H`:输出以上信息

`-C`:调用Linux.CVE 调用 `linux.systeminfo()` `linux.ckeck_CVE()`

`-G`: 需要跟一个参数 $query=<查询语句>, `linux.Github_CVE(query)`

 `-I`:调用`linux.systeminfo()`

`-A`：调用全部参数 `linux.systeminfo()`，`linux.check_CVE()`，`find.SUID_CVE()`,`find_backup()`,`find.serice()`,`find_logs()`

`-LS`: ` linux_systeminfo()`,`find_SUID_CVE()`

`-LB`:` linux_systeminfo()`,`find_backup()`

`-LE`:` linux_systeminfo()`,`find_Service()`

`-LL`：`linux_systeminfo()`,`find_Logs()`

`-LA`:`find.SUID_CVE()`,`find_backup()`,`find.serice()`,`find_logs()`

### 5.输出信息

`蓝色字体`：为程序执行信息

`绿色字体`：为程序性执行结果

---

```tex
[!]：需要重点关注的信息
[+]:程序基础执行信息
```





