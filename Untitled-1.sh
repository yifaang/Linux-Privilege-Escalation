EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-1959]${txtrst} userns_root_sploit
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<3.8.9
Tags: 
Rank: 1
analysis-url: http://www.openwall.com/lists/oss-security/2013/04/29/1
exploit-db: 25450
EOF
)


EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-2851]${txtrst} use-after-free in ping_init_sock() ${bldblu}(DoS)${txtrst}
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<=3.14
Tags: 
Rank: 0
analysis-url: https://cyseclabs.com/page?n=02012016
exploit-db: 32926
EOF
)



EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-5207]${txtrst} fuse_suid
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<=3.16.1
Tags: 
Rank: 1
exploit-db: 34923
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-9322]${txtrst} BadIRET
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<3.17.5,x86_64
Tags: RHEL<=7,fedora=20
Rank: 1
analysis-url: http://labs.bromium.com/2015/02/02/exploiting-badiret-vulnerability-cve-2014-9322-linux-kernel-privilege-escalation/
src-url: http://site.pi3.com.pl/exp/p_cve-2014-9322.tar.gz
exploit-db:
author: Rafal 'n3rgal' Wojtczuk & Adam 'pi3' Zabrocki
EOF
)



EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-8660]${txtrst} overlayfs (ovl_setattr)
Reqs: pkg=linux-kernel,ver>=3.0.0,ver<=4.3.3
Tags: ubuntu=(14.04|15.10){kernel:4.2.0-(18|19|20|21|22)-generic}
Rank: 1
analysis-url: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
exploit-db: 39166
EOF
)


EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-4997]${txtrst} target_offset
Reqs: pkg=linux-kernel,ver>=4.4.0,ver<=4.4.0,cmd:grep -qi ip_tables /proc/modules
Tags: ubuntu=16.04{kernel:4.4.0-21-generic}
Rank: 1
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/40053.zip
Comments: ip_tables.ko needs to be loaded
exploit-db: 40049
author: Vitaly 'vnik' Nikolenko
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-4557]${txtrst} double-fdput()
Reqs: pkg=linux-kernel,ver>=4.4,ver<4.5.5,CONFIG_BPF_SYSCALL=y,sysctl:kernel.unprivileged_bpf_disabled!=1
Tags: ubuntu=16.04{kernel:4.4.0-(21|38|42|98|140)-generic}
Rank: 1
analysis-url: https://bugs.chromium.org/p/project-zero/issues/detail?id=808
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/39772.zip
Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1
exploit-db: 40759
author: Jann Horn
EOF
)


EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-8655]${txtrst} chocobo_root
Reqs: pkg=linux-kernel,ver>=4.4.0,ver<4.9,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1
Tags: ubuntu=(14.04|16.04){kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic}
Rank: 1
analysis-url: http://www.openwall.com/lists/oss-security/2016/12/06/1
Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled
bin-url: https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/exploits/CVE-2016-8655/chocobo_root
exploit-db: 40871
author: rebel
EOF
)

------------------------------------------------------------------->
EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000253]${txtrst} PIE_stack_corruption
Reqs: pkg=linux-kernel,ver>=3.2,ver<=4.13,x86_64
Tags: RHEL=6,RHEL=7{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
Rank: 1
analysis-url: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
src-url: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c
exploit-db: 42887
author: Qualys
Comments:
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2018-5333]${txtrst} rds_atomic_free_op NULL pointer dereference
Reqs: pkg=linux-kernel,ver>=4.4,ver<=4.14.13,cmd:grep -qi rds /proc/modules,x86_64
Tags: ubuntu=16.04{kernel:4.4.0|4.8.0}
Rank: 1
src-url: https://gist.githubusercontent.com/wbowling/9d32492bd96d9e7c3bf52e23a0ac30a4/raw/959325819c78248a6437102bb289bb8578a135cd/cve-2018-5333-poc.c
ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2018-5333/cve-2018-5333.c
Comments: rds.ko kernel module needs to be loaded. Modified version at 'ext-url' adds support for additional targets and bypassing KASLR.
author: wbowling (orginal exploit author); bcoles (author of exploit update at 'ext-url')
EOF
)




EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-13272]${txtrst} PTRACE_TRACEME
Reqs: pkg=linux-kernel,ver>=4,ver<5.1.17,sysctl:kernel.yama.ptrace_scope==0,x86_64
Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},debian=10{kernel:4.19.0-*},fedora=30{kernel:5.0.9-*}
Rank: 1
analysis-url: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
src-url: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47133.zip
ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
Comments: Requires an active PolKit agent.
exploit-db: 47133
exploit-db: 47163
author: Jann Horn (orginal exploit author); bcoles (author of exploit update at 'ext-url')
EOF
)
-------------------------------------------------------------------------------------------------------

############ USERSPACE EXPLOITS ###########################
n=0

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-0186]${txtrst} samba
Reqs: pkg=samba,ver<=2.2.8
Tags: 
Rank: 1
exploit-db: 23674
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-1185]${txtrst} udev
Reqs: pkg=udev,ver<141,cmd:[[ -f /etc/udev/rules.d/95-udev-late.rules || -f /lib/udev/rules.d/95-udev-late.rules ]]
Tags: ubuntu=8.10|9.04
Rank: 1
exploit-db: 8572
Comments: Version<1.4.1 vulnerable but distros use own versioning scheme. Manual verification needed 
EOF
)



EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-0832]${txtrst} PAM MOTD
Reqs: pkg=libpam-modules,ver<=1.1.1
Tags: ubuntu=9.10|10.04
Rank: 1
exploit-db: 14339
Comments: SSH access to non privileged user is needed
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-4170]${txtrst} SystemTap
Reqs: pkg=systemtap,ver<=1.3
Tags: RHEL=5{systemtap:1.1-3.el5},fedora=13{systemtap:1.2-1.fc13}
Rank: 1
author: Tavis Ormandy
exploit-db: 15620
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2011-1485]${txtrst} pkexec
Reqs: pkg=polkit,ver=0.96
Tags: RHEL=6,ubuntu=10.04|10.10
Rank: 1
exploit-db: 17942
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2011-2921]${txtrst} ktsuss
Reqs: pkg=ktsuss,ver<=1.4
Tags: sparky=5|6
Rank: 1
analysis-url: https://www.openwall.com/lists/oss-security/2011/08/13/2
src-url: https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2011-2921/ktsuss-lpe.sh
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2012-0809]${txtrst} death_star (sudo)
Reqs: pkg=sudo,ver>=1.8.0,ver<=1.8.3
Tags: fedora=16 
Rank: 1
analysis-url: http://seclists.org/fulldisclosure/2012/Jan/att-590/advisory_sudo.txt
exploit-db: 18436
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-0476]${txtrst} chkrootkit
Reqs: pkg=chkrootkit,ver<0.50
Tags: 
Rank: 1
analysis-url: http://seclists.org/oss-sec/2014/q2/430
exploit-db: 33899
Comments: Rooting depends on the crontab (up to one day of delay)
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-5119]${txtrst} __gconv_translit_find
Reqs: pkg=glibc|libc6,x86
Tags: debian=6
Rank: 1
analysis-url: http://googleprojectzero.blogspot.com/2014/08/the-poisoned-nul-byte-2014-edition.html
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/34421.tar.gz
exploit-db: 34421
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1862]${txtrst} newpid (abrt)
Reqs: pkg=abrt,cmd:grep -qi abrt /proc/sys/kernel/core_pattern
Tags: fedora=20
Rank: 1
analysis-url: http://openwall.com/lists/oss-security/2015/04/14/4
src-url: https://gist.githubusercontent.com/taviso/0f02c255c13c5c113406/raw/eafac78dce51329b03bea7167f1271718bee4dcc/newpid.c
exploit-db: 36746
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-3315]${txtrst} raceabrt
Reqs: pkg=abrt,cmd:grep -qi abrt /proc/sys/kernel/core_pattern
Tags: fedora=19{abrt:2.1.5-1.fc19},fedora=20{abrt:2.2.2-2.fc20},fedora=21{abrt:2.3.0-3.fc21},RHEL=7{abrt:2.1.11-12.el7}
Rank: 1
analysis-url: http://seclists.org/oss-sec/2015/q2/130
src-url: https://gist.githubusercontent.com/taviso/fe359006836d6cd1091e/raw/32fe8481c434f8cad5bcf8529789231627e5074c/raceabrt.c
exploit-db: 36747
author: Tavis Ormandy
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1318]${txtrst} newpid (apport)
Reqs: pkg=apport,ver>=2.13,ver<=2.17,cmd:grep -qi apport /proc/sys/kernel/core_pattern
Tags: ubuntu=14.04
Rank: 1
analysis-url: http://openwall.com/lists/oss-security/2015/04/14/4
src-url: https://gist.githubusercontent.com/taviso/0f02c255c13c5c113406/raw/eafac78dce51329b03bea7167f1271718bee4dcc/newpid.c
exploit-db: 36746
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-3202]${txtrst} fuse (fusermount)
Reqs: pkg=fuse,ver<2.9.3
Tags: debian=7.0|8.0,ubuntu=*
Rank: 1
analysis-url: http://seclists.org/oss-sec/2015/q2/520
exploit-db: 37089
Comments: Needs cron or system admin interaction
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1815]${txtrst} setroubleshoot
Reqs: pkg=setroubleshoot,ver<3.2.22
Tags: fedora=21
Rank: 1
exploit-db: 36564
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-3246]${txtrst} userhelper
Reqs: pkg=libuser,ver<=0.60
Tags: RHEL=6{libuser:0.56.13-(4|5).el6},RHEL=6{libuser:0.60-5.el7},fedora=13|19|20|21|22
Rank: 1
analysis-url: https://www.qualys.com/2015/07/23/cve-2015-3245-cve-2015-3246/cve-2015-3245-cve-2015-3246.txt 
exploit-db: 37706
Comments: RHEL 5 is also vulnerable, but installed version of glibc (2.5) lacks functions needed by roothelper.c
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-5287]${txtrst} abrt/sosreport-rhel7
Reqs: pkg=abrt,cmd:grep -qi abrt /proc/sys/kernel/core_pattern
Tags: RHEL=7{abrt:2.1.11-12.el7}
Rank: 1
analysis-url: https://www.openwall.com/lists/oss-security/2015/12/01/1
src-url: https://www.openwall.com/lists/oss-security/2015/12/01/1/1
exploit-db: 38832
author: rebel
EOF
)
---------------------------------------------------------------------------------------


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-6565]${txtrst} not_an_sshnuke
Reqs: pkg=openssh-server,ver>=6.8,ver<=6.9
Tags:
Rank: 1
analysis-url: http://www.openwall.com/lists/oss-security/2017/01/26/2
exploit-db: 41173
author: Federico Bento
Comments: Needs admin interaction (root user needs to login via ssh to trigger exploitation)
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-8612]${txtrst} blueman set_dhcp_handler d-bus privesc
Reqs: pkg=blueman,ver<2.0.3
Tags: debian=8{blueman:1.23}
Rank: 1
analysis-url: https://twitter.com/thegrugq/status/677809527882813440
exploit-db: 46186
author: Sebastian Krahmer
Comments: Distros use own versioning scheme. Manual verification needed.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1240]${txtrst} tomcat-rootprivesc-deb.sh
Reqs: pkg=tomcat
Tags: debian=8,ubuntu=16.04
Rank: 1
analysis-url: https://legalhackers.com/advisories/Tomcat-DebPkgs-Root-Privilege-Escalation-Exploit-CVE-2016-1240.html
src-url: http://legalhackers.com/exploits/tomcat-rootprivesc-deb.sh
exploit-db: 40450
author: Dawid Golunski
Comments: Affects only Debian-based distros
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1247]${txtrst} nginxed-root.sh
Reqs: pkg=nginx|nginx-full,ver<1.10.3
Tags: debian=8,ubuntu=14.04|16.04|16.10
Rank: 1
analysis-url: https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
src-url: https://legalhackers.com/exploits/CVE-2016-1247/nginxed-root.sh
exploit-db: 40768
author: Dawid Golunski
Comments: Rooting depends on cron.daily (up to 24h of delay). Affected: deb8: <1.6.2; 14.04: <1.4.6; 16.04: 1.10.0; gentoo: <1.10.2-r3
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1531]${txtrst} perl_startup (exim)
Reqs: pkg=exim,ver<4.86.2
Tags: 
Rank: 1
analysis-url: http://www.exim.org/static/doc/CVE-2016-1531.txt
exploit-db: 39549
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-5425]${txtrst} tomcat-RH-root.sh
Reqs: pkg=tomcat
Tags: RHEL=7
Rank: 1
analysis-url: http://legalhackers.com/advisories/Tomcat-RedHat-Pkgs-Root-PrivEsc-Exploit-CVE-2016-5425.html
src-url: http://legalhackers.com/exploits/tomcat-RH-root.sh
exploit-db: 40488
author: Dawid Golunski
Comments: Affects only RedHat-based distros
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-6663,CVE-2016-6664|CVE-2016-6662]${txtrst} mysql-exploit-chain
Reqs: pkg=mysql-server|mariadb-server,ver<5.5.52
Tags: ubuntu=16.04.1
Rank: 1
analysis-url: https://legalhackers.com/advisories/MySQL-Maria-Percona-PrivEscRace-CVE-2016-6663-5616-Exploit.html
src-url: http://legalhackers.com/exploits/CVE-2016-6663/mysql-privesc-race.c
exploit-db: 40678
author: Dawid Golunski
Comments: Also MariaDB ver<10.1.18 and ver<10.0.28 affected
EOF
)



EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-9566]${txtrst} nagios-root-privesc
Reqs: pkg=nagios,ver<4.2.4
Tags:
Rank: 1
analysis-url: https://legalhackers.com/advisories/Nagios-Exploit-Root-PrivEsc-CVE-2016-9566.html
src-url: https://legalhackers.com/exploits/CVE-2016-9566/nagios-root-privesc.sh
exploit-db: 40921
author: Dawid Golunski
Comments: Allows priv escalation from nagios user or nagios group
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-0358]${txtrst} ntfs-3g-modprobe
Reqs: pkg=ntfs-3g,ver<2017.4
Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
Rank: 1
analysis-url: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
exploit-db: 41356
author: Jann Horn
Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-5899]${txtrst} s-nail-privget
Reqs: pkg=s-nail,ver<14.8.16
Tags: ubuntu=16.04,manjaro=16.10
Rank: 1
analysis-url: https://www.openwall.com/lists/oss-security/2017/01/27/7
src-url: https://www.openwall.com/lists/oss-security/2017/01/27/7/1
ext-url: https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2017-5899/exploit.sh
author: wapiflapi (orginal exploit author); Brendan Coles (author of exploit update at 'ext-url')
Comments: Distros use own versioning scheme. Manual verification needed.
EOF
)




EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000366,CVE-2017-1000370]${txtrst} linux_ldso_hwcap
Reqs: pkg=glibc|libc6,ver<=2.25,x86
Tags:
Rank: 1
analysis-url: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
src-url: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap.c
exploit-db: 42274
author: Qualys
Comments: Uses "Stack Clash" technique, works against most SUID-root binaries
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000366,CVE-2017-1000371]${txtrst} linux_ldso_dynamic
Reqs: pkg=glibc|libc6,ver<=2.25,x86
Tags: debian=9|10,ubuntu=14.04.5|16.04.2|17.04,fedora=23|24|25
Rank: 1
analysis-url: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
src-url: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_dynamic.c
exploit-db: 42276
author: Qualys
Comments: Uses "Stack Clash" technique, works against most SUID-root PIEs
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000366,CVE-2017-1000379]${txtrst} linux_ldso_hwcap_64
Reqs: pkg=glibc|libc6,ver<=2.25,x86_64
Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
Rank: 1
analysis-url: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
src-url: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
exploit-db: 42275
author: Qualys
Comments: Uses "Stack Clash" technique, works against most SUID-root binaries
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000370,CVE-2017-1000371]${txtrst} linux_offset2lib
Reqs: pkg=glibc|libc6,ver<=2.25,x86
Tags:
Rank: 1
analysis-url: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
src-url: https://www.qualys.com/2017/06/19/stack-clash/linux_offset2lib.c
exploit-db: 42273
author: Qualys
Comments: Uses "Stack Clash" technique
EOF
)




EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2018-10900]${txtrst} vpnc_privesc.py
Reqs: pkg=networkmanager-vpnc|network-manager-vpnc,ver<1.2.6
Tags: ubuntu=16.04{network-manager-vpnc:1.1.93-1},debian=9.0{network-manager-vpnc:1.2.4-4},manjaro=17
Rank: 1
analysis-url: https://pulsesecurity.co.nz/advisories/NM-VPNC-Privesc
src-url: https://bugzilla.novell.com/attachment.cgi?id=779110
exploit-db: 45313
author: Denis Andzakovic
Comments: Distros use own versioning scheme. Manual verification needed.
EOF
)


EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2018-14665]${txtrst} raptor_xorgy
Reqs: pkg=xorg-x11-server-Xorg,cmd:[ -u /usr/bin/Xorg ]
Tags: centos=7.4
Rank: 1
analysis-url: https://www.securepatterns.com/2018/10/cve-2018-14665-xorg-x-server.html
exploit-db: 45922
author: raptor
Comments: X.Org Server before 1.20.3 is vulnerable. Distros use own versioning scheme. Manual verification needed.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-7304]${txtrst} dirty_sock
Reqs: pkg=snapd,ver<2.37,cmd:[ -S /run/snapd.socket ]
Tags: ubuntu=18.10,mint=19
Rank: 1
analysis-url: https://initblog.com/2019/dirty-sock/
exploit-db: 46361
exploit-db: 46362
src-url: https://github.com/initstring/dirty_sock/archive/master.zip
author: InitString
Comments: Distros use own versioning scheme. Manual verification needed.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-10149]${txtrst} raptor_exim_wiz
Reqs: pkg=exim|exim4,ver>=4.87,ver<=4.91
Tags:
Rank: 1
analysis-url: https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt
exploit-db: 46996
author: raptor
EOF
)
-------------------------------------------------------------------------------------------------

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-12181]${txtrst} Serv-U FTP Server
Reqs: cmd:[ -u /usr/local/Serv-U/Serv-U ]
Tags: debian=9
Rank: 1
analysis-url: https://blog.vastart.dev/2019/06/cve-2019-12181-serv-u-exploit-writeup.html
exploit-db: 47009
src-url: https://raw.githubusercontent.com/guywhataguy/CVE-2019-12181/master/servu-pe-cve-2019-12181.c
ext-url: https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-12181/SUroot
author: Guy Levin (orginal exploit author); Brendan Coles (author of exploit update at 'ext-url')
Comments: Modified version at 'ext-url' uses bash exec technique, rather than compiling with gcc.
EOF
)
EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-18862]${txtrst} GNU Mailutils 2.0 <= 3.7 maidag url local root (CVE-2019-18862)
Reqs: cmd:[ -u /usr/local/sbin/maidag ]
Tags: 
Rank: 1
analysis-url: https://www.mike-gualtieri.com/posts/finding-a-decade-old-flaw-in-gnu-mailutils
ext-url: https://github.com/bcoles/local-exploits/raw/master/CVE-2019-18862/exploit.cron.sh
src-url: https://github.com/bcoles/local-exploits/raw/master/CVE-2019-18862/exploit.ldpreload.sh
author: bcoles
EOF
)

###########################################################
## security related HW/kernel features
###########################################################
n=0

FEATURES[((n++))]=$(cat <<EOF
section: Mainline kernel protection mechanisms:
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Kernel Page Table Isolation (PTI) support
available: ver>=4.15
enabled: cmd:grep -Eqi '\spti' /proc/cpuinfo
analysis-url: https://github.com/mzet-/les-res/blob/master/features/pti.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: GCC stack protector support
available: CONFIG_HAVE_STACKPROTECTOR=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/stackprotector-regular.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: GCC stack protector STRONG support
available: CONFIG_STACKPROTECTOR_STRONG=y,ver>=3.14
analysis-url: https://github.com/mzet-/les-res/blob/master/features/stackprotector-strong.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Low address space to protect from user allocation
available: CONFIG_DEFAULT_MMAP_MIN_ADDR=[0-9]+
enabled: sysctl:vm.mmap_min_addr!=0
analysis-url: https://github.com/mzet-/les-res/blob/master/features/mmap_min_addr.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Prevent users from using ptrace to examine the memory and state of their processes
available: CONFIG_SECURITY_YAMA=y
enabled: sysctl:kernel.yama.ptrace_scope!=0
analysis-url: https://github.com/mzet-/les-res/blob/master/features/yama_ptrace_scope.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Restrict unprivileged access to kernel syslog
available: CONFIG_SECURITY_DMESG_RESTRICT=y,ver>=2.6.37
enabled: sysctl:kernel.dmesg_restrict!=0
analysis-url: https://github.com/mzet-/les-res/blob/master/features/dmesg_restrict.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Randomize the address of the kernel image (KASLR)
available: CONFIG_RANDOMIZE_BASE=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/kaslr.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Hardened user copy support
available: CONFIG_HARDENED_USERCOPY=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/hardened_usercopy.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Make kernel text and rodata read-only
available: CONFIG_STRICT_KERNEL_RWX=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/strict_kernel_rwx.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Set loadable kernel module data as NX and text as RO
available: CONFIG_STRICT_MODULE_RWX=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/strict_module_rwx.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: BUG() conditions reporting
available: CONFIG_BUG=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/bug.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Additional 'cred' struct checks
available: CONFIG_DEBUG_CREDENTIALS=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/debug_credentials.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Sanity checks for notifier call chains
available: CONFIG_DEBUG_NOTIFIERS=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/debug_notifiers.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Extended checks for linked-lists walking
available: CONFIG_DEBUG_LIST=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/debug_list.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Checks on scatter-gather tables
available: CONFIG_DEBUG_SG=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/debug_sg.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Checks for data structure corruptions
available: CONFIG_BUG_ON_DATA_CORRUPTION=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/bug_on_data_corruption.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Checks for a stack overrun on calls to 'schedule'
available: CONFIG_SCHED_STACK_END_CHECK=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/sched_stack_end_check.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Freelist order randomization on new pages creation
available: CONFIG_SLAB_FREELIST_RANDOM=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/slab_freelist_random.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Freelist metadata hardening
available: CONFIG_SLAB_FREELIST_HARDENED=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/slab_freelist_hardened.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Allocator validation checking
available: CONFIG_SLUB_DEBUG_ON=y,cmd:! grep 'slub_debug=-' /proc/cmdline
analysis-url: https://github.com/mzet-/les-res/blob/master/features/slub_debug.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Virtually-mapped kernel stacks with guard pages
available: CONFIG_VMAP_STACK=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/vmap_stack.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Pages poisoning after free_pages() call
available: CONFIG_PAGE_POISONING=y
enabled: cmd: grep 'page_poison=1' /proc/cmdline
analysis-url: https://github.com/mzet-/les-res/blob/master/features/page_poisoning.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Using 'refcount_t' instead of 'atomic_t'
available: CONFIG_REFCOUNT_FULL=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/refcount_full.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Hardening common str/mem functions against buffer overflows
available: CONFIG_FORTIFY_SOURCE=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/fortify_source.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Restrict /dev/mem access
available: CONFIG_STRICT_DEVMEM=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/strict_devmem.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Restrict I/O access to /dev/mem
available: CONFIG_IO_STRICT_DEVMEM=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/io_strict_devmem.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
section: Hardware-based protection features:
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Supervisor Mode Execution Protection (SMEP) support
available: ver>=3.0
enabled: cmd:grep -qi smep /proc/cpuinfo
analysis-url: https://github.com/mzet-/les-res/blob/master/features/smep.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Supervisor Mode Access Prevention (SMAP) support
available: ver>=3.7
enabled: cmd:grep -qi smap /proc/cpuinfo
analysis-url: https://github.com/mzet-/les-res/blob/master/features/smap.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
section: 3rd party kernel protection mechanisms:
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Grsecurity
available: CONFIG_GRKERNSEC=y
enabled: cmd:test -c /dev/grsec
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: PaX
available: CONFIG_PAX=y
enabled: cmd:test -x /sbin/paxctl
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Linux Kernel Runtime Guard (LKRG) kernel module
enabled: cmd:test -d /proc/sys/lkrg
analysis-url: https://github.com/mzet-/les-res/blob/master/features/lkrg.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
section: Attack Surface:
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: User namespaces for unprivileged accounts
available: CONFIG_USER_NS=y
enabled: sysctl:kernel.unprivileged_userns_clone==1
analysis-url: https://github.com/mzet-/les-res/blob/master/features/user_ns.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Unprivileged access to bpf() system call
available: CONFIG_BPF_SYSCALL=y
enabled: sysctl:kernel.unprivileged_bpf_disabled!=1
analysis-url: https://github.com/mzet-/les-res/blob/master/features/bpf_syscall.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Syscalls filtering
available: CONFIG_SECCOMP=y
enabled: cmd:grep -i Seccomp /proc/self/status | awk '{print \$2}'
analysis-url: https://github.com/mzet-/les-res/blob/master/features/bpf_syscall.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Support for /dev/mem access
available: CONFIG_DEVMEM=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/devmem.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Support for /dev/kmem access
available: CONFIG_DEVKMEM=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/devkmem.md
EOF
)
