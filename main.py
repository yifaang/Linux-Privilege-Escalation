#!/usr/bin/env python3
#-*- codeing:utf-8 -*-
import subprocess,json,re,time,sys,requests
from colorama import init,Fore
from optparse import OptionParser
init(autoreset=True)

class kernel:                                                               #初始化获得操作系统信息
    # linuxinfo_dic={'Kernel Version':'',
    #                'Sudo location':'',
    #                'uname location':'',
    #                'lsb_release':''}
    def __init__(self):
        self.cve_dic = self.import_json()
        self.linuxinfo_dic={'Kernel Version':'',                            #输出到一个字典当中
                            'sudo':'',
                            'sudo Verison':'',
                            'uname':'',
                            'lsb_release':'',}
        kernel_Version = subprocess.Popen('uname -r', shell=True, stdout=subprocess.PIPE)
        sudo = subprocess.Popen('which sudo',shell=True,stdout=subprocess.PIPE)
        sudo_version = subprocess.Popen('sudo -V', shell=True, stdout=subprocess.PIPE)
        uname = subprocess.Popen('uname -a',shell=True,stdout=subprocess.PIPE)
        lsb_release = subprocess.Popen('lsb_release -a',shell=True,stdout=subprocess.PIPE)
        self.linuxinfo_dic['Kernel Version'] = bytes.decode(kernel_Version.stdout.read()).replace('\n','')
        self.linuxinfo_dic['sudo'] =  bytes.decode(sudo.stdout.read()).replace('\n','')
        self.linuxinfo_dic['sudo Version'] = bytes.decode(sudo_version.stdout.read()).replace('\n','\n\t')
        self.linuxinfo_dic['uname'] = bytes.decode(uname.stdout.read())
        self.linuxinfo_dic['lsb_release'] = bytes.decode(lsb_release.stdout.read()).replace('\n','\n\t')

    def systeminfo(self):                                                   #工具启动时进行当前版本信息显示
        print(Fore.BLUE+'[!][Linux System Information]')
        print('[+]The Sytem Kernel Version is \n\t' + Fore.GREEN+self.linuxinfo_dic['Kernel Version'])
        print('[+]The Sudo is in: \n\t' + Fore.GREEN+self.linuxinfo_dic['sudo'])
        print('[+]SUDO Version: \n\t' + Fore.GREEN+self.linuxinfo_dic['sudo Version'])
        print('[+]System name: \n\t' + Fore.GREEN+self.linuxinfo_dic['uname'])
        print('[+]GNU/Linux Info: \n\t'+Fore.GREEN+self.linuxinfo_dic['lsb_release'])
        print(Fore.CYAN+'-----------------------------------------------------------------------------------------------------------')

    def ckeck_CVE(self):                                                    #检测CVE
        #type 存在 sudo samba kernel
        version = self.linuxinfo_dic['Kernel Version']
        temp_list = re.findall('(\d)\.(.*?)\.(.*?)-',version)
        one,two,three = temp_list[0]
        # for type in self.cve_dic['Kernel Linux']:
        #     print(type)
        self.kernel_CVE_Check(one,two,three)#检查操作系统内核漏洞
        # print(one,two,three)
        #开始循环 便利
        
    def import_json(self):                                                  #导入CVE.json文件
        with open('./exploit.json','r') as f:
            cve_dic = json.loads(f.read())
            return cve_dic

    def Github_CVE(self,query):
        url = 'https://api.github.com/search/repositories?q=' + query + '&sort=updated'
        data = requests.get(url).content.decode('utf-8')
        # print(data)
        datalist = json.loads(data)
        print('Find ' + str((datalist['total_count'])) + ' result')
        for i in range(0, datalist['total_count'] - 1):
            print(datalist['items'][i]['full_name'])

    def kernel_CVE_Check(self,one,two,three):
        # for cve in self.cve_dic:
        print(Fore.BLUE + 'Start the Kernel Linux CVE Check .....')
        for type in self.cve_dic['Kernel Linux']:
            i = 0
            m = 0
            z = 0
            temp_version_list = self.cve_dic['Kernel Linux'][type]['Version']
            for version in temp_version_list:
                # time.sleep(0.1)
                # print(type)
                if '->' not in version:
                    if ('>' not in version) and ('<' not in version):
                        a,b,c = self.GetVersion('kernel',version)
                        if a == one:
                            if (b == two):
                                if (c == three) or (c == '*'):
                                    z+=1
                            elif (b == '*'):
                                z+=1
                            else:
                                pass
                        else:
                            pass
                    else:
                        if '>' in version:
                            l = re.findall('>(\d)\.(.*?)\.', version)
                            m_a_1, m_a_2 = l[0]
                            if (float(str(one)+'.'+str(two)) >= float(str(m_a_1)+'.'+str(m_a_2))):
                                z+=1
                            else:
                                pass
                        elif '<' in version:
                            lb = re.findall('<(\d)\.(.*?)\.', version)
                            m_b_1, m_b_2 = lb[0]
                            if (float(str(one)+'.'+str(two)) <= float(str(m_b_1)+'.'+str(m_b_2))):
                                z+=1
                            else:
                                pass
                else:
                    b = re.findall('(\d)\.(.*?)\.', version)
                    s_a_1,s_a_2 = b[0]
                    s_b_1,s_b_2 = b[1]
                    if (float(str(one)+'.'+str(two)) >= float(str(s_a_1)+'.'+str(s_a_2))) and (float(str(one)+'.'+str(two)) <= float(str(s_b_1)+'.'+str(s_b_2))):
                        z+=1
                    else:
                        pass
            if z >0:
                print(Fore.GREEN+'[!]System hava '+type+'\n ﹂The download is '+(self.cve_dic['Kernel Linux'][type]['Exploition'][0]))

    def GetVersion(self,type,origin):
        origin = str(origin)
        if type == 'kernel':
            origin_list = re.findall('(\d)\.(.*?)\.(.*)',origin)
            a,b,c = origin_list[0]
            return (a,b,c)
            # print(b)
            print(origin_list)
        elif type =='sudo':
            print(Fore.BLUE+'Start check the SUDO CVE......')
        elif type =='samba':
            print(Fore.BLUE+'Start check the samba CVE......')

    def update(self):
        print(Fore.GREEN+"Update the programe!!!")
        find.cmd('git clone https://github.com/yifaang/Linux-Privilege-Escalation.git /usr/share/Linux-Privilege-Escalation/')

    def banner(self):
        print(Fore.GREEN+"                                            ")
        print(Fore.GREEN+"      ╔═╗   ╔═╗  ╔══════════╗                ")
        print(Fore.GREEN+"      ║ ║   ║ ║  ║  ╔═══════╝                ")
        print(Fore.GREEN+"      ║ ╚═══╝ ║  ║  ╚═══════╗                ")
        print(Fore.GREEN+"      ╚══╗ ╔══╝  ║  ╔═══════╝                ")
        print(Fore.GREEN+"         ║ ║     ║  ║     ╔══╗ ╔═══ ╔═══╗    ")
        print(Fore.GREEN+"         ║ ║     ║  ║     ╚══╗ ╠═══ ║        ")
        print(Fore.GREEN+"         ╚═╝     ╚══╝     ╚══╝ ╚═══ ╚═══╝    ")
        print(Fore.GREEN+"                                             ")
        
class linuxfind:
    def __init__(self):
        pass
    def SUID_Check(self):
        print(Fore.BLUE+'Start find SUID file.....')
        for cmd in linux.cve_dic['Command']['SUID']:
            print(linux.cve_dic['Command']['SUID'][cmd][0]+'\n\t'+Fore.GREEN+self.cmd(cmd))

    def backup(self):
        print(Fore.BLUE + 'Start find Backsup file.....')
        for cmd in linux.cve_dic['Command']['Backsup']:
            print(linux.cve_dic['Command']['Backsup'][cmd][0] + '\n\t' + Fore.GREEN + self.cmd(cmd))

    def logs(self):
        print(Fore.BLUE + 'Start find Logs file.....')
        for cmd in linux.cve_dic['Command']['Logs']:
            print(linux.cve_dic['Command']['Logs'][cmd][0] + '\n\t' + Fore.GREEN + self.cmd(cmd))

    def Service(self):
        print(Fore.BLUE + 'Start find Services file.....')
        for cmd in linux.cve_dic['Command']['Service']:
            print(linux.cve_dic['Command']['Service'][cmd][0] + '\n\t' + Fore.GREEN + self.cmd(cmd))

    def cmd(self,cmd):
        shell = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        shell = bytes.decode(shell.stdout.read()).replace('\n','\n\t')
        return shell

if __name__ == '__main__':
    linux = kernel()        #实例化对象
    find = linuxfind()
    parser = OptionParser("Usage: %prog -h")
    parser.add_option("-V","--version",action="store_true",help="program version")
    parser.add_option("-C","--CVE-check",action="store_true",help="CVE Check")
    parser.add_option("-G","--Git-Query",action="store",help="Github CVE Search")
    parser.add_option("-I","--info",action="store_true",help="Print System information")
    parser.add_option("-A","--all",action="store_true",help="Use all function")
    parser.add_option("-L","--linux-all",action="store_true",help="Linux All File Check")
    parser.add_option("-U","--update",action="store_true",help="update the programe")
    parser.add_option("-B","--banner",action="store_true",help="echo the banner")
    options,args= parser.parse_args(sys.argv[1:])
    if options.version == True:
        print(Fore.GREEN+"Version: 1.0")
    if options.all == True:
        linux.systeminfo()      #输出系统信息方便人工判断
        linux.ckeck_CVE()
        find.SUID_Check()
        find.backup()
        find.Service()
        find.logs()
    if options.CVE_check == True:
        linux.systeminfo()
        linux.ckeck_CVE()
    if options.Git_Query != None:
        linux.Github_CVE(options.Git_Query)
    if options.info == True:
        linux.systeminfo()
    if options.linux_all == True:
        find.SUID_Check()
        find.backup()
        find.Service()
        find.logs()
    if options.update == True:
        linux.update()
    if options.banner == True:
        linux.banner()



