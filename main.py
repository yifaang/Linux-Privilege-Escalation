#!/usr/bin/env python3
#-*- codeing:utf-8 -*-
import subprocess,json,re,time,sys,requests,random
from colorama import init,Fore
from optparse import OptionParser
init(autoreset=True)
class kernel_linux:
    def __init__(self):
        self.cve_dic = self.import_json()              #读取exploit.json文件
        self.linuxinfo_dic = {'Kernel Version': '',   #初始化字典
                              'sudo': '',
                              'sudo Verison': '',
                              'uname': '',
                              'lsb_release': '', }
        kernel_Version = subprocess.Popen('uname -r', shell=True, stdout=subprocess.PIPE)
        sudo = subprocess.Popen('which sudo', shell=True, stdout=subprocess.PIPE)
        sudo_version = subprocess.Popen('sudo -V', shell=True, stdout=subprocess.PIPE)
        uname = subprocess.Popen('uname -a', shell=True, stdout=subprocess.PIPE)
        lsb_release = subprocess.Popen('lsb_release -a', shell=True, stdout=subprocess.PIPE)
        self.linuxinfo_dic['Kernel Version'] = bytes.decode(kernel_Version.stdout.read()).replace('\n', '')
        self.linuxinfo_dic['sudo'] = bytes.decode(sudo.stdout.read()).replace('\n', '')
        self.linuxinfo_dic['sudo Version'] = bytes.decode(sudo_version.stdout.read()).replace('\n', '\n\t')
        self.linuxinfo_dic['uname'] = bytes.decode(uname.stdout.read())
        self.linuxinfo_dic['lsb_release'] = bytes.decode(lsb_release.stdout.read()).replace('\n', '\n\t')

    def import_json(self):                                                  #导入CVE.json文件
        with open('./exploit.json','r') as f:
            cve_dic = json.loads(f.read())
            return cve_dic          #返回列表数据

    def GetVersion(self,version_tried):
        origin_list = re.findall('(\d)\.(.*?)\.(.*)',version_tried)
        a,b,c = origin_list[0]
        return (a,b,c)

    def systeminfo(self):
        print(Fore.BLUE + '[!][Linux System Information]')
        print('[+]The Sytem Kernel Version is \n\t' + Fore.GREEN + self.linuxinfo_dic['Kernel Version'])
        print('[+]The Sudo is in: \n\t' + Fore.GREEN + self.linuxinfo_dic['sudo'])
        print('[+]SUDO Version: \n\t' + Fore.GREEN + self.linuxinfo_dic['sudo Version'])
        print('[+]System name: \n\t' + Fore.GREEN + self.linuxinfo_dic['uname'])
        print('[+]GNU/Linux Info: \n\t' + Fore.GREEN + self.linuxinfo_dic['lsb_release'])
        print(Fore.CYAN + '-----------------------------------------------------------------------------------------------------------------------')

    def CVE_check(self):
        print(Fore.BLUE + 'Start the Kernel Linux CVE Check .....')
        temp_data = str(self.linuxinfo_dic['Kernel Version'])
        origin_list = re.findall('(\d)\.(.*?)\.(.*?)-', temp_data)
        ver1,ver2,ver3 = origin_list[0]
        for cve in self.cve_dic['Kernel Linux']:
            for ver_sion in self.cve_dic['Kernel Linux'][cve]['Version']:
                try_ver1,try_ver2,try_ver3 = self.GetVersion(ver_sion)
                while True:
                    if ver1 == try_ver1:
                        pass
                    else:
                        break
                    if (try_ver2 == '*') or (ver2 == try_ver2):
                        pass
                    else:
                        break
                    if (try_ver3 == '*') or (ver3 == try_ver3):
                        print(Fore.GREEN+'[!]System hava '+cve+'\n ﹂The download address is '+(self.cve_dic['Kernel Linux'][cve]['Exploition'][0]))
                        break
                    else:
                        break

class tools:
    def update(self):
        print(Fore.GREEN+"Update the programe!!!")
        self.cmd('git clone https://github.com/yifaang/Linux-Privilege-Escalation.git /usr/share/Linux-Privilege-Escalation/')

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

    def Github_CVE(self,query):
        url = 'https://api.github.com/search/repositories?q=' + query + '&sort=updated'
        data = requests.get(url).content.decode('utf-8')
        datalist = json.loads(data)
        print('Find ' + str((datalist['total_count'])) + ' result')
        for i in range(0, datalist['total_count'] - 1):
            print(datalist['items'][i]['full_name'])

    def cmd(self,cmd):
        shell = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        shell = bytes.decode(shell.stdout.read()).replace('\n','\n\t')
        return shell

class other:
    def SUID_Check(self):
        print(Fore.BLUE+'Start find SUID file.....')
        for cmd in linux.cve_dic['Command']['SUID']:
            print(linux.cve_dic['Command']['SUID'][cmd][0]+'\n\t'+Fore.GREEN+tools.cmd(cmd))

    def backup(self):
        print(Fore.BLUE + 'Start find Backsup file.....')
        for cmd in linux.cve_dic['Command']['Backsup']:
            print(linux.cve_dic['Command']['Backsup'][cmd][0] + '\n\t' + Fore.GREEN + tools.cmd(cmd))

    def logs(self):
        print(Fore.BLUE + 'Start find Logs file.....')
        for cmd in linux.cve_dic['Command']['Logs']:
            print(linux.cve_dic['Command']['Logs'][cmd][0] + '\n\t' + Fore.GREEN + tools.cmd(cmd))

    def Service(self):
        print(Fore.BLUE + 'Start find Services file.....')
        for cmd in linux.cve_dic['Command']['Service']:
            print(linux.cve_dic['Command']['Service'][cmd][0] + '\n\t' + Fore.GREEN + tools.cmd(cmd))

if __name__ == '__main__':
    linux = kernel_linux()        #实例化对象
    other = other()
    tools = tools()
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
        linux.CVE_check()
        other.SUID_Check()
        other.backup()
        other.Service()
        other.logs()
    if options.CVE_check == True:
        linux.systeminfo()
        linux.CVE_check()
    if options.Git_Query != None:
        linux.Github_CVE(options.Git_Query)
    if options.info == True:
        linux.systeminfo()
    if options.linux_all == True:
        other.SUID_Check()
        other.backup()
        other.Service()
        other.logs()
    if options.update == True:
        linux.update()
    if options.banner == True:
        tools.banner()
