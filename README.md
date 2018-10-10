# GoldFishCmd

Program created by eRaMvn. 

A simple program that generates commands for pentesters to avoid mistakes during an engagement

Please run
```
pip install -r requirements.txt
```

### Tools supported:

cewl / curl / dig / enum4linux / gobuster / hydra / mount / msfvenom / mysql / nc / nikto / nmap / plink / rdesktop / reverse_shell / smbclient / smtp-user-enum / sqlmap / ssh / sshuttle / tcpdump / unicorn / wpscan

### Arguments

_positional arguments:_

   [source ip]    source ip address - usually attacker's ip address
   
   [target ip]    target's ip address

_optional arguments:_

  -h, --help      show this help message and exit
  
  -lp [port]      local port to listen to. Default port is 443
  
  -d [directory]  directory where files can be stored
  
  -v              show program's version number and exit
  
## Sample Output:

PS C:\Users\eRaMvn> & "C:/Users/eRaMvn/AppData/Local/Programs/Python/Python37-32/python.exe" "d:/GoldFish/GoldFishCmd.py" 10.11.12.13 10.11.12.230
```
You are currently in tool selection mode.

Please choose commmand to generate. Otherwise, type "list" to list tools supported, "change" to change ips and ports, "exit" to quit program.

Input: nmap

1. nmap -sSV -Pn -nvv -p- --reason -T4 -oN ~/Desktop/10.11.12.230_nmap_tcp_ports.txt 10.11.12.230
-----------------------------
2. nmap -sSV -sC -Pn -nvv -p[edit port] -A --version-intensity 9 -O --reason -T4 -oN ~/Desktop/10.11.12.230_nmap_detailed.txt 10.11.12.230
-----------------------------
3. nmap -A -O --script vuln -p25,22,111,145,139 -oN ~/Desktop/10.11.12.230_nmap_vuln_scan.txt 10.11.12.230
-----------------------------
4. nmap -Pn -p- -sU --stats-every 3m --max-retries 2 -T4 -oN ~/Desktop/10.11.12.230_nmap_udp_ports.txt 10.11.12.230
-----------------------------
5. nmap -T4 -sV --script=firewalk.nse -oN ~/Desktop/10.11.12.230_nmap_firewalk.txt 10.11.12.230
-----------------------------

Please choose commmand number to copy to clipboard. Type "0" to return to tool selection

Input: 1

Command has been copied to your clipboard!

Please enter an integer from -1 to 5. 0 to return, -1 to list commands

Input: 0

-----------------------------

Taking you back to tool selection!

-----------------------------

You are currently in tool selection mode.

Please choose commmand to generate. Otherwise, type "list" to list tools supported, "change" to change ips and ports, "exit" to quit program.

Input: exit

Bye!
```
## Command in clipboard:
```
nmap -sSV -Pn -nvv -p- --reason -T4 -oN ~/Desktop/10.11.12.230_nmap_tcp_ports.txt 10.11.12.230
```
