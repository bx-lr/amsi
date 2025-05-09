## Ropping the Callback

### Getting DLL's
We need to get a list of dlls that can be used as a target of the callback. Also, we need to bypass CFG. We have a couple options for this bypass and need to build out a list of acceptable cannidates. To do so we can check the DLL_CHARACTERISTIC field to see if any of the DLL's we wish to target are accepatable. 

Two command line options for checking the security of the DLL's are Get-PESecurity.psm1 and BinSkim. To use Get-PESecurity follow the instructions at https://github.com/NetSPI/PESecurity. Unfortunately, this PowerShell script will be flagged by AMSI. I guess Microsoft would prefer if you used their tool. To use BinSkim follow the instructions at https://github.com/microsoft/binskim. 

#### Sample output
Each tool will output the results of the scanning in a different format. 

Get-PESecurity.psm1 output
```bash
#TYPE System.Data.DataRow
"FileName","ARCH","ASLR","DEP","Authenticode","StrongNaming","SafeSEH","ControlFlowGuard"
"C:\windows\SysWOW64\1028\VsGraphicsResources.dll","I386","True","True","True","N/A","N/A","False"
"C:\windows\SysWOW64\1028\vsjitdebuggerui.dll","I386","True","True","True","N/A","N/A","False"
"C:\windows\SysWOW64\1029\VsGraphicsResources.dll","I386","True","True","True","N/A","N/A","False"
```

BinSkim output
```powershell
.\BinSkim.exe analyze c:\windows\syswow64\*.dll  |grep 'BA2008:'
c:\windows\syswow64\f3ahvoas.dll: error BA2008: 'f3ahvoas.dll' does not enable the control flow guard (CFG) mitigation. To resolve this issue, pass /guard:cf on both the compiler and linker command lines. Binaries also require the /DYNAMICBASE linker option in order to enable CFG.
c:\windows\syswow64\gnsdk_fp.dll: error BA2008: 'gnsdk_fp.dll' does not enable the control flow guard (CFG) mitigation. To resolve this issue, pass /guard:cf on both the compiler and linker command lines. Binaries also require the /DYNAMICBASE linker option in order to enable CFG.
c:\windows\syswow64\kbd101.DLL: error BA2008: 'kbd101.DLL' does not enable the control flow guard (CFG) mitigation. To resolve this issue, pass /guard:cf on both the compiler and linker command lines. Binaries also require the /DYNAMICBASE linker option in order to enable CFG.
c:\windows\syswow64\kbd101a.DLL: error BA2008: 'kbd101a.DLL' does not enable the control flow guard (CFG) mitigation. To resolve this issue, pass /guard:cf on both the compiler and linker command lines. Binaries also require the /DYNAMICBASE linker option in order to enable CFG.
...
```

Now we have a (rather large) list of DLL's that could potentially be used to bypass CFG on the targeted system. 

### Locating Gadgets at Scale
To locate gadgets at scale we need to create a searchable database of potential options. We will install mquery on a Kali linux vm and search the non-CFG enabled DLL's for our gadgets. 

#### Mquery
This program uses UrsaDB to scan files at scale with YARA. More information found at https://github.com/CERT-Polska/mquery

#### Installation
Follow the instructions at the GitHub link. Also, we need to install docker...

```bash
$ sudo apt update
$ sudo apt install -y docker.io docker-compose
$ sudo systemctl enable docker --now
$ git clone https://github.com/CERT-Polska/mquery
$ cd mquery
$ sudo docker-compose up
```

To verify everything is working properly, visit http://localhost:80. We should have something like this:

![[images/image-06.png]]

#### Indexing
We need to upload all of the non-CFG enabled DLL's to our mquery instance. 

On Kali:
```bash
$ ifconfig eth0
$ # returns 192.168.68.130
$ cd ~/mquery/samples
$ sudo impacket-smbserver -smb2support myshare .
```

On Windows:
```bash
net use H: \\192.168.68.130\myshare
cp -r x86_bins\ H:\
```

Make sure the permissions on the uploaded files are correct
```bash
$ cd ~/mquery/samples/
$ sudo chgrp -R kail .
$ sudo chown -R kali . 
```

Now we can resart mquery and index the files. 

![[images/image-07.png]]


Note: if indexing fails due to OOM try to increase the available memory in the VM settings. 

Once all the files have been indexed be sure to compact the database and verify that the files are correctly loaded. 

![[images/image-08.png]]


Get the opcodes we are looking for...

```bash
┌──(kali㉿kali)-[~/mquery/samples]
└─$ rasm2 -a x86 'add esp, 0x460; ret'
81c460040000c3
```


Build a YARA rule to search accross the corpus. 
```bash
import "pe"

rule test
{
  strings:
    $pivot = {81 c4 6? 04 00 00 c3}
  condition:
    $pivot in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
```


![[images/image-09.png]]

Verify our hit and get the offset

```bash
┌──(kali㉿kali)-[~/mquery/samples]
└─$ /usr/local/bin/ROPgadget --binary WibuCm32.dll --rawArch=x86 --rawMode=32 | grep 'add esp, 0x460'
0x0004f367 : add al, byte ptr [eax] ; add esp, 0x460 ; ret
0x0004f369 : add esp, 0x460 ; ret
0x0004f366 : inc ebx ; add al, byte ptr [eax] ; add esp, 0x460 ; ret
```