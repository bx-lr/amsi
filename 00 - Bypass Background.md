## Background on Bypass Techniques

## RWX Allocation

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


## Finding ProcessHeap


```text
0:011> dt 0x026c0000 ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0x4 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y0
   +0x004 Mutant           : 0xffffffff Void
   +0x008 ImageBaseAddress : 0x00300000 Void
   +0x00c Ldr              : 0x77d35d80 _PEB_LDR_DATA
   +0x010 ProcessParameters : 0x02900af0 _RTL_USER_PROCESS_PARAMETERS
   +0x014 SubSystemData    : (null) 
   +0x018 ProcessHeap      : 0x02900000 Void   <--- here
```

