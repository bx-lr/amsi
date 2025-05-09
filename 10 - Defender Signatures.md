## Signatures
Signatures seem to be split... Some block and some force logging

https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/



### Identify Windows Defender AV Signatures
The Windows Defender antivirus signature database is located under C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}\mpavbase.vdm and mpasbase.vdm. Really weird but the files have PE headers...

![[images/image-01.png]]

Looking through the file we find the FileVersion and ProductVersion vaues of 1.343.0.0 

![[images/image-02.png]]

Maybe this has some relation to the results from get-mpcomputerstatus

![[images/image-03.png]]


We can use two different projects to extract the Windows Defender antivirus signature databases. They look to do the same thing. 

* https://gist.github.com/mattifestation/3af5a472e11b7e135273e71cb5fed866
* https://github.com/hfiref0x/WDExtract


```PowerShell
PS > Import-Module .\ExpandDefenderSig.ps1
PS > ls 'C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{3D115D4B-8455-439B-BBBB-3B43A46EC636}\mpasbase.vdm' | Expand-DefenderAVSignatureDB -OutputFileName mpavbase.decompressed
```


This will ouput the results into the mpavbase.decompress file. Looking through the results we can see some familiar things. 

![[images/image-04.png]]

Not sure of the format for this file. However, we can still see some actionable results....


### Additional Signatures 
Windows PowerShell contains a list of 'Suspicious' strings in Sytem.Management.Automation.dll. This DLL can be found in C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\24dd1e25b46bc13292f1f25a9a0b816c\System.Management.Automation.ni.dll

* Where NativeImages_v4.0.30319_64 contains the version and architecture of PowerShell. 
* Where 24dd1e25b46bc13292f1f25a9a0b816c is a hash

Investigating this DLL we can find a check for 'suspicious' content. 

![[images/image-05.png]]

ScriptBlockText content is checked against the list. 

```powershell
		private static HashSet<string> signatures = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
		{
			"Add-Type",
			"DllImport",
			"DefineDynamicAssembly",
			"DefineDynamicModule",
			"DefineType",
			"DefineConstructor",
			"CreateType",
			"DefineLiteral",
			"DefineEnum",
			"DefineField",
			"ILGenerator",
			"Emit",
			"UnverifiableCodeAttribute",
			"DefinePInvokeMethod",
			"GetTypes",
			"GetAssemblies",
			"Methods",
			"Properties",
			"GetConstructor",
			"GetConstructors",
			"GetDefaultMembers",
			"GetEvent",
			"GetEvents",
			"GetField",
			"GetFields",
			"GetInterface",
			"GetInterfaceMap",
			"GetInterfaces",
			"GetMember",
			"GetMembers",
			"GetMethod",
			"GetMethods",
			"GetNestedType",
			"GetNestedTypes",
			"GetProperties",
			"GetProperty",
			"InvokeMember",
			"MakeArrayType",
			"MakeByRefType",
			"MakeGenericType",
			"MakePointerType",
			"DeclaringMethod",
			"DeclaringType",
			"ReflectedType",
			"TypeHandle",
			"TypeInitializer",
			"UnderlyingSystemType",
			"InteropServices",
			"Marshal",
			"AllocHGlobal",
			"PtrToStructure",
			"StructureToPtr",
			"FreeHGlobal",
			"IntPtr",
			"MemoryStream",
			"DeflateStream",
			"FromBase64String",
			"EncodedCommand",
			"Bypass",
			"ToBase64String",
			"ExpandString",
			"GetPowerShell",
			"OpenProcess",
			"VirtualAlloc",
			"VirtualFree",
			"WriteProcessMemory",
			"CreateUserThread",
			"CloseHandle",
			"GetDelegateForFunctionPointer",
			"kernel32",
			"CreateThread",
			"memcpy",
			"LoadLibrary",
			"GetModuleHandle",
			"GetProcAddress",
			"VirtualProtect",
			"FreeLibrary",
			"ReadProcessMemory",
			"CreateRemoteThread",
			"AdjustTokenPrivileges",
			"WriteByte",
			"WriteInt32",
			"OpenThreadToken",
			"PtrToString",
			"FreeHGlobal",
			"ZeroFreeGlobalAllocUnicode",
			"OpenProcessToken",
			"GetTokenInformation",
			"SetThreadToken",
			"ImpersonateLoggedOnUser",
			"RevertToSelf",
			"GetLogonSessionData",
			"CreateProcessWithToken",
			"DuplicateTokenEx",
			"OpenWindowStation",
			"OpenDesktop",
			"MiniDumpWriteDump",
			"AddSecurityPackage",
			"EnumerateSecurityPackages",
			"GetProcessHandle",
			"DangerousGetHandle",
			"CryptoServiceProvider",
			"Cryptography",
			"RijndaelManaged",
			"SHA1Managed",
			"CryptoStream",
			"CreateEncryptor",
			"CreateDecryptor",
			"TransformFinalBlock",
			"DeviceIoControl",
			"SetInformationProcess",
			"PasswordDeriveBytes",
			"GetAsyncKeyState",
			"GetKeyboardState",
			"GetForegroundWindow",
			"BindingFlags",
			"NonPublic",
			"ScriptBlockLogging",
			"LogPipelineExecutionDetails",
			"ProtectedEventLogging"
		};
```


All located under 
* File: System.Management.Automation.dll
* Namespace: System.Management.Automation
* Class: ScriptBlock
* Function: CheckSuspiciousContent 

PowerShell scripts containing one or more of these strings will be flagged as 'Suspicious' and logging will be forced. You know what they say...

![[giphy.gif]]


### Easy Testing
We can use this project (https://github.com/RythmStick/AMSITrigger) to test the bypass. It can provide source lines and alert values. 