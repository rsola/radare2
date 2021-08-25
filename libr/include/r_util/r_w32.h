#ifndef R_W32_H
#define R_W32_H

#ifdef __cplusplus
extern "C" {
#endif

#if __WINDOWS__
#include <windows.h> // CreateToolhelp32Snapshot
#include <tlhelp32.h> // CreateToolhelp32Snapshot
#include <psapi.h> // GetModuleFileNameEx, GetProcessImageFileName

#ifndef NTSTATUS
#define NTSTATUS DWORD
#endif

extern R_API DWORD (*w32_GetProcessImageFileName)(HANDLE,LPSTR,DWORD);
extern R_API DWORD (*w32_GetModuleBaseName)(HANDLE, HMODULE, LPTSTR, DWORD);
extern R_API BOOL (*w32_GetModuleInformation)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
extern R_API BOOL (*w32_DebugActiveProcessStop)(DWORD);
extern R_API HANDLE (*w32_OpenThread)(DWORD, BOOL, DWORD);
extern R_API BOOL (*w32_DebugBreakProcess)(HANDLE);
extern R_API DWORD (*w32_GetThreadId)(HANDLE); // Vista
extern R_API DWORD (*w32_GetProcessId)(HANDLE); // XP
extern R_API HANDLE (*w32_OpenProcess)(DWORD, BOOL, DWORD);
extern R_API BOOL (*w32_QueryFullProcessImageName)(HANDLE, DWORD, LPTSTR, PDWORD);
extern R_API DWORD (*w32_GetMappedFileName)(HANDLE, LPVOID, LPTSTR, DWORD);
extern R_API NTSTATUS (*w32_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
extern R_API NTSTATUS (*w32_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
extern R_API NTSTATUS (*w32_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
extern R_API NTSTATUS (*w32_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);
extern R_API ut64 (*w32_GetEnabledXStateFeatures)(void);
extern R_API BOOL (*w32_InitializeContext)(PVOID, DWORD, PCONTEXT*, PDWORD);
extern R_API BOOL (*w32_GetXStateFeaturesMask)(PCONTEXT Context, PDWORD64);
extern R_API PVOID (*w32_LocateXStateFeature)(PCONTEXT Context, DWORD, PDWORD);
extern R_API BOOL (*w32_SetXStateFeaturesMask)(PCONTEXT Context, DWORD64);
extern R_API DWORD (*w32_GetModuleFileNameEx)(HANDLE, HMODULE, LPTSTR, DWORD);
extern R_API HANDLE (*w32_CreateToolhelp32Snapshot)(DWORD, DWORD);
#endif

#ifdef __cplusplus
}
#endif

#endif //  R_W32_H
