#include <map>
#include <iostream>
#include <istream>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>
#include <cstdint>
#include <sys/mman.h>

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
    std::cout << "Powering up the deck.....\n";
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
    //"mov %0, %%rbx\n"
    //"call *%%rbx\n"
    :
    : 
    : 
);
}
}

int main() {
    std::string fortune;
    std::cout << "Welcome to the Fortune telling tent!" << "\n";
    std::cout << "Lay out the cards and see your destiny:";
    std::getline(std::cin, fortune);

    std::string token;
    std::vector<uint8_t> shellcode;
    std::istringstream ss{fortune};
    for (std::string line; std::getline(ss, line, ',');) {
        auto card_value = Cards.find(line);
        if (card_value == Cards.end()) {
            std::cout << "The fortune is not on your side....\n";
            return 1;
        }
        shellcode.push_back(card_value -> second);
    }
    if (shellcode.size() > 0x1000) {
        std::cout << "The cards are telling me that you will lose...\n";
        return 1;
    }
    run_shellcode(shellcode);
}
