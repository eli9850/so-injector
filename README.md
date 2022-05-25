# SO_INJECTOR

Patch an elf, and make him load my so before he calls the main function.

Parse the given elf and change the main function that _start calls to my injected shellcode

The injector was tested on elfs that compiled with glibc 2.34

## Usage

./so-injector <path/to/elf/to/inject> <path/to/shellcode.bin> <path/to/so/to/inject>
