#pragma once

#include <memory>

#include "../Guards/MapGuard.h"
#include "../ElfParser/ElfParser.h"

struct ShellcodeArgs {
    long offset_to_real_main;
    long  offset_to_got_libc_start_main;
    long  offset_from_libc_start_main_to_dlopen;
    char so_name[40];
};

class Injector final {
public:
    Injector(std::shared_ptr<MapGuard> file_to_inject, std::shared_ptr<MapGuard> shellcode_to_inject, std::string so_name);

    void inject();

private:
    [[nodiscard]] ShellcodeArgs get_shellcode_args(const Elf64_Phdr &segment_to_edit) const;
    [[nodiscard]] long get_offset_to_got_libc_start_main_from_shellcode(const Elf64_Phdr &segment_to_edit) const;
    void inject_shellcode_args_to_shellcode(const ShellcodeArgs &args);
    void inject_shellcode_to_elf(const std::vector<char> &shellcode, const Elf64_Phdr &segment_to_edit);

    void edit_segment_size(const Elf64_Phdr &segment_to_edit, unsigned long shellcode_offset_from_main_ptr);
    [[nodiscard]] uint32_t get_offset_to_shellcode(const Elf64_Phdr &exec_segment) const;
    void edit_main_offset_parameter(uint32_t shellcode_offset);


private:
    std::shared_ptr<MapGuard> m_file;
    std::shared_ptr<MapGuard> m_shellcode;
    ElfParser m_elf_parser;
    std::string m_so_name;

};