#include "ElfParser.h"

// TODO: remove this
#include <iostream>

#include <string_view>
#include <cstring>
#include <sys/mman.h>

constexpr std::string_view DYNSYM_TABLE_NAME = ".dynsym";
constexpr std::string_view SYMTEB_TABLE_NAME = ".symtab";
constexpr std::string_view RELA_DYN_TABLE_NAME = ".rela.dyn";

ElfParser::ElfParser(const std::filesystem::path &path_to_file) :
        m_elf(std::make_shared<MapGuard>(path_to_file, PROT_READ, MAP_SHARED)) {}


ElfParser::ElfParser(std::shared_ptr<MapGuard> elf) :
        m_elf(std::move(elf)) {}


Elf64_Ehdr ElfParser::get_elf_header() const {
    Elf64_Ehdr elf_header = {0};
    std::memcpy(&elf_header, m_elf->get_file_data(0), sizeof(Elf64_Ehdr));
    return elf_header;

}

std::vector<Elf64_Phdr> ElfParser::get_program_headers() const {
    Elf64_Ehdr elf_header = get_elf_header();
    std::vector<Elf64_Phdr> elf_program_headers(elf_header.e_phnum);
    auto program_header_offset = elf_header.e_phoff;
    for (int i = 0; i < elf_header.e_phnum; ++i) {
        std::memcpy(&elf_program_headers[i], m_elf->get_file_data(program_header_offset), sizeof(Elf64_Phdr));
        program_header_offset += sizeof(Elf64_Phdr);
    }
    return elf_program_headers;
}

Elf64_Phdr ElfParser::get_program_header(int index) const {
    Elf64_Ehdr elf_header = get_elf_header();

    if (index >= elf_header.e_phnum) {
        throw std::out_of_range("The index is to great");
    }

    Elf64_Phdr elf_program_header = {0};
    auto program_header_offset = elf_header.e_phoff + index * sizeof(Elf64_Phdr);
    std::memcpy(&elf_program_header, m_elf->get_file_data(program_header_offset), sizeof(Elf64_Phdr));
    return elf_program_header;
}

std::vector<Elf64_Shdr> ElfParser::get_section_headers() const {
    Elf64_Ehdr elf_header = get_elf_header();
    std::vector<Elf64_Shdr> elf_section_headers(elf_header.e_shnum);
    auto section_header_offset = elf_header.e_shoff;
    for (int i = 0; i < elf_header.e_shnum; ++i) {
        std::memcpy(&elf_section_headers[i], m_elf->get_file_data(section_header_offset), sizeof(Elf64_Shdr));
        section_header_offset += sizeof(Elf64_Shdr);
    }
    return elf_section_headers;

}

Elf64_Shdr ElfParser::get_section_header(int index) const {
    Elf64_Ehdr elf_header = get_elf_header();

    if (index >= elf_header.e_shnum) {
        throw std::out_of_range("The index is to great");
    }

    Elf64_Shdr elf_section_header;
    auto section_header_offset = elf_header.e_shoff;
    std::memcpy(&elf_section_header, m_elf->get_file_data(section_header_offset + index * sizeof(Elf64_Shdr)),
                sizeof(Elf64_Shdr));

    return elf_section_header;
}

std::optional<Elf64_Shdr> ElfParser::get_section_header(const std::string &section_name) const {

    auto elf_header = get_elf_header();

    auto string_section = get_section_header(elf_header.e_shstrndx);
    auto sections = get_section_headers();
    for (const auto &section: sections) {
        if (0 == std::strcmp(section_name.c_str(), m_elf->get_file_data(string_section.sh_offset + section.sh_name))) {
            return section;
        }

    }

    return {};
}

Elf64_Addr ElfParser::get_symbol_value(const std::string &symbol_name) const {

    auto symtab_section = get_section_header(SYMTEB_TABLE_NAME.data());
    if (symtab_section.has_value()) {
        auto symtab_link_section = get_section_header(symtab_section->sh_link);

        auto number_of_symbols = symtab_section->sh_size / sizeof(Elf64_Sym);
        auto symbol_offset = symtab_section->sh_offset;

        for (int i = 0; i < number_of_symbols; ++i) {

            Elf64_Sym symbol = (reinterpret_cast<const Elf64_Sym *>(m_elf->get_file_data(symbol_offset)))[0];
            auto symbol_name_offset = symtab_link_section.sh_offset + symbol.st_name;
            if (0 == std::strcmp(m_elf->get_file_data(symbol_name_offset), symbol_name.c_str())) {
                return symbol.st_value;
            }

            symbol_offset += sizeof(Elf64_Sym);

        }
    }

    auto dynsym_section = get_section_header(DYNSYM_TABLE_NAME.data());
    if (dynsym_section.has_value()) {
        auto dynsym_link_section = get_section_header(dynsym_section->sh_link);

        auto number_of_symbols = dynsym_section->sh_size / sizeof(Elf64_Sym);
        auto symbol_offset = dynsym_section->sh_offset;

        for (int i = 0; i < number_of_symbols; ++i) {

            Elf64_Sym symbol = (reinterpret_cast<const Elf64_Sym *>(m_elf->get_file_data(symbol_offset)))[0];
            auto symbol_name_offset = dynsym_link_section.sh_offset + symbol.st_name;
            if (0 == std::strcmp(m_elf->get_file_data(symbol_name_offset), symbol_name.c_str())) {
                return symbol.st_value;
            }

            symbol_offset += sizeof(Elf64_Sym);

        }
    }

    return 0;
}

Elf64_Addr ElfParser::get_offset_of_relocatable_symbol(const std::string &symbol_name) const {


    auto rela_section = get_section_header(RELA_DYN_TABLE_NAME.data());
    auto dynsym_section = get_section_header(DYNSYM_TABLE_NAME.data());
    auto dynsym_link_section = get_section_header(dynsym_section->sh_link);

    auto number_of_symbols = rela_section->sh_size / sizeof(Elf64_Rela);
    for (int i = 0; i < number_of_symbols; ++i) {
        Elf64_Rela rela_symbol = (reinterpret_cast<const Elf64_Rela *>(m_elf->get_file_data(
                rela_section->sh_offset + i * sizeof(Elf64_Rela))))[0];
        auto symbol_index = ELF64_R_SYM(rela_symbol.r_info);
        Elf64_Sym symbol = (reinterpret_cast<const Elf64_Sym *>(m_elf->get_file_data(
                dynsym_section->sh_offset + symbol_index * sizeof(Elf64_Sym))))[0];
        auto symbol_name_offset = dynsym_link_section.sh_offset + symbol.st_name;
        if (0 == std::strcmp(m_elf->get_file_data(symbol_name_offset), symbol_name.c_str())) {
            return rela_symbol.r_offset;
        }

    }
    return 0;

}