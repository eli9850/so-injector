#pragma once

#include <memory>
#include <vector>
#include <optional>
#include <elf.h>
#include "../Guards/MapGuard.h"

class ElfParser final {

public:
    explicit ElfParser(const std::filesystem::path& path_to_file);
    explicit ElfParser(std::shared_ptr<MapGuard> elf);

    [[nodiscard]] Elf64_Ehdr get_elf_header() const;
    [[nodiscard]] std::vector<Elf64_Phdr> get_program_headers() const;
    [[nodiscard]] Elf64_Phdr get_program_header(int index) const;
    [[nodiscard]] std::vector<Elf64_Shdr> get_section_headers() const;
    [[nodiscard]] Elf64_Shdr get_section_header(int index) const;
    [[nodiscard]] std::optional<Elf64_Shdr> get_section_header(const std::string& section_name) const;
    [[nodiscard]] Elf64_Addr get_symbol_value(const std::string& symbol_name) const;
    [[nodiscard]] Elf64_Addr get_offset_of_relocatable_symbol(const std::string& symbol_name) const;

private:
    std::shared_ptr<MapGuard> m_elf;
};