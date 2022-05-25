#pragma once

#include <filesystem>
#include <vector>

class MapGuard {

public:
    explicit MapGuard(const std::filesystem::path &file_path, int prot, int flags, int offset = 0, void *address = nullptr);

    MapGuard(const MapGuard &) = delete;
    MapGuard operator=(const MapGuard &) = delete;
    MapGuard(MapGuard &&) noexcept;
    MapGuard operator=(MapGuard &&) = delete;

    void write_to_file(const std::vector<char>& data, unsigned long offset);
    [[nodiscard]] std::vector<char> read_from_file(unsigned long offset, unsigned long size) const;
    [[nodiscard]] const char* get_file_data(unsigned long offset) const;
    [[nodiscard]] unsigned long get_file_size() const;

    virtual ~MapGuard();

private:
    char *m_file_data;
    unsigned long m_file_size;
};

