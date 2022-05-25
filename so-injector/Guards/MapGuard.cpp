#include "MapGuard.h"
#include <sys/mman.h>
#include <fcntl.h>

#include "FileGuard.h"


MapGuard::MapGuard(const std::filesystem::path &file_path, int prot, int flags, int offset, void *address) {

    auto permission = O_RDONLY;
    if (prot & PROT_WRITE ){
        permission = O_RDWR;
    }
    FileGuard file(file_path, permission);
    m_file_size = std::filesystem::file_size(file_path);
    m_file_data = reinterpret_cast<char *>(mmap(address, m_file_size, prot, flags, file.get_file_fd(), offset));
    if (nullptr == m_file_data) {
        throw std::runtime_error("Could not map file");
    }

}

MapGuard::MapGuard(MapGuard &&old_map) noexcept {

    if (old_map.m_file_data != nullptr) {
        m_file_data = old_map.m_file_data;
        old_map.m_file_data = nullptr;
        m_file_size = old_map.m_file_size;
        old_map.m_file_size = 0;
    }
}

const char *MapGuard::get_file_data(unsigned long offset) const {
    if (offset >= m_file_size) {
        throw std::range_error("offset is to big");
    }
    return &m_file_data[offset];
}

unsigned long MapGuard::get_file_size() const {
    return m_file_size;
}

std::vector<char> MapGuard::read_from_file(unsigned long offset, unsigned long size) const {
    if (offset + size > m_file_size) {
        throw std::range_error("offset is to big");
    }
    std::vector<char> data_to_read(size);
    for (int i = 0; i < size; ++i) {
        data_to_read[i] = m_file_data[offset + i];
    }
    return data_to_read;
}

void MapGuard::write_to_file(const std::vector<char> &data, unsigned long offset) {
    if (offset + data.size() > m_file_size) {
        throw std::range_error("offset is to big");
    }
    for (int i = 0; i < data.size(); ++i) {
        m_file_data[offset + i] = data[i];
    }
}

MapGuard::~MapGuard() {
    try {
        if (nullptr != m_file_data) {
            munmap(m_file_data, m_file_size);
        }
    }
    catch (...) {

    }
}