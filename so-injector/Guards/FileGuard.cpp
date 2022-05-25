#include "FileGuard.h"
#include <unistd.h>
#include <fcntl.h>

constexpr int OPEN_FILE_FAILED = -1;

FileGuard::FileGuard(const std::filesystem::path &file_path, int flags) {
    m_file_fd = open(file_path.c_str(), flags);
    if (OPEN_FILE_FAILED == m_file_fd){
        throw std::runtime_error("could not open file");
    }
}

FileGuard::FileGuard(const std::filesystem::path &file_path, int flags, int mode) {
    m_file_fd = open(file_path.c_str(), flags, mode);
    if (OPEN_FILE_FAILED == m_file_fd){
        throw std::runtime_error("could not open file");
    }
}

int FileGuard::get_file_fd() const{
    return m_file_fd;
}

FileGuard::~FileGuard() {
    try {
        if (m_file_fd != -1) {
            close(m_file_fd);
        }
    } catch (...) {}

}