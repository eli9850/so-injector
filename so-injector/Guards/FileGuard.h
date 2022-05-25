#pragma once

#include <filesystem>

class FileGuard {

public:
    explicit FileGuard(const std::filesystem::path &file_path, int flags);
    explicit FileGuard(const std::filesystem::path &file_path, int flags, int mode);

    FileGuard(const FileGuard &) = delete;
    FileGuard operator=(const FileGuard &) = delete;
    FileGuard(FileGuard &&) = delete;
    FileGuard operator=(FileGuard &&) = delete;

    [[nodiscard]] int get_file_fd() const;

    virtual ~FileGuard();

private:
    int m_file_fd;
};

