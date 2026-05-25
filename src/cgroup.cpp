#include "cgroup.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

std::string cgroup_root() {
    return "/sys/fs/cgroup";
}

bool check_cgroup_v2(std::string &err) {
    struct stat st;
    std::string path = cgroup_root() + "/cgroup.controllers";
    if (stat(path.c_str(), &st) != 0) {
        err = "cgroup v2 not detected: missing /sys/fs/cgroup/cgroup.controllers";
        return false;
    }
    return true;
}

bool check_cgroup_id_support(std::string &err) {
    std::string path = cgroup_root() + "/cgroup.id";
    struct stat st;
    if (stat(path.c_str(), &st) == 0) return true;

    // Fallback: check if name_to_handle_at works on the root
    struct {
        struct file_handle handle;
        unsigned char f_handle[8];
    } h;
    h.handle.handle_bytes = 8;
    int mount_id;
    if (name_to_handle_at(AT_FDCWD, cgroup_root().c_str(), &h.handle, &mount_id, 0) == 0) {
        return true;
    }

    err = "cgroup ID support not detected (no cgroup.id and name_to_handle_at failed)";
    return false;
}

bool ensure_cgroup_dir(const std::string &path, std::string &err) {
    if (mkdir(path.c_str(), 0755) != 0) {
        if (errno == EEXIST) {
            err = "cgroup directory already exists: " + path;
            return false;
        }
        err = "failed to create cgroup directory " + path + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

bool move_pid_to_cgroup(int pid, const std::string &path, std::string &err) {
    std::string procs = path + "/cgroup.procs";
    std::ofstream out(procs);
    if (!out) {
        err = "unable to open " + procs;
        return false;
    }
    out << pid << "\n";
    if (!out) {
        err = "failed to write to " + procs;
        return false;
    }
    return true;
}

bool read_cgroup_id(const std::string &path, std::string &out, std::string &err) {
    // 1. Try to read binary cgroup.id if it exists
    std::string id_path = path + "/cgroup.id";
    int fd = open(id_path.c_str(), O_RDONLY);
    if (fd >= 0) {
        unsigned long long id = 0;
        ssize_t n = read(fd, &id, sizeof(id));
        close(fd);
        if (n == sizeof(id)) {
            out = std::to_string(id);
            return true;
        }
    }

    // 2. Use name_to_handle_at to get the full 64-bit kernel handle (inode + more)
    struct {
        struct file_handle handle;
        unsigned char f_handle[8];
    } h;
    h.handle.handle_bytes = 8;
    int mount_id;
    if (name_to_handle_at(AT_FDCWD, path.c_str(), &h.handle, &mount_id, 0) == 0) {
        if (h.handle.handle_bytes == 8) {
            unsigned long long id = 0;
            std::memcpy(&id, h.f_handle, 8);
            out = std::to_string(id);
            return true;
        }
    }

    // 3. Last resort: standard inode number
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        out = std::to_string(st.st_ino);
        return true;
    }

    err = "unable to retrieve cgroup ID for " + path;
    return false;
}

bool remove_cgroup_dir(const std::string &path, std::string &err) {
    if (rmdir(path.c_str()) != 0) {
        if (errno == ENOENT) return true;
        err = "failed to remove cgroup directory " + path + ": " + std::strerror(errno);
        return false;
    }
    return true;
}
