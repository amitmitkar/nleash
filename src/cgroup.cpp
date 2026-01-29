#include "cgroup.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
    std::string id_path = path + "/cgroup.id";
    std::ifstream in(id_path);
    if (!in) {
        err = "unable to read " + id_path + " (kernel must support cgroup.id)";
        return false;
    }
    std::getline(in, out);
    if (out.empty()) {
        err = "cgroup.id is empty for " + path;
        return false;
    }
    return true;
}

bool remove_cgroup_dir(const std::string &path, std::string &err) {
    if (rmdir(path.c_str()) != 0) {
        if (errno == ENOENT) return true;
        err = "failed to remove cgroup directory " + path + ": " + std::strerror(errno);
        return false;
    }
    return true;
}
