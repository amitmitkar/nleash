#include "state.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static std::string state_dir() {
    return "/run/nleash";
}

std::string state_file_path() {
    return state_dir() + "/state.txt";
}

std::string nextid_file_path() {
    return state_dir() + "/nextid";
}

bool ensure_state_dir(std::string &err) {
    if (mkdir(state_dir().c_str(), 0755) != 0) {
        if (errno == EEXIST) return true;
        err = "failed to create /run/nleash: " + std::string(std::strerror(errno));
        return false;
    }
    return true;
}

bool allocate_leash_id(int &out_id, std::string &err) {
    int fd = open(nextid_file_path().c_str(), O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        err = "unable to open /run/nleash/nextid";
        return false;
    }
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        err = "unable to lock /run/nleash/nextid";
        return false;
    }

    std::string content;
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        content = buf;
    }
    int current = 1;
    if (!content.empty()) {
        try {
            current = std::stoi(content);
        } catch (...) {
            current = 1;
        }
    }
    out_id = current;
    int next = current + 1;

    if (lseek(fd, 0, SEEK_SET) < 0 || ftruncate(fd, 0) != 0) {
        flock(fd, LOCK_UN);
        close(fd);
        err = "failed to update /run/nleash/nextid";
        return false;
    }
    std::string next_str = std::to_string(next);
    if (write(fd, next_str.c_str(), next_str.size()) < 0) {
        flock(fd, LOCK_UN);
        close(fd);
        err = "failed to write /run/nleash/nextid";
        return false;
    }

    flock(fd, LOCK_UN);
    close(fd);
    return true;
}

bool append_state(const LeashState &st, std::string &err) {
    int fd = open(state_file_path().c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        err = "unable to open " + state_file_path() + ": " + std::strerror(errno);
        return false;
    }
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        err = "unable to lock " + state_file_path() + ": " + std::strerror(errno);
        return false;
    }

    std::stringstream ss;
    ss << st.pid << " " << st.uid << " " << st.starttime << " " << st.boot_id << " " << st.leash_id << " "
       << st.iface << " " << st.rate << " " << st.cgroup_path << " " << st.classid << "\n";
    std::string line = ss.str();

    if (write(fd, line.c_str(), line.size()) < 0) {
        err = "failed to write to " + state_file_path() + ": " + std::strerror(errno);
        flock(fd, LOCK_UN);
        close(fd);
        return false;
    }

    flock(fd, LOCK_UN);
    close(fd);
    return true;
}

bool load_state(std::vector<LeashState> &out, std::string &err) {
    int fd = open(state_file_path().c_str(), O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) return true;
        err = "unable to open " + state_file_path() + ": " + std::strerror(errno);
        return false;
    }
    if (flock(fd, LOCK_SH) != 0) {
        close(fd);
        err = "unable to lock " + state_file_path() + ": " + std::strerror(errno);
        return false;
    }

    // Read entire file into stringstream for parsing
    char buf[4096];
    std::string content;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        content.append(buf, n);
    }
    
    flock(fd, LOCK_UN);
    close(fd);

    std::istringstream in(content);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        LeashState st;
        if (iss >> st.pid >> st.uid >> st.starttime >> st.boot_id >> st.leash_id >> st.iface >> st.rate >> st.cgroup_path >> st.classid) {
            out.push_back(st);
            continue;
        }
        iss.clear();
        iss.str(line);
        if (iss >> st.pid >> st.starttime >> st.boot_id >> st.leash_id >> st.iface >> st.rate >> st.cgroup_path >> st.classid) {
            st.uid = -1;
            out.push_back(st);
        }
    }
    return true;
}

bool remove_state_by_pid(int pid, int uid, std::string &err) {
    int fd = open(state_file_path().c_str(), O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        err = "unable to open " + state_file_path() + " for rewrite: " + std::strerror(errno);
        return false;
    }
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        err = "unable to lock " + state_file_path() + " for rewrite: " + std::strerror(errno);
        return false;
    }

    char buf[4096];
    std::string content;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        content.append(buf, n);
    }

    std::vector<LeashState> all;
    std::istringstream in(content);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        LeashState st;
        if (iss >> st.pid >> st.uid >> st.starttime >> st.boot_id >> st.leash_id >> st.iface >> st.rate >> st.cgroup_path >> st.classid) {
            all.push_back(st);
        }
    }

    if (lseek(fd, 0, SEEK_SET) < 0 || ftruncate(fd, 0) != 0) {
        flock(fd, LOCK_UN);
        close(fd);
        err = "failed to truncate " + state_file_path();
        return false;
    }

    std::stringstream out;
    for (const auto &st : all) {
        if (st.pid == pid && (uid < 0 || st.uid == uid)) continue;
        out << st.pid << " " << st.uid << " " << st.starttime << " " << st.boot_id << " " << st.leash_id << " "
            << st.iface << " " << st.rate << " " << st.cgroup_path << " " << st.classid << "\n";
    }
    std::string out_str = out.str();
    if (write(fd, out_str.c_str(), out_str.size()) < 0) {
        err = "failed to write rewritten state: " + std::string(std::strerror(errno));
        flock(fd, LOCK_UN);
        close(fd);
        return false;
    }

    flock(fd, LOCK_UN);
    close(fd);
    return true;
}
