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
    std::ofstream out(state_file_path(), std::ios::app);
    if (!out) {
        err = "unable to open /run/nleash/state.txt";
        return false;
    }
    out << st.pid << " " << st.uid << " " << st.starttime << " " << st.boot_id << " " << st.leash_id << " "
        << st.iface << " " << st.rate << " " << st.cgroup_path << " " << st.classid << "\n";
    if (!out) {
        err = "failed to write /run/nleash/state.txt";
        return false;
    }
    return true;
}

bool load_state(std::vector<LeashState> &out, std::string &err) {
    std::ifstream in(state_file_path());
    if (!in) {
        if (access(state_file_path().c_str(), F_OK) != 0 && errno == ENOENT) return true;
        err = "unable to open /run/nleash/state.txt";
        return false;
    }
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
    std::vector<LeashState> all;
    if (!load_state(all, err)) return false;
    std::ofstream out(state_file_path(), std::ios::trunc);
    if (!out) {
        err = "unable to open /run/nleash/state.txt for rewrite";
        return false;
    }
    for (const auto &st : all) {
        if (st.pid == pid && (uid < 0 || st.uid == uid)) continue;
        out << st.pid << " " << st.uid << " " << st.starttime << " " << st.boot_id << " " << st.leash_id << " "
            << st.iface << " " << st.rate << " " << st.cgroup_path << " " << st.classid << "\n";
    }
    return true;
}
