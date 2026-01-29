#include "proc.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

bool read_boot_id(std::string &out, std::string &err) {
    std::ifstream in("/proc/sys/kernel/random/boot_id");
    if (!in) {
        err = "unable to read /proc/sys/kernel/random/boot_id";
        return false;
    }
    std::getline(in, out);
    if (out.empty()) {
        err = "boot_id is empty";
        return false;
    }
    return true;
}

bool read_proc_starttime(int pid, long long &out, std::string &err) {
    std::string path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream in(path);
    if (!in) {
        err = "unable to read " + path;
        return false;
    }
    std::string line;
    std::getline(in, line);
    if (line.empty()) {
        err = "empty stat line for pid";
        return false;
    }

    // stat format: pid (comm) state ...
    size_t lparen = line.find('(');
    size_t rparen = line.rfind(')');
    if (lparen == std::string::npos || rparen == std::string::npos || rparen <= lparen) {
        err = "unexpected /proc/<pid>/stat format";
        return false;
    }

    std::string rest = line.substr(rparen + 2);
    std::istringstream iss(rest);
    std::string field;
    std::vector<std::string> fields;
    while (iss >> field) {
        fields.push_back(field);
    }
    if (fields.size() < 20) {
        err = "unexpected /proc/<pid>/stat field count";
        return false;
    }
    // starttime is field 22 overall, index 19 in fields starting at field 3.
    try {
        out = std::stoll(fields[19]);
    } catch (...) {
        err = "failed to parse starttime";
        return false;
    }
    return true;
}

bool proc_exists(int pid) {
    std::string path = "/proc/" + std::to_string(pid);
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

bool read_proc_uid(int pid, uid_t &out, std::string &err) {
    std::string path = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream in(path);
    if (!in) {
        err = "unable to read " + path;
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("Uid:", 0) == 0) {
            std::istringstream iss(line);
            std::string label;
            uid_t real_uid = 0;
            if (iss >> label >> real_uid) {
                out = real_uid;
                return true;
            }
            break;
        }
    }
    err = "unable to parse uid from /proc/<pid>/status";
    return false;
}

bool read_proc_cgroup_path(int pid, std::string &out_path, std::string &err) {
    std::string path = "/proc/" + std::to_string(pid) + "/cgroup";
    std::ifstream in(path);
    if (!in) {
        err = "unable to read " + path;
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        // cgroup v2 line is: 0::/path
        if (line.rfind("0::", 0) == 0) {
            out_path = line.substr(3);
            if (out_path.empty()) out_path = "/";
            return true;
        }
    }
    err = "no unified cgroup v2 entry found in /proc/<pid>/cgroup";
    return false;
}
