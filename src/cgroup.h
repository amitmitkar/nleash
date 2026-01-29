#pragma once

#include <string>

struct CgroupInfo {
    std::string parent_path;   // /sys/fs/cgroup/...
    std::string child_path;    // /sys/fs/cgroup/.../nleash-<id>
    std::string cgroup_id;     // contents of cgroup.id
};

bool check_cgroup_v2(std::string &err);
bool ensure_cgroup_dir(const std::string &path, std::string &err);
bool move_pid_to_cgroup(int pid, const std::string &path, std::string &err);
bool read_cgroup_id(const std::string &path, std::string &out, std::string &err);
bool remove_cgroup_dir(const std::string &path, std::string &err);

std::string cgroup_root();
