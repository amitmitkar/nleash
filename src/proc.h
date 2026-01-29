#pragma once

#include <string>
#include <sys/types.h>

struct ProcIdentity {
    int pid = -1;
    long long starttime_ticks = 0;
    std::string boot_id;
};

bool read_boot_id(std::string &out, std::string &err);
bool read_proc_starttime(int pid, long long &out, std::string &err);
bool proc_exists(int pid);
bool read_proc_uid(int pid, uid_t &out, std::string &err);

bool read_proc_cgroup_path(int pid, std::string &out_path, std::string &err);
