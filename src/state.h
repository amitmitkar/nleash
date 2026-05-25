#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct LeashState {
    int pid = -1;
    int uid = -1;
    long long starttime = 0;
    std::string boot_id;
    int leash_id = 0;
    uint64_t rate_bps = 0;
    uint64_t burst_bytes = 0;
    std::string cgroup_path;
    uint64_t cgroup_id = 0;   // BPF map key
};

bool ensure_state_dir(std::string &err);
bool allocate_leash_id(int &out_id, std::string &err);

bool append_state(const LeashState &st, std::string &err);
bool load_state(std::vector<LeashState> &out, std::string &err);
bool remove_state_by_pid(int pid, int uid, std::string &err);

std::string state_file_path();
std::string nextid_file_path();
