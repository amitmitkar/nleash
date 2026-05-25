#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "state.h"

struct LeashContext {
    int leash_id = 0;
    std::string cgroup_path;
    uint64_t cgroup_id = 0;
    int pid = -1;
};

class LeashManager {
public:
    LeashManager(uid_t caller_uid, gid_t caller_gid, bool enforce_owner);

    int list_leashes(bool json);
    int clear_leash(int pid);
    int show_stats(int pid, bool json);
    int apply_leash(int pid, const std::string &rate, const std::string &burst);
    int run_command(const std::vector<std::string> &cmd_args,
                    const std::string &rate, const std::string &burst);

private:
    bool cleanup_leash(const LeashContext &ctx, std::string &err);
    bool check_owner(int pid, std::string &err);
    bool drop_to_real_user(std::string &err);

    uid_t m_real_uid;
    gid_t m_real_gid;
    bool m_enforce_owner;
};

// Parse a tc-style rate string ("500kbit", "10mbit", "1gbit", "1500bit")
// into bytes-per-second. Returns false with `err` set on bad input.
bool parse_rate(const std::string &s, uint64_t &bytes_per_sec, std::string &err);

// Parse a byte-size string ("3000", "16kb", "1mb") into bytes. Empty input is
// rejected.
bool parse_bytes(const std::string &s, uint64_t &bytes, std::string &err);

// Default burst when the user didn't supply --burst.
uint64_t default_burst(uint64_t rate_bps);
