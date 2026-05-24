#pragma once

#include <string>
#include <vector>
#include "state.h"
#include "tc.h"

struct LeashContext {
    int leash_id = 0;
    std::string iface;
    std::string cgroup_path;
    std::string cgroup_id;
    int pid = -1;
};

class LeashManager {
public:
    LeashManager(uid_t caller_uid, gid_t caller_gid, bool enforce_owner);

    int list_leashes(bool json);
    int clear_leash(int pid);
    int apply_leash(int pid, const std::string& rate, const std::string& iface_opt);
    int run_command(const std::vector<std::string>& cmd_args, const std::string& rate, const std::string& iface_opt);

private:
    bool setup_context(int pid, const std::string& iface_opt, LeashContext& ctx, std::string& err);
    bool apply_tc_and_state(const LeashContext& ctx, const LeashState& st, std::string& err);
    bool cleanup_leash(const LeashContext& ctx, std::string& err);
    bool check_owner(int pid, std::string& err);
    bool drop_to_real_user(std::string& err);

    uid_t m_real_uid;
    gid_t m_real_gid;
    bool m_enforce_owner;
};
