#include "leash_manager.h"
#include "bpf_filter.h"
#include "cgroup.h"
#include "proc.h"
#include "state.h"

#include <algorithm>
#include <cctype>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <vector>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

static volatile sig_atomic_t g_interrupted = 0;
static pid_t g_child_pid = -1;

static void on_signal(int sig) {
    g_interrupted = sig;
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGTERM);
    }
}

static std::string json_escape(const std::string &in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                const char hex[] = "0123456789ABCDEF";
                unsigned char v = static_cast<unsigned char>(c);
                out += "\\u00";
                out += hex[(v >> 4) & 0xF];
                out += hex[v & 0xF];
            } else {
                out += c;
            }
        }
    }
    return out;
}

bool parse_rate(const std::string &s, uint64_t &bytes_per_sec, std::string &err) {
    if (s.empty()) { err = "rate is empty"; return false; }
    // Split numeric prefix from unit suffix.
    size_t i = 0;
    while (i < s.size() && (std::isdigit((unsigned char)s[i]) || s[i] == '.')) i++;
    if (i == 0) { err = "rate must start with a number: " + s; return false; }
    std::string num = s.substr(0, i);
    std::string unit = s.substr(i);
    std::transform(unit.begin(), unit.end(), unit.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    double v = 0;
    try { v = std::stod(num); } catch (...) {
        err = "invalid rate number: " + num; return false;
    }
    if (v < 0) { err = "rate cannot be negative"; return false; }

    // tc-style: every unit is bits-per-second unless suffix says otherwise.
    double bps_bits = 0;
    if (unit == "" || unit == "bit" || unit == "bps") bps_bits = v;
    else if (unit == "kbit") bps_bits = v * 1000.0;
    else if (unit == "mbit") bps_bits = v * 1000.0 * 1000.0;
    else if (unit == "gbit") bps_bits = v * 1000.0 * 1000.0 * 1000.0;
    else if (unit == "kibit") bps_bits = v * 1024.0;
    else if (unit == "mibit") bps_bits = v * 1024.0 * 1024.0;
    else { err = "unknown rate unit '" + unit + "' (use bit/kbit/mbit/gbit)"; return false; }

    bytes_per_sec = static_cast<uint64_t>(bps_bits / 8.0);
    if (bytes_per_sec == 0) { err = "rate rounds to zero bytes/sec"; return false; }
    return true;
}

bool parse_bytes(const std::string &s, uint64_t &bytes, std::string &err) {
    if (s.empty()) { err = "burst is empty"; return false; }
    size_t i = 0;
    while (i < s.size() && (std::isdigit((unsigned char)s[i]) || s[i] == '.')) i++;
    if (i == 0) { err = "burst must start with a number: " + s; return false; }
    std::string num = s.substr(0, i);
    std::string unit = s.substr(i);
    std::transform(unit.begin(), unit.end(), unit.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    double v = 0;
    try { v = std::stod(num); } catch (...) {
        err = "invalid burst number: " + num; return false;
    }
    if (v < 0) { err = "burst cannot be negative"; return false; }

    double bytes_d = 0;
    if (unit == "" || unit == "b") bytes_d = v;
    else if (unit == "kb" || unit == "k") bytes_d = v * 1024.0;
    else if (unit == "mb" || unit == "m") bytes_d = v * 1024.0 * 1024.0;
    else { err = "unknown burst unit '" + unit + "' (use b/kb/mb)"; return false; }

    bytes = static_cast<uint64_t>(bytes_d);
    if (bytes == 0) { err = "burst rounds to zero bytes"; return false; }
    return true;
}

uint64_t default_burst(uint64_t rate_bps) {
    // rate * 50ms, with a floor of 2 MTU (~3KB).
    uint64_t burst = (rate_bps * 50) / 1000;   // 50ms worth of bytes
    uint64_t floor = 2 * 1500;
    return std::max(burst, floor);
}

LeashManager::LeashManager(uid_t caller_uid, gid_t caller_gid, bool enforce_owner)
    : m_real_uid(caller_uid), m_real_gid(caller_gid), m_enforce_owner(enforce_owner) {}

bool LeashManager::check_owner(int pid, std::string &err) {
    if (!m_enforce_owner || m_real_uid == 0) return true;
    uid_t owner = 0;
    if (!read_proc_uid(pid, owner, err)) {
        err = "unable to verify process ownership";
        return false;
    }
    if (owner != m_real_uid) {
        err = "pid is not owned by the caller";
        return false;
    }
    return true;
}

bool LeashManager::drop_to_real_user(std::string &err) {
    if (m_real_uid == 0) return true;
    struct passwd *pw = getpwuid(m_real_uid);
    if (pw) {
        if (initgroups(pw->pw_name, m_real_gid) != 0) {
            err = "initgroups failed";
            return false;
        }
    } else {
        if (setgroups(0, nullptr) != 0) {
            err = "setgroups failed";
            return false;
        }
    }
    if (setgid(m_real_gid) != 0) { err = "setgid failed"; return false; }
    if (setuid(m_real_uid) != 0) { err = "setuid failed"; return false; }
    return true;
}

bool LeashManager::cleanup_leash(const LeashContext &ctx, std::string &err) {
    bool ok = true;
    std::string tmp;
    // Detach BPF programs from the cgroup BEFORE removing the cgroup
    // (you can't open a removed cgroup to detach from it).
    if (!ctx.cgroup_path.empty() && !bpf_filter_detach_cgroup(ctx.cgroup_path, tmp)) {
        err = "bpf detach (cgroup): " + tmp;
        ok = false;
    }
    if (ctx.cgroup_id != 0 && !bpf_filter_detach(ctx.cgroup_id, tmp)) {
        if (ok) err = "bpf detach (map): " + tmp;
        ok = false;
    }
    if (!ctx.cgroup_path.empty() && !remove_cgroup_dir(ctx.cgroup_path, tmp)) {
        if (ok) err = "rmdir cgroup: " + tmp;
        ok = false;
    }
    return ok;
}

int LeashManager::list_leashes(bool json) {
    std::vector<LeashState> all;
    std::string err;
    if (!load_state(all, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (json) {
        std::cout << "[";
        bool first = true;
        for (const auto &st : all) {
            if (m_enforce_owner && m_real_uid != 0 && st.uid != static_cast<int>(m_real_uid)) continue;
            if (!first) std::cout << ",";
            first = false;
            std::cout << "{"
                      << "\"pid\":" << st.pid << ","
                      << "\"uid\":" << st.uid << ","
                      << "\"starttime\":" << st.starttime << ","
                      << "\"boot_id\":\"" << json_escape(st.boot_id) << "\","
                      << "\"leash_id\":" << st.leash_id << ","
                      << "\"egress_rate_bps\":" << st.egress_rate_bps << ","
                      << "\"egress_burst_bytes\":" << st.egress_burst_bytes << ","
                      << "\"ingress_rate_bps\":" << st.ingress_rate_bps << ","
                      << "\"ingress_burst_bytes\":" << st.ingress_burst_bytes << ","
                      << "\"cgroup_path\":\"" << json_escape(st.cgroup_path) << "\","
                      << "\"cgroup_id\":" << st.cgroup_id
                      << "}";
        }
        std::cout << "]\n";
    } else {
        for (const auto &st : all) {
            if (m_enforce_owner && m_real_uid != 0 && st.uid != static_cast<int>(m_real_uid)) continue;
            std::cout << st.pid << " " << st.uid << " " << st.starttime << " "
                      << st.boot_id << " " << st.leash_id << " "
                      << st.egress_rate_bps << " " << st.egress_burst_bytes << " "
                      << st.ingress_rate_bps << " " << st.ingress_burst_bytes << " "
                      << st.cgroup_path << " " << st.cgroup_id << "\n";
        }
    }
    return 0;
}

int LeashManager::clear_leash(int pid) {
    std::vector<LeashState> all;
    std::string err;
    if (!load_state(all, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    const LeashState *target = nullptr;
    for (const auto &st : all) {
        if (st.pid == pid) {
            if (m_enforce_owner && m_real_uid != 0 && st.uid != static_cast<int>(m_real_uid)) continue;
            target = &st;
            break;
        }
    }

    if (!target) {
        std::cerr << "nleash: no active leash for pid " << pid << "\n";
        return 1;
    }

    std::string boot_id;
    if (!read_boot_id(boot_id, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    bool identity_ok = true;
    if (boot_id != target->boot_id) identity_ok = false;
    if (!proc_exists(pid)) identity_ok = false;
    long long starttime = 0;
    if (identity_ok) {
        if (!read_proc_starttime(pid, starttime, err)) identity_ok = false;
        else if (starttime != target->starttime) identity_ok = false;
    }

    LeashContext ctx;
    ctx.pid = pid;
    ctx.leash_id = target->leash_id;
    ctx.cgroup_path = target->cgroup_path;
    ctx.cgroup_id = target->cgroup_id;

    if (!cleanup_leash(ctx, err)) {
        std::cerr << "nleash: cleanup failed: " << err << "\n";
        return 1;
    }
    int uid_filter = (m_enforce_owner && m_real_uid != 0) ? static_cast<int>(m_real_uid) : -1;
    if (!remove_state_by_pid(pid, uid_filter, err)) {
        std::cerr << "nleash: failed to update state: " << err << "\n";
        return 1;
    }

    if (!identity_ok) {
        std::cerr << "nleash: safety check failed; cleared bpf/cgroup only (pid reuse or reboot)\n";
    }
    return 0;
}

int LeashManager::show_stats(int pid, bool json) {
    std::vector<LeashState> all;
    std::string err;
    if (!load_state(all, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    bool found_any = false;
    if (json) std::cout << "[";

    for (const auto &st : all) {
        if (pid > 0 && st.pid != pid) continue;
        if (m_enforce_owner && m_real_uid != 0 && st.uid != static_cast<int>(m_real_uid)) continue;

        nleash_stats s;
        if (!bpf_filter_get_stats(st.cgroup_id, s, err)) {
            continue;
        }

        if (json) {
            if (found_any) std::cout << ",";
            std::cout << "{"
                      << "\"pid\":" << st.pid << ","
                      << "\"egress_rate_bps\":" << st.egress_rate_bps << ","
                      << "\"ingress_rate_bps\":" << st.ingress_rate_bps << ","
                      << "\"egress_pass_bytes\":" << s.egress_pass_bytes << ","
                      << "\"egress_drop_bytes\":" << s.egress_drop_bytes << ","
                      << "\"ingress_pass_bytes\":" << s.ingress_pass_bytes << ","
                      << "\"ingress_drop_bytes\":" << s.ingress_drop_bytes
                      << "}";
        } else {
            std::cout << "PID: " << st.pid
                      << " | EGRESS RATE: " << st.egress_rate_bps << " B/s"
                      << " | INGRESS RATE: " << st.ingress_rate_bps << " B/s\n"
                      << "  Egress  : pass=" << s.egress_pass_bytes
                      <<           " drop=" << s.egress_drop_bytes << " bytes\n"
                      << "  Ingress : pass=" << s.ingress_pass_bytes
                      <<           " drop=" << s.ingress_drop_bytes << " bytes\n";
        }
        found_any = true;
    }

    if (json) std::cout << "]\n";
    else if (!found_any) {
        if (pid > 0) std::cerr << "nleash: no active leash for pid " << pid << "\n";
        else std::cout << "No active leashes.\n";
        return 1;
    }
    return 0;
}

// Shared setup for both apply_leash and run_command. Resolves rates, sets up
// the cgroup directory, computes cgroup id, attaches BPF, persists state.
// On success, fills ctx; caller is responsible for moving pid(s) into the
// cgroup at the appropriate time (before vs after fork differs).
static bool prepare_cgroup(const std::string &rel_cgroup,
                           int leash_id,
                           LeashContext &ctx,
                           std::string &err) {
    std::string parent = (rel_cgroup == "/") ? cgroup_root() : (cgroup_root() + rel_cgroup);
    ctx.leash_id = leash_id;
    ctx.cgroup_path = parent + "/nleash-" + std::to_string(leash_id);
    if (!ensure_cgroup_dir(ctx.cgroup_path, err)) return false;
    return true;
}

// Resolve one direction's rate + burst. Empty rate string => 0 (unshaped).
static bool resolve_dir(const std::string &rate, const std::string &burst,
                        uint64_t &rate_bps, uint64_t &burst_bytes,
                        std::string &err) {
    if (rate.empty()) {
        rate_bps = 0;
        burst_bytes = 0;
        return true;
    }
    if (!parse_rate(rate, rate_bps, err)) return false;
    if (burst.empty()) {
        burst_bytes = default_burst(rate_bps);
    } else if (!parse_bytes(burst, burst_bytes, err)) {
        return false;
    }
    return true;
}

int LeashManager::apply_leash(int pid,
                              const std::string &egress_rate, const std::string &egress_burst,
                              const std::string &ingress_rate, const std::string &ingress_burst) {
    std::string err;
    uint64_t eg_rate = 0, eg_burst = 0, in_rate = 0, in_burst = 0;
    if (!resolve_dir(egress_rate, egress_burst, eg_rate, eg_burst, err) ||
        !resolve_dir(ingress_rate, ingress_burst, in_rate, in_burst, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    if (!check_cgroup_v2(err) || !ensure_state_dir(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!check_owner(pid, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    ProcIdentity id;
    id.pid = pid;
    if (!read_proc_starttime(pid, id.starttime_ticks, err) || !read_boot_id(id.boot_id, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    if (!bpf_filter_ensure_loaded(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    int leash_id = 0;
    if (!allocate_leash_id(leash_id, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    std::string rel_cgroup;
    if (!read_proc_cgroup_path(pid, rel_cgroup, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    LeashContext ctx;
    ctx.pid = pid;
    if (!prepare_cgroup(rel_cgroup, leash_id, ctx, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!move_pid_to_cgroup(pid, ctx.cgroup_path, err)) {
        std::cerr << "nleash: " << err << "\n";
        remove_cgroup_dir(ctx.cgroup_path, err);
        return 1;
    }

    std::string cgid_str;
    if (!read_cgroup_id(ctx.cgroup_path, cgid_str, err)) {
        std::cerr << "nleash: " << err << "\n";
        remove_cgroup_dir(ctx.cgroup_path, err);
        return 1;
    }
    try {
        ctx.cgroup_id = std::stoull(cgid_str);
    } catch (...) {
        std::cerr << "nleash: failed to parse cgroup id: " << cgid_str << "\n";
        remove_cgroup_dir(ctx.cgroup_path, err);
        return 1;
    }

    if (!bpf_filter_attach(ctx.cgroup_id, ctx.cgroup_path,
                           eg_rate, eg_burst, in_rate, in_burst, err)) {
        std::cerr << "nleash: bpf attach failed: " << err << "\n";
        remove_cgroup_dir(ctx.cgroup_path, err);
        return 1;
    }

    LeashState st;
    st.pid = pid;
    st.uid = static_cast<int>(m_real_uid);
    st.starttime = id.starttime_ticks;
    st.boot_id = id.boot_id;
    st.leash_id = leash_id;
    st.egress_rate_bps = eg_rate;
    st.egress_burst_bytes = eg_burst;
    st.ingress_rate_bps = in_rate;
    st.ingress_burst_bytes = in_burst;
    st.cgroup_path = ctx.cgroup_path;
    st.cgroup_id = ctx.cgroup_id;

    if (!append_state(st, err)) {
        std::cerr << "nleash: " << err << "\n";
        cleanup_leash(ctx, err);
        return 1;
    }
    return 0;
}

int LeashManager::run_command(const std::vector<std::string> &cmd_args,
                              const std::string &egress_rate, const std::string &egress_burst,
                              const std::string &ingress_rate, const std::string &ingress_burst) {
    std::string err;
    uint64_t eg_rate = 0, eg_burst = 0, in_rate = 0, in_burst = 0;
    if (!resolve_dir(egress_rate, egress_burst, eg_rate, eg_burst, err) ||
        !resolve_dir(ingress_rate, ingress_burst, in_rate, in_burst, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    if (!check_cgroup_v2(err) || !ensure_state_dir(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!bpf_filter_ensure_loaded(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    int leash_id = 0;
    if (!allocate_leash_id(leash_id, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    std::string rel_cgroup;
    if (!read_proc_cgroup_path(getpid(), rel_cgroup, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    LeashContext ctx;
    if (!prepare_cgroup(rel_cgroup, leash_id, ctx, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    std::string cgid_str;
    if (!read_cgroup_id(ctx.cgroup_path, cgid_str, err)) {
        std::cerr << "nleash: " << err << "\n";
        remove_cgroup_dir(ctx.cgroup_path, err);
        return 1;
    }
    try {
        ctx.cgroup_id = std::stoull(cgid_str);
    } catch (...) {
        std::cerr << "nleash: failed to parse cgroup id: " << cgid_str << "\n";
        remove_cgroup_dir(ctx.cgroup_path, err);
        return 1;
    }

    // Attach BEFORE fork so the child's first packet is already shaped.
    if (!bpf_filter_attach(ctx.cgroup_id, ctx.cgroup_path,
                           eg_rate, eg_burst, in_rate, in_burst, err)) {
        std::cerr << "nleash: bpf attach failed: " << err << "\n";
        remove_cgroup_dir(ctx.cgroup_path, err);
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "nleash: fork failed\n";
        cleanup_leash(ctx, err);
        return 1;
    }
    if (pid == 0) {
        std::string move_err;
        if (!move_pid_to_cgroup(getpid(), ctx.cgroup_path, move_err)) {
            std::cerr << "nleash: " << move_err << "\n";
            _exit(127);
        }
        std::string drop_err;
        if (!drop_to_real_user(drop_err)) {
            std::cerr << "nleash: " << drop_err << "\n";
            _exit(127);
        }
        std::vector<char *> argv;
        for (const auto &s : cmd_args) argv.push_back(const_cast<char *>(s.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        std::cerr << "nleash: execvp failed: " << std::strerror(errno) << "\n";
        _exit(127);
    }

    g_child_pid = pid;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    ctx.pid = pid;

    LeashState st;
    st.pid = pid;
    st.uid = static_cast<int>(m_real_uid);
    if (!read_proc_starttime(pid, st.starttime, err) || !read_boot_id(st.boot_id, err)) {
        std::cerr << "nleash: " << err << "\n";
    }
    st.leash_id = leash_id;
    st.egress_rate_bps = eg_rate;
    st.egress_burst_bytes = eg_burst;
    st.ingress_rate_bps = in_rate;
    st.ingress_burst_bytes = in_burst;
    st.cgroup_path = ctx.cgroup_path;
    st.cgroup_id = ctx.cgroup_id;

    if (!append_state(st, err)) {
        std::cerr << "nleash: " << err << "\n";
        kill(pid, SIGTERM);
        waitpid(pid, nullptr, 0);
        cleanup_leash(ctx, err);
        return 1;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    g_child_pid = -1;

    if (!cleanup_leash(ctx, err)) {
        std::cerr << "nleash: cleanup failed: " << err << "\n";
    }
    int uid_filter = (m_enforce_owner && m_real_uid != 0) ? static_cast<int>(m_real_uid) : -1;
    remove_state_by_pid(pid, uid_filter, err);

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
