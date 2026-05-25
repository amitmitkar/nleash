#include "leash_manager.h"
#include "cgroup.h"
#include "netutil.h"
#include "proc.h"
#include "state.h"
#include "tc.h"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <cerrno>
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
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
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
    if (setgid(m_real_gid) != 0) {
        err = "setgid failed";
        return false;
    }
    if (setuid(m_real_uid) != 0) {
        err = "setuid failed";
        return false;
    }
    return true;
}

bool LeashManager::cleanup_leash(const LeashContext &ctx, std::string &err) {
    std::string tmp;
    bool ok = true;
    if (!ctx.cgroup_id.empty()) {
        if (!tc_remove_filter(ctx.iface, ctx.cgroup_id, tmp)) {
            err = "failed to remove tc filter";
            ok = false;
        }
    }
    if (!tc_remove_class(ctx.iface, ctx.leash_id, tmp)) {
        err = "failed to remove tc class";
        ok = false;
    }
    if (!remove_cgroup_dir(ctx.cgroup_path, tmp)) {
        err = "failed to remove cgroup";
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
                      << "\"iface\":\"" << json_escape(st.iface) << "\","
                      << "\"rate\":\"" << json_escape(st.rate) << "\","
                      << "\"cgroup_path\":\"" << json_escape(st.cgroup_path) << "\","
                      << "\"classid\":\"" << json_escape(st.classid) << "\""
                      << "}";
        }
        std::cout << "]\n";
    } else {
        for (const auto &st : all) {
            if (m_enforce_owner && m_real_uid != 0 && st.uid != static_cast<int>(m_real_uid)) continue;
            std::cout << st.pid << " " << st.uid << " " << st.starttime << " " << st.boot_id << " "
                      << st.leash_id << " " << st.iface << " " << st.rate << " "
                      << st.cgroup_path << " " << st.classid << "\n";
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
        if (!read_proc_starttime(pid, starttime, err)) {
            identity_ok = false;
        } else if (starttime != target->starttime) {
            identity_ok = false;
        }
    }

    LeashContext ctx;
    ctx.pid = pid;
    ctx.leash_id = target->leash_id;
    ctx.iface = target->iface;
    ctx.cgroup_path = target->cgroup_path;
    ctx.cgroup_id.clear();
    std::string cgid;
    if (read_cgroup_id(target->cgroup_path, cgid, err)) {
        ctx.cgroup_id = cgid;
    }

    // Detect TC filter method for cleanup
    TcFilterMethod filter_method = detect_tc_filter_method(err);
    if (filter_method != TcFilterMethod::UNKNOWN) {
        tc_init_filter_method(filter_method, ctx.iface, err);
    }

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
        std::cerr << "nleash: safety check failed; cleared tc/cgroup only (pid reuse or reboot)\n";
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

        TcStats stats;
        if (!tc_get_stats(st.iface, st.leash_id, stats, err)) {
            // Stats might fail if tc class is gone but state exists
            continue;
        }

        if (json) {
            if (found_any) std::cout << ",";
            std::cout << "{"
                      << "\"pid\":" << st.pid << ","
                      << "\"bytes\":" << stats.bytes << ","
                      << "\"packets\":" << stats.packets << ","
                      << "\"dropped\":" << stats.drops << ","
                      << "\"overlimits\":" << stats.overlimits << ","
                      << "\"bps\":" << stats.bps << ","
                      << "\"pps\":" << stats.pps
                      << "}";
        } else {
            std::cout << "PID: " << st.pid << " | IFACE: " << st.iface << " | RATE: " << st.rate << "\n"
                      << "  Sent: " << stats.bytes << " bytes, " << stats.packets << " packets\n"
                      << "  Dropped: " << stats.drops << ", Overlimits: " << stats.overlimits << "\n"
                      << "  Current Rate: " << stats.bps << " bps, " << stats.pps << " pps\n";
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

int LeashManager::apply_leash(int pid, const std::string& rate, const std::string& iface_opt) {
    std::string err;
    if (!check_tools(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    TcFilterMethod filter_method = detect_tc_filter_method(err);
    if (filter_method == TcFilterMethod::UNKNOWN) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    if (!check_cgroup_v2(err) || !check_cgroup_id_support(err) || !ensure_state_dir(err)) {
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

    std::string iface = iface_opt;
    if (iface.empty() && !detect_default_iface(iface, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    if (!tc_setup_root(iface, err) || !tc_setup_parent_class(iface, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    if (!tc_init_filter_method(filter_method, iface, err)) {
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
    std::string parent = (rel_cgroup == "/") ? cgroup_root() : (cgroup_root() + rel_cgroup);
    std::string child = parent + "/nleash-" + std::to_string(leash_id);

    if (!ensure_cgroup_dir(child, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!move_pid_to_cgroup(pid, child, err)) {
        std::cerr << "nleash: " << err << "\n";
        remove_cgroup_dir(child, err);
        return 1;
    }

    std::string cgid;
    if (!read_cgroup_id(child, cgid, err)) {
        std::cerr << "nleash: " << err << "\n";
        remove_cgroup_dir(child, err);
        return 1;
    }

    LeashState st;
    st.pid = pid;
    st.uid = static_cast<int>(m_real_uid);
    st.starttime = id.starttime_ticks;
    st.boot_id = id.boot_id;
    st.leash_id = leash_id;
    st.iface = iface;
    st.rate = rate;
    st.cgroup_path = child;
    st.classid = "1:" + std::to_string(leash_id);

    LeashContext ctx;
    ctx.pid = pid;
    ctx.leash_id = leash_id;
    ctx.iface = iface;
    ctx.cgroup_path = child;
    ctx.cgroup_id = cgid;

    if (!tc_setup_leash_class(ctx.iface, ctx.leash_id, st.rate, err) ||
        !tc_setup_filter(ctx.iface, ctx.cgroup_id, ctx.leash_id, err) ||
        !append_state(st, err)) {
        std::cerr << "nleash: " << err << "\n";
        cleanup_leash(ctx, err);
        return 1;
    }
    return 0;
}

int LeashManager::run_command(const std::vector<std::string>& cmd_args, const std::string& rate, const std::string& iface_opt) {
    std::string err;
    if (!check_tools(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    TcFilterMethod filter_method = detect_tc_filter_method(err);
    if (filter_method == TcFilterMethod::UNKNOWN) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    if (!check_cgroup_v2(err) || !check_cgroup_id_support(err) || !ensure_state_dir(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    std::string iface = iface_opt;
    if (iface.empty() && !detect_default_iface(iface, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    if (!tc_setup_root(iface, err) || !tc_setup_parent_class(iface, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    if (!tc_init_filter_method(filter_method, iface, err)) {
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
    std::string parent = (rel_cgroup == "/") ? cgroup_root() : (cgroup_root() + rel_cgroup);
    std::string child = parent + "/nleash-" + std::to_string(leash_id);
    if (!ensure_cgroup_dir(child, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "nleash: fork failed\n";
        return 1;
    }
    if (pid == 0) {
        std::string move_err;
        if (!move_pid_to_cgroup(getpid(), child, move_err)) {
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

    std::string cgid;
    if (!read_cgroup_id(child, cgid, err)) {
        std::cerr << "nleash: " << err << "\n";
        remove_cgroup_dir(child, err);
        return 1;
    }

    LeashState st;
    st.pid = pid;
    st.uid = static_cast<int>(m_real_uid);
    if (!read_proc_starttime(pid, st.starttime, err) || !read_boot_id(st.boot_id, err)) {
        std::cerr << "nleash: " << err << "\n";
    }
    st.leash_id = leash_id;
    st.iface = iface;
    st.rate = rate;
    st.cgroup_path = child;
    st.classid = "1:" + std::to_string(leash_id);

    LeashContext ctx;
    ctx.pid = pid;
    ctx.leash_id = leash_id;
    ctx.iface = iface;
    ctx.cgroup_path = child;
    ctx.cgroup_id = cgid;

    if (!tc_setup_leash_class(ctx.iface, ctx.leash_id, st.rate, err) ||
        !tc_setup_filter(ctx.iface, ctx.cgroup_id, ctx.leash_id, err) ||
        !append_state(st, err)) {
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
