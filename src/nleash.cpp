#include "nleash.h"
#include "cli.h"
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
#include <string>
#include <vector>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

static volatile sig_atomic_t g_interrupted = 0;
static pid_t g_child_pid = -1;
static uid_t g_real_uid = 0;
static gid_t g_real_gid = 0;
static bool g_enforce_owner = false;

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

static bool read_identity(int pid, ProcIdentity &id, std::string &err) {
    id.pid = pid;
    if (!read_proc_starttime(pid, id.starttime_ticks, err)) return false;
    if (!read_boot_id(id.boot_id, err)) return false;
    return true;
}

static bool get_parent_cgroup_path(int pid, std::string &out, std::string &err) {
    std::string rel;
    if (!read_proc_cgroup_path(pid, rel, err)) return false;
    std::string root = cgroup_root();
    if (rel == "/") {
        out = root;
    } else {
        out = root + rel;
    }
    return true;
}

static bool check_owner(int pid, std::string &err) {
    if (!g_enforce_owner || g_real_uid == 0) return true;
    uid_t owner = 0;
    if (!read_proc_uid(pid, owner, err)) {
        err = "unable to verify process ownership";
        return false;
    }
    if (owner != g_real_uid) {
        err = "pid is not owned by the caller";
        return false;
    }
    return true;
}

static bool drop_to_real_user(std::string &err) {
    if (g_real_uid == 0) return true;
    struct passwd *pw = getpwuid(g_real_uid);
    if (pw) {
        if (initgroups(pw->pw_name, g_real_gid) != 0) {
            err = "initgroups failed";
            return false;
        }
    } else {
        if (setgroups(0, nullptr) != 0) {
            err = "setgroups failed";
            return false;
        }
    }
    if (setgid(g_real_gid) != 0) {
        err = "setgid failed";
        return false;
    }
    if (setuid(g_real_uid) != 0) {
        err = "setuid failed";
        return false;
    }
    return true;
}

struct LeashContext {
    int leash_id = 0;
    std::string iface;
    std::string cgroup_path;
    std::string cgroup_id;
    int pid = -1;
};

static bool cleanup_leash(const LeashContext &ctx, std::string &err) {
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

static bool apply_tc_and_state(const LeashContext &ctx, const LeashState &st, std::string &err) {
    if (!tc_setup_root(ctx.iface, err)) return false;
    if (!tc_setup_parent_class(ctx.iface, err)) return false;
    if (!tc_setup_leash_class(ctx.iface, ctx.leash_id, st.rate, err)) return false;
    if (!tc_setup_filter(ctx.iface, ctx.cgroup_id, ctx.leash_id, err)) return false;
    if (!append_state(st, err)) return false;
    return true;
}

static int do_list(bool json) {
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
            if (g_enforce_owner && g_real_uid != 0 && st.uid != static_cast<int>(g_real_uid)) continue;
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
            if (g_enforce_owner && g_real_uid != 0 && st.uid != static_cast<int>(g_real_uid)) continue;
            std::cout << st.pid << " " << st.uid << " " << st.starttime << " " << st.boot_id << " "
                      << st.leash_id << " " << st.iface << " " << st.rate << " "
                      << st.cgroup_path << " " << st.classid << "\n";
        }
    }
    return 0;
}

static int do_clear(int pid) {
    std::vector<LeashState> all;
    std::string err;
    if (!load_state(all, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    LeashState target;
    bool found = false;
    for (const auto &st : all) {
        if (st.pid == pid) { target = st; found = true; break; }
    }
    if (!found) {
        std::cerr << "nleash: no state for pid " << pid << "\n";
        return 1;
    }
    if (g_enforce_owner && g_real_uid != 0) {
        if (target.uid == -1) {
            if (proc_exists(pid)) {
                std::string own_err;
                if (!check_owner(pid, own_err)) {
                    std::cerr << "nleash: " << own_err << "\n";
                    return 1;
                }
            } else {
                std::cerr << "nleash: cannot verify ownership of stale entry (run as root)\n";
                return 1;
            }
        } else if (target.uid != static_cast<int>(g_real_uid)) {
            std::cerr << "nleash: state entry not owned by caller\n";
            return 1;
        }
    }

    std::string boot_id;
    if (!read_boot_id(boot_id, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    bool identity_ok = true;
    if (boot_id != target.boot_id) identity_ok = false;
    if (!proc_exists(pid)) identity_ok = false;
    long long starttime = 0;
    if (identity_ok) {
        if (!read_proc_starttime(pid, starttime, err)) {
            identity_ok = false;
        } else if (starttime != target.starttime) {
            identity_ok = false;
        }
    }

    LeashContext ctx;
    ctx.pid = pid;
    ctx.leash_id = target.leash_id;
    ctx.iface = target.iface;
    ctx.cgroup_path = target.cgroup_path;
    ctx.cgroup_id.clear();
    std::string cgid;
    if (read_cgroup_id(target.cgroup_path, cgid, err)) {
        ctx.cgroup_id = cgid;
    }

    if (!cleanup_leash(ctx, err)) {
        std::cerr << "nleash: cleanup failed: " << err << "\n";
        return 1;
    }
    int uid_filter = (g_enforce_owner && g_real_uid != 0) ? static_cast<int>(g_real_uid) : -1;
    if (!remove_state_by_pid(pid, uid_filter, err)) {
        std::cerr << "nleash: failed to update state: " << err << "\n";
        return 1;
    }

    if (!identity_ok) {
        std::cerr << "nleash: safety check failed; cleared tc/cgroup only (pid reuse or reboot)\n";
    }
    return 0;
}

static int do_apply_existing(const CliOptions &opt) {
    std::string err;
    if (!check_tools(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!ensure_cls_cgroup(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!check_cgroup_v2(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!check_cgroup_id_support(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!ensure_state_dir(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    if (!check_owner(opt.pid, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    ProcIdentity id;
    if (!read_identity(opt.pid, id, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    std::string iface = opt.iface;
    if (iface.empty()) {
        if (!detect_default_iface(iface, err)) {
            std::cerr << "nleash: " << err << "\n";
            return 1;
        }
    }

    int leash_id = 0;
    if (!allocate_leash_id(leash_id, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    std::string parent;
    if (!get_parent_cgroup_path(opt.pid, parent, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    std::string child = parent + "/nleash-" + std::to_string(leash_id);
    if (!ensure_cgroup_dir(child, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!move_pid_to_cgroup(opt.pid, child, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    std::string cgid;
    if (!read_cgroup_id(child, cgid, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    LeashState st;
    st.pid = opt.pid;
    st.uid = static_cast<int>(g_real_uid);
    st.starttime = id.starttime_ticks;
    st.boot_id = id.boot_id;
    st.leash_id = leash_id;
    st.iface = iface;
    st.rate = opt.rate;
    st.cgroup_path = child;
    st.classid = "1:" + std::to_string(leash_id);

    LeashContext ctx;
    ctx.pid = opt.pid;
    ctx.leash_id = leash_id;
    ctx.iface = iface;
    ctx.cgroup_path = child;
    ctx.cgroup_id = cgid;

    if (!apply_tc_and_state(ctx, st, err)) {
        std::cerr << "nleash: " << err << "\n";
        cleanup_leash(ctx, err);
        return 1;
    }
    return 0;
}

static int do_run_command(const CliOptions &opt) {
    std::string err;
    if (!check_tools(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!ensure_cls_cgroup(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!check_cgroup_v2(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!check_cgroup_id_support(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
    if (!ensure_state_dir(err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    std::string iface = opt.iface;
    if (iface.empty()) {
        if (!detect_default_iface(iface, err)) {
            std::cerr << "nleash: " << err << "\n";
            return 1;
        }
    }

    int leash_id = 0;
    if (!allocate_leash_id(leash_id, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    std::string parent;
    if (!get_parent_cgroup_path(getpid(), parent, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }
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
        for (const auto &s : opt.cmd) argv.push_back(const_cast<char *>(s.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        std::cerr << "nleash: failed to exec " << opt.cmd[0] << "\n";
        _exit(127);
    }

    g_child_pid = pid;

    ProcIdentity id;
    if (!read_identity(pid, id, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    std::string cgid;
    if (!read_cgroup_id(child, cgid, err)) {
        std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    LeashState st;
    st.pid = pid;
    st.uid = static_cast<int>(g_real_uid);
    st.starttime = id.starttime_ticks;
    st.boot_id = id.boot_id;
    st.leash_id = leash_id;
    st.iface = iface;
    st.rate = opt.rate;
    st.cgroup_path = child;
    st.classid = "1:" + std::to_string(leash_id);

    LeashContext ctx;
    ctx.pid = pid;
    ctx.leash_id = leash_id;
    ctx.iface = iface;
    ctx.cgroup_path = child;
    ctx.cgroup_id = cgid;

    if (!apply_tc_and_state(ctx, st, err)) {
        std::cerr << "nleash: " << err << "\n";
        cleanup_leash(ctx, err);
        return 1;
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR && g_interrupted) break;
        if (errno == EINTR) continue;
        break;
    }

    cleanup_leash(ctx, err);
    int uid_filter = (g_enforce_owner && g_real_uid != 0) ? static_cast<int>(g_real_uid) : -1;
    remove_state_by_pid(pid, uid_filter, err);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

static void print_usage() {
    std::cerr << "Usage:\n"
              << "  nleash --pid <PID> --rate <RATE> [--iface <IFACE>]\n"
              << "  nleash --rate <RATE> [--iface <IFACE>] -- <cmd> [args...]\n"
              << "  nleash --pid <PID> --clear\n"
              << "  nleash --list [--json]\n";
}

int nleash_run(int argc, char **argv, bool enforce_owner) {
    if (geteuid() != 0) {
        std::cerr << "nleash: must be run with elevated privileges (requires CAP_NET_ADMIN and cgroup write permissions)\n";
        return 1;
    }

    g_real_uid = getuid();
    g_real_gid = getgid();
    g_enforce_owner = enforce_owner;

    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    CliOptions opt;
    std::string err;
    if (!parse_cli(argc, argv, opt, err)) {
        std::cerr << "nleash: " << err << "\n";
        print_usage();
        return 1;
    }

    if (opt.list) {
        return do_list(opt.json);
    }

    if (opt.clear) {
        if (!opt.has_pid) {
            std::cerr << "nleash: --clear requires --pid\n";
            return 1;
        }
        return do_clear(opt.pid);
    }

    if (!opt.cmd.empty()) {
        if (opt.rate.empty()) {
            std::cerr << "nleash: --rate is required\n";
            return 1;
        }
        return do_run_command(opt);
    }

    if (opt.has_pid) {
        if (opt.rate.empty()) {
            std::cerr << "nleash: --rate is required\n";
            return 1;
        }
        return do_apply_existing(opt);
    }

    print_usage();
    return 1;
}
