#include "tc.h"
#include "tc_cgroup.skel.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <linux/limits.h>
#include <linux/if_link.h>
#include <linux/pkt_cls.h>

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>

extern char **environ;

// Global state for which TC filter method is in use
static TcFilterMethod g_filter_method = TcFilterMethod::UNKNOWN;
static struct tc_cgroup_bpf *g_skel = nullptr;

static bool run_cmd_lit(std::initializer_list<const char *> args, std::string &err) {
    if (args.size() == 0) {
        err = "internal error: empty command";
        return false;
    }
    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (const char *s : args) {
        char *dup = strdup(s);
        if (!dup) {
            err = "memory allocation failed";
            for (char *p : argv) free(p);
            return false;
        }
        argv.push_back(dup);
    }
    argv.push_back(nullptr);

    pid_t pid = -1;
    int rc = posix_spawnp(&pid, argv[0], nullptr, nullptr, argv.data(), environ);
    if (rc != 0) {
        for (char *p : argv) free(p);
        err = "failed to execute " + std::string(argv[0]) + ": " + std::strerror(rc);
        return false;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        for (char *p : argv) free(p);
        err = "waitpid failed for " + std::string(argv[0]);
        return false;
    }
    for (char *p : argv) free(p);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        err = "command failed: " + std::string(argv[0]);
        return false;
    }
    return true;
}

static bool run_cmd(const std::vector<std::string> &args, std::string &err) {
    if (args.empty()) {
        err = "internal error: empty command";
        return false;
    }
    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (const auto &s : args) {
        char *dup = strdup(s.c_str());
        if (!dup) {
            err = "memory allocation failed";
            return false;
        }
        argv.push_back(dup);
    }
    argv.push_back(nullptr);

    pid_t pid = -1;
    int rc = posix_spawnp(&pid, argv[0], nullptr, nullptr, argv.data(), environ);
    if (rc != 0) {
        for (char *p : argv) free(p);
        err = "failed to execute " + args[0] + ": " + std::strerror(rc);
        return false;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        for (char *p : argv) free(p);
        err = "waitpid failed for " + args[0];
        return false;
    }
    for (char *p : argv) free(p);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        err = "command failed: " + args[0];
        return false;
    }
    return true;
}

bool check_tools(std::string &err) {
    if (!run_cmd_lit({"tc", "-V"}, err)) {
        err = "tc not available or not executable";
        return false;
    }
    if (!run_cmd_lit({"ip", "-V"}, err)) {
        err = "ip not available or not executable";
        return false;
    }
    if (!run_cmd_lit({"modprobe", "-V"}, err)) {
        err = "modprobe not available or not executable";
        return false;
    }
    return true;
}

bool ensure_cls_cgroup(std::string &err) {
    std::string dummy;
    run_cmd_lit({"modprobe", "cls_cgroup"}, dummy); // best effort
    struct stat st;
    if (stat("/sys/module/cls_cgroup", &st) != 0) {
        struct utsname uts;
        if (uname(&uts) == 0) {
            std::string cfg = std::string("/boot/config-") + uts.release;
            std::ifstream in(cfg);
            if (in) {
                std::string line;
                while (std::getline(in, line)) {
                    if (line.rfind("CONFIG_NET_CLS_CGROUP=", 0) == 0) {
                        if (line == "CONFIG_NET_CLS_CGROUP=y") return true;
                        err = "cls_cgroup not available (CONFIG_NET_CLS_CGROUP is not enabled)";
                        return false;
                    }
                }
            }
        }
        err = "cls_cgroup kernel module not loaded and not available (module missing or built-in config unknown)";
        return false;
    }
    return true;
}

static bool check_bpf_support(std::string &err) {
    std::string dummy;
    if (!run_cmd_lit({"clang", "--version"}, dummy)) {
        err = "clang not available (needed for eBPF support)";
        return false;
    }

    struct utsname uts;
    if (uname(&uts) != 0) {
        err = "failed to get kernel version";
        return false;
    }

    int major = 0, minor = 0;
    if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
        err = "failed to parse kernel version";
        return false;
    }

    if (major < 4 || (major == 4 && minor < 18)) {
        err = "kernel too old for eBPF cgroup classification (need >= 4.18)";
        return false;
    }

    return true;
}

TcFilterMethod detect_tc_filter_method(std::string &err) {
    struct utsname uts;
    if (uname(&uts) == 0) {
        int major = 0, minor = 0;
        if (sscanf(uts.release, "%d.%d", &major, &minor) == 2) {
            if (major >= 6) {
                std::string bpf_err;
                if (check_bpf_support(bpf_err)) {
                    return TcFilterMethod::BPF;
                }
            }
        }
    }

    std::string cls_err;
    if (ensure_cls_cgroup(cls_err)) {
        return TcFilterMethod::CLS_CGROUP;
    }

    std::string bpf_err;
    if (check_bpf_support(bpf_err)) {
        return TcFilterMethod::BPF;
    }

    err = "No suitable TC filter method available.\n";
    err += "  cls_cgroup: " + cls_err + "\n";
    err += "  eBPF: " + bpf_err;
    return TcFilterMethod::UNKNOWN;
}

static std::string get_bpf_obj_path() {
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        return "/usr/lib/nleash/tc_cgroup.bpf.o";
    }
    exe_path[len] = '\0';
    char *last_slash = strrchr(exe_path, '/');
    if (!last_slash) {
        return "/usr/lib/nleash/tc_cgroup.bpf.o";
    }
    *last_slash = '\0';
    return std::string(exe_path) + "/tc_cgroup.bpf.o";
}

bool tc_init_filter_method(TcFilterMethod method, const std::string &iface, std::string &err) {
    g_filter_method = method;

    if (method == TcFilterMethod::CLS_CGROUP) {
        return true;
    }

    if (method == TcFilterMethod::BPF) {
        if (g_skel) return true;

        g_skel = tc_cgroup_bpf__open_and_load();
        if (!g_skel) {
            err = "failed to open and load BPF skeleton";
            return false;
        }

        std::string obj_path = get_bpf_obj_path();
        std::vector<std::string> load_cmd = {
            "tc", "filter", "replace",
            "dev", iface,
            "parent", "1:",
            "protocol", "all",
            "prio", "1",
            "bpf",
            "object-file", obj_path,
            "section", "classifier",
            "direct-action"
        };

        if (!run_cmd(load_cmd, err)) {
            err = "failed to load eBPF classifier via tc: " + err;
            tc_cgroup_bpf__destroy(g_skel);
            g_skel = nullptr;
            return false;
        }

        return true;
    }

    err = "unknown TC filter method";
    return false;
}

void tc_cleanup_filter_method(TcFilterMethod method, const std::string &iface) {
    if (method == TcFilterMethod::BPF) {
        std::string dummy;
        run_cmd({"tc", "filter", "del", "dev", iface, "parent", "1:", "prio", "1"}, dummy);
        if (g_skel) {
            tc_cgroup_bpf__destroy(g_skel);
            g_skel = nullptr;
        }
    }
    g_filter_method = TcFilterMethod::UNKNOWN;
}

bool tc_setup_root(const std::string &iface, std::string &err) {
    std::string out;
    if (run_cmd_capture({"tc", "qdisc", "show", "dev", iface, "root"}, out, err)) {
        if (out.find("htb") != std::string::npos && (out.find("handle 1:") != std::string::npos || out.find("1:") != std::string::npos)) {
            std::string dummy;
            run_cmd({"tc", "class", "replace", "dev", iface, "parent", "1:", "classid", "1:30", "htb", "rate", "1000mbit"}, dummy);
            return true; 
        }
        if (out.find("qdisc") != std::string::npos && 
            out.find("noqueue") == std::string::npos && 
            out.find("pfifo_fast") == std::string::npos &&
            out.find("fq_codel") == std::string::npos) {
            err = "root qdisc already exists and is not HTB handle 1: " + out;
            return false;
        }
    }
    if (!run_cmd({"tc", "qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb", "default", "1e"}, err)) {
        return false;
    }
    // Setup default class (1:30)
    std::string dummy;
    run_cmd({"tc", "class", "replace", "dev", iface, "parent", "1:", "classid", "1:1e", "htb", "rate", "1000mbit"}, dummy);
    return true;
}

bool tc_setup_parent_class(const std::string &iface, std::string &err) {
    return run_cmd({"tc", "class", "replace", "dev", iface, "parent", "1:", "classid", "1:1", "htb", "rate", "1000mbit"}, err);
}

bool tc_setup_leash_class(const std::string &iface, int leash_id, const std::string &rate, std::string &err) {
    std::string classid = "1:" + std::to_string(leash_id);
    return run_cmd({"tc", "class", "replace", "dev", iface, "parent", "1:1", "classid", classid, "htb", "rate", rate}, err);
}

bool tc_setup_filter(const std::string &iface, const std::string &cgroup_id, int leash_id, std::string &err) {
    std::string classid = "1:" + std::to_string(leash_id);

    // 1. Try the modern 'cgroup' meta-classifier first (most compatible for cgroup v2)
    // This requires the cgroup to be mapped to a classid, which nleash does via state.
    // However, the 'tc filter ... cgroup' command handles the lookup.
    if (run_cmd({"tc", "filter", "replace", "dev", iface, "parent", "1:", "protocol", "all", "prio", "1", "cgroup", "action", "skbedit", "priority", classid}, err)) {
        return true;
    }

    if (g_filter_method == TcFilterMethod::CLS_CGROUP) {
        std::string classid = "1:" + std::to_string(leash_id);
        return run_cmd({"tc", "filter", "replace", "dev", iface, "parent", "1:", "protocol", "all", "prio", "1", "handle", cgroup_id, "cgroup", "flowid", classid}, err);
    }

    if (g_filter_method == TcFilterMethod::BPF) {
        if (!g_skel) {
            err = "BPF skeleton not initialized";
            return false;
        }
        // Use only the lower 32 bits for the map key
        unsigned long long full_cgid = std::stoull(cgroup_id);
        unsigned int cgid_32 = (unsigned int)(full_cgid & 0xFFFFFFFF);
        unsigned int classid = 0x10000 | (unsigned int)leash_id;

        int map_fd = bpf_map__fd(g_skel->maps.cgroup_classid_map);
        if (bpf_map_update_elem(map_fd, &cgid_32, &classid, BPF_ANY) != 0) {
            err = "failed to update BPF map: " + std::string(strerror(errno));
            return false;
        }

        return true;
    }

    err = "TC filter method not initialized";
    return false;
}

bool tc_get_stats(const std::string &iface, int leash_id, TcStats &stats, std::string &err) {
    std::string classid = "1:" + std::to_string(leash_id);
    std::string out;
    if (!run_cmd_capture({"tc", "-s", "class", "show", "dev", iface, "classid", classid}, out, err)) {
        return false;
    }

    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("Sent") != std::string::npos) {
            std::istringstream lss(line);
            std::string token;
            while (lss >> token) {
                if (token == "Sent") {
                    lss >> stats.bytes;
                    lss >> token; 
                    lss >> stats.packets;
                } else if (token == "dropped" || token == "(dropped") {
                    lss >> stats.drops;
                } else if (token == "overlimits") {
                    lss >> stats.overlimits;
                }
            }
        } else if (line.find("rate") != std::string::npos) {
             std::istringstream lss(line);
             std::string token;
             while (lss >> token) {
                 if (token == "rate") {
                     std::string val;
                     lss >> val;
                     char *endptr = nullptr;
                     stats.bps = std::strtoull(val.c_str(), &endptr, 10);
                 } else if (token.find("pps") != std::string::npos) {
                     char *endptr = nullptr;
                     stats.pps = std::strtoul(token.c_str(), &endptr, 10);
                 }
             }
        }
    }
    return true;
}

bool tc_remove_filter(const std::string &iface, const std::string &cgroup_id, std::string &err) {
    if (g_filter_method == TcFilterMethod::CLS_CGROUP) {
        return run_cmd({"tc", "filter", "del", "dev", iface, "parent", "1:", "protocol", "all", "prio", "1", "handle", cgroup_id, "cgroup"}, err);
    }

    if (g_filter_method == TcFilterMethod::BPF) {
        if (!g_skel) return true;
        unsigned long long full_cgid = std::stoull(cgroup_id);
        unsigned int cgid_32 = (unsigned int)(full_cgid & 0xFFFFFFFF);
        int map_fd = bpf_map__fd(g_skel->maps.cgroup_classid_map);
        bpf_map_delete_elem(map_fd, &cgid_32);
        return true;
    }

    err = "TC filter method not initialized";
    return false;
}

bool tc_remove_class(const std::string &iface, int leash_id, std::string &err) {
    std::string classid = "1:" + std::to_string(leash_id);
    return run_cmd({"tc", "class", "del", "dev", iface, "classid", classid}, err);
}
