#include "tc.h"

#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

extern char **environ;

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
        err = "cls_cgroup kernel module not loaded and not available";
        return false;
    }
    return true;
}

bool tc_setup_root(const std::string &iface, std::string &err) {
    return run_cmd({"tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "30"}, err);
}

bool tc_setup_parent_class(const std::string &iface, std::string &err) {
    return run_cmd({"tc", "class", "add", "dev", iface, "parent", "1:", "classid", "1:1", "htb", "rate", "1000mbit"}, err);
}

bool tc_setup_leash_class(const std::string &iface, int leash_id, const std::string &rate, std::string &err) {
    std::string classid = "1:" + std::to_string(leash_id);
    return run_cmd({"tc", "class", "replace", "dev", iface, "parent", "1:1", "classid", classid, "htb", "rate", rate}, err);
}

bool tc_setup_filter(const std::string &iface, const std::string &cgroup_id, int leash_id, std::string &err) {
    std::string classid = "1:" + std::to_string(leash_id);
    return run_cmd({"tc", "filter", "replace", "dev", iface, "parent", "1:", "protocol", "all", "prio", "10", "handle", cgroup_id, "cgroup", "flowid", classid}, err);
}

bool tc_remove_filter(const std::string &iface, const std::string &cgroup_id, std::string &err) {
    return run_cmd({"tc", "filter", "del", "dev", iface, "parent", "1:", "protocol", "all", "prio", "10", "handle", cgroup_id, "cgroup"}, err);
}

bool tc_remove_class(const std::string &iface, int leash_id, std::string &err) {
    std::string classid = "1:" + std::to_string(leash_id);
    return run_cmd({"tc", "class", "del", "dev", iface, "classid", classid}, err);
}
