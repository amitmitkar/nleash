#include "netutil.h"

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

extern char **environ;

bool run_cmd_capture(const std::vector<std::string> &args, std::string &out, std::string &err) {
    if (args.empty()) {
        err = "internal error: empty command";
        return false;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        err = "pipe failed";
        return false;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    posix_spawn_file_actions_addclose(&actions, pipefd[1]);

    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (const auto &s : args) {
        char *dup = strdup(s.c_str());
        if (!dup) {
            close(pipefd[0]);
            close(pipefd[1]);
            err = "memory allocation failed";
            return false;
        }
        argv.push_back(dup);
    }
    argv.push_back(nullptr);

    pid_t pid = -1;
    int rc = posix_spawnp(&pid, argv[0], &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipefd[1]);
    if (rc != 0) {
        close(pipefd[0]);
        for (char *p : argv) free(p);
        err = "failed to execute " + args[0] + ": " + std::strerror(rc);
        return false;
    }

    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        out.append(buf, buf + n);
    }
    close(pipefd[0]);

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

bool detect_default_iface(std::string &iface, std::string &err) {
    std::string out;
    if (!run_cmd_capture({"ip", "route", "show", "default"}, out, err)) {
        err = "failed to detect default interface via ip route";
        return false;
    }
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        std::istringstream ls(line);
        std::string token;
        if (!(ls >> token)) continue;
        if (token != "default") continue;
        while (ls >> token) {
            if (token == "dev") {
                if (ls >> iface) return true;
            }
        }
    }
    err = "no default route found; specify --iface";
    return false;
}
