#include "nleash.h"

#include <cstring>
#include <cerrno>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

static int exec_helper(int argc, char **argv) {
    std::string helper;
    std::string arg0 = argv[0] ? argv[0] : "nleash";
    size_t slash = arg0.find_last_of('/');
    if (slash != std::string::npos) {
        helper = arg0.substr(0, slash) + "/nleash-helper";
        std::vector<char *> new_argv;
        new_argv.reserve(static_cast<size_t>(argc) + 1);
        new_argv.push_back(const_cast<char *>(helper.c_str()));
        for (int i = 1; i < argc; ++i) new_argv.push_back(argv[i]);
        new_argv.push_back(nullptr);
        execv(helper.c_str(), new_argv.data());
        std::cerr << "nleash: failed to exec " << helper << ": " << std::strerror(errno) << "\n";
        return 1;
    }

    execvp("nleash-helper", argv);
    std::cerr << "nleash: failed to exec nleash-helper: " << std::strerror(errno) << "\n";
    return 1;
}

static void print_usage() {
    std::cerr << "Usage:\n"
              << "  nleash --pid <PID> --rate <RATE> [--iface <IFACE>]\n"
              << "  nleash --rate <RATE> [--iface <IFACE>] -- <cmd> [args...]\n"
              << "  nleash --pid <PID> --clear\n"
              << "  nleash --list [--json]\n";
}

int main(int argc, char **argv) {
    // Handle --help without requiring privileges
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            print_usage();
            return 0;
        }
    }

    if (geteuid() == 0) {
        return nleash_run(argc, argv, false);
    }
    return exec_helper(argc, argv);
}
