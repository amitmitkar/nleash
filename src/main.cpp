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

int main(int argc, char **argv) {
    if (geteuid() == 0) {
        return nleash_run(argc, argv, false);
    }
    return exec_helper(argc, argv);
}
