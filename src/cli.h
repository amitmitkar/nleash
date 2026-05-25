#pragma once

#include <string>
#include <vector>

struct CliOptions {
    bool list = false;
    bool clear = false;
    bool stats = false;
    bool json = false;
    bool has_pid = false;
    int pid = -1;
    std::string rate;
    std::string burst;   // empty => use default (rate × 50ms, min 2×MTU)
    std::vector<std::string> cmd;
};

bool parse_cli(int argc, char **argv, CliOptions &out, std::string &err);
