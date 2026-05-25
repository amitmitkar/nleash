#include "cli.h"

#include <cstring>

static bool is_flag(const char *arg, const char *flag) {
    return std::strcmp(arg, flag) == 0;
}

bool parse_cli(int argc, char **argv, CliOptions &out, std::string &err) {
    bool end_of_flags = false;
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!end_of_flags && is_flag(arg, "--")) {
            end_of_flags = true;
            continue;
        }
        if (!end_of_flags && is_flag(arg, "--pid")) {
            if (i + 1 >= argc) { err = "--pid requires a value"; return false; }
            out.has_pid = true;
            try {
                out.pid = std::stoi(argv[++i]);
            } catch (...) {
                err = "invalid --pid value";
                return false;
            }
            continue;
        }
        if (!end_of_flags && is_flag(arg, "--rate")) {
            if (i + 1 >= argc) { err = "--rate requires a value"; return false; }
            out.rate = argv[++i];
            continue;
        }
        if (!end_of_flags && is_flag(arg, "--burst")) {
            if (i + 1 >= argc) { err = "--burst requires a value"; return false; }
            out.burst = argv[++i];
            continue;
        }
        if (!end_of_flags && is_flag(arg, "--ingress-rate")) {
            if (i + 1 >= argc) { err = "--ingress-rate requires a value"; return false; }
            out.ingress_rate = argv[++i];
            continue;
        }
        if (!end_of_flags && is_flag(arg, "--ingress-burst")) {
            if (i + 1 >= argc) { err = "--ingress-burst requires a value"; return false; }
            out.ingress_burst = argv[++i];
            continue;
        }
        if (!end_of_flags && is_flag(arg, "--clear")) {
            out.clear = true;
            continue;
        }
        if (!end_of_flags && is_flag(arg, "--stats")) {
            out.stats = true;
            continue;
        }
        if (!end_of_flags && is_flag(arg, "--list")) {
            out.list = true;
            continue;
        }
        if (!end_of_flags && is_flag(arg, "--json")) {
            out.json = true;
            continue;
        }
        if (!end_of_flags) {
            err = std::string("unknown option: ") + arg;
            return false;
        }
        out.cmd.emplace_back(arg);
    }
    return true;
}
