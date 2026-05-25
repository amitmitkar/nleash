#include "nleash.h"
#include "cli.h"
#include "leash_manager.h"
#include <iostream>
#include <unistd.h>

static bool has_any_rate(const CliOptions &opt) {
    return !opt.rate.empty() || !opt.ingress_rate.empty();
}

int nleash_run(int argc, char **argv, bool enforce_owner) {
    CliOptions opt;
    std::string err;
    if (!parse_cli(argc, argv, opt, err)) {
        if (!err.empty()) std::cerr << "nleash: " << err << "\n";
        return 1;
    }

    LeashManager manager(getuid(), getgid(), enforce_owner);

    if (opt.list) {
        return manager.list_leashes(opt.json);
    }

    if (opt.clear) {
        if (opt.pid <= 0) {
            std::cerr << "nleash: --clear requires --pid\n";
            return 1;
        }
        return manager.clear_leash(opt.pid);
    }

    if (opt.stats) {
        return manager.show_stats(opt.pid, opt.json);
    }

    if (!opt.cmd.empty()) {
        if (!has_any_rate(opt)) {
            std::cerr << "nleash: at least one of --rate / --ingress-rate is required\n";
            return 1;
        }
        return manager.run_command(opt.cmd,
                                   opt.rate, opt.burst,
                                   opt.ingress_rate, opt.ingress_burst);
    }

    if (opt.pid > 0) {
        if (!has_any_rate(opt)) {
            std::cerr << "nleash: at least one of --rate / --ingress-rate is required\n";
            return 1;
        }
        return manager.apply_leash(opt.pid,
                                   opt.rate, opt.burst,
                                   opt.ingress_rate, opt.ingress_burst);
    }

    std::cerr << "nleash: no action specified\n";
    return 1;
}
