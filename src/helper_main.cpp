#include "nleash.h"

#include <iostream>
#include <unistd.h>

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        std::cerr << "nleash-helper: must be setuid root or run as root\n";
        return 1;
    }
    return nleash_run(argc, argv, true);
}
