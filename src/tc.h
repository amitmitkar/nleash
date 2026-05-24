#pragma once

#include <string>
#include <vector>

// Traffic control filter method
enum class TcFilterMethod {
    UNKNOWN,
    CLS_CGROUP,  // Traditional cls_cgroup (kernel < 6.0)
    BPF          // eBPF-based classifier (kernel >= 4.1)
};

bool check_tools(std::string &err);
bool ensure_cls_cgroup(std::string &err);

bool run_cmd_capture(const std::vector<std::string> &args, std::string &out, std::string &err);

// Detect and select the best available TC filter method
TcFilterMethod detect_tc_filter_method(std::string &err);

// Initialize the selected TC filter method (load eBPF if needed)
bool tc_init_filter_method(TcFilterMethod method, const std::string &iface, std::string &err);

// Cleanup the TC filter method (unload eBPF if needed)
void tc_cleanup_filter_method(TcFilterMethod method, const std::string &iface);

bool tc_setup_root(const std::string &iface, std::string &err);
bool tc_setup_parent_class(const std::string &iface, std::string &err);
bool tc_setup_leash_class(const std::string &iface, int leash_id, const std::string &rate, std::string &err);
bool tc_setup_filter(const std::string &iface, const std::string &cgroup_id, int leash_id, std::string &err);

struct TcStats {
    unsigned long long bytes = 0;
    unsigned int packets = 0;
    unsigned int drops = 0;
    unsigned int overlimits = 0;
    unsigned int bps = 0;
    unsigned int pps = 0;
};
bool tc_get_stats(const std::string &iface, int leash_id, TcStats &stats, std::string &err);

bool tc_remove_filter(const std::string &iface, const std::string &cgroup_id, std::string &err);
bool tc_remove_class(const std::string &iface, int leash_id, std::string &err);
