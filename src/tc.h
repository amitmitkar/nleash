#pragma once

#include <string>

bool check_tools(std::string &err);
bool ensure_cls_cgroup(std::string &err);

bool tc_setup_root(const std::string &iface, std::string &err);
bool tc_setup_parent_class(const std::string &iface, std::string &err);
bool tc_setup_leash_class(const std::string &iface, int leash_id, const std::string &rate, std::string &err);
bool tc_setup_filter(const std::string &iface, const std::string &cgroup_id, int leash_id, std::string &err);

bool tc_remove_filter(const std::string &iface, const std::string &cgroup_id, std::string &err);
bool tc_remove_class(const std::string &iface, int leash_id, std::string &err);
