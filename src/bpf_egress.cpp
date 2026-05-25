#include "bpf_egress.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <linux/bpf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "leash.skel.h"

// Forward all libbpf messages (including verifier log on load failure) to
// stderr so a load error gives the user something actionable.
static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap) {
    (void)level;
    return vfprintf(stderr, fmt, ap);
}

static struct libbpf_print_setter {
    libbpf_print_setter() { libbpf_set_print(libbpf_print); }
} _libbpf_print_setter;

// Userspace mirror of the BPF `struct bucket` in src/leash.bpf.c. Layout must
// match exactly — verified at startup with a static_assert.
struct nleash_bucket {
    uint64_t rate_bps;
    uint64_t burst;
    uint64_t tokens;
    uint64_t last_ns;
    uint64_t pass_bytes;
    uint64_t drop_bytes;
    uint32_t lock;   // bpf_spin_lock {__u32 val;}
    uint32_t _pad;
};
static_assert(sizeof(nleash_bucket) == 56,
              "nleash_bucket layout must match BPF struct bucket");

static const char *kBpfDir   = "/sys/fs/bpf/nleash";
static const char *kProgPin  = "/sys/fs/bpf/nleash/prog";
static const char *kMapPin   = "/sys/fs/bpf/nleash/buckets";
static const char *kLinksDir = "/sys/fs/bpf/nleash/links";

static int g_prog_fd = -1;
static int g_map_fd  = -1;

static std::string link_path(uint64_t cgroup_id) {
    return std::string(kLinksDir) + "/" + std::to_string(cgroup_id);
}

static bool mkdir_p_one(const char *path, std::string &err) {
    if (mkdir(path, 0700) == 0) return true;
    if (errno == EEXIST)        return true;
    err = std::string("mkdir ") + path + ": " + std::strerror(errno);
    return false;
}

bool bpf_egress_ensure_loaded(std::string &err) {
    if (g_prog_fd >= 0 && g_map_fd >= 0) return true;

    // /sys/fs/bpf is mounted by systemd on all supported distros; we don't
    // try to mount it ourselves to avoid surprising the rest of the system.
    struct stat st;
    if (stat("/sys/fs/bpf", &st) != 0) {
        err = "/sys/fs/bpf is not present; mount bpffs first";
        return false;
    }

    if (!mkdir_p_one(kBpfDir, err))   return false;
    if (!mkdir_p_one(kLinksDir, err)) return false;

    int prog_fd = bpf_obj_get(kProgPin);
    int map_fd  = bpf_obj_get(kMapPin);
    if (prog_fd >= 0 && map_fd >= 0) {
        g_prog_fd = prog_fd;
        g_map_fd  = map_fd;
        return true;
    }
    if (prog_fd >= 0) close(prog_fd);
    if (map_fd  >= 0) close(map_fd);

    // Not pinned — open + set pin path + load. We do NOT use
    // leash_bpf__open_and_load() because LIBBPF_PIN_BY_NAME would default
    // the map's pin path to /sys/fs/bpf/<name>, ignoring our subdirectory.
    struct leash_bpf *skel = leash_bpf__open();
    if (!skel) {
        err = std::string("leash_bpf__open: ") + std::strerror(errno);
        return false;
    }

    if (bpf_map__set_pin_path(skel->maps.buckets, kMapPin) != 0) {
        err = std::string("bpf_map__set_pin_path: ") + std::strerror(errno);
        leash_bpf__destroy(skel);
        return false;
    }
    // Verbose verifier log on failure (level 1 = errors, level 2 = trace).
    bpf_program__set_log_level(skel->progs.leash_egress, 1);

    if (leash_bpf__load(skel) != 0) {
        err = std::string("leash_bpf__load: ") + std::strerror(errno);
        leash_bpf__destroy(skel);
        return false;
    }

    int loaded_prog = bpf_program__fd(skel->progs.leash_egress);

    if (bpf_obj_pin(loaded_prog, kProgPin) != 0) {
        err = std::string("bpf_obj_pin prog: ") + std::strerror(errno);
        leash_bpf__destroy(skel);
        return false;
    }
    // Map was auto-pinned by libbpf during load (PIN_BY_NAME + set_pin_path).

    // Re-open via pinned paths so the fds outlive the skeleton.
    g_prog_fd = bpf_obj_get(kProgPin);
    g_map_fd  = bpf_obj_get(kMapPin);
    leash_bpf__destroy(skel);

    if (g_prog_fd < 0 || g_map_fd < 0) {
        err = "failed to re-open pinned BPF objects after load";
        return false;
    }
    return true;
}

bool bpf_egress_attach(uint64_t cgroup_id,
                       const std::string &cgroup_path,
                       uint64_t rate_bps,
                       uint64_t burst_bytes,
                       std::string &err) {
    if (!bpf_egress_ensure_loaded(err)) return false;

    nleash_bucket v = {};
    v.rate_bps  = rate_bps;
    v.burst     = burst_bytes;
    v.tokens    = burst_bytes;   // start full
    v.last_ns   = 0;             // primed on first packet

    // Maps with bpf_spin_lock require BPF_F_LOCK on update.
    if (bpf_map_update_elem(g_map_fd, &cgroup_id, &v, BPF_F_LOCK) != 0) {
        err = std::string("bpf_map_update_elem(bucket): ") + std::strerror(errno);
        return false;
    }

    // BPF link_create wants a "real" cgroup fd; some kernels reject O_PATH.
    int cgroup_fd = open(cgroup_path.c_str(), O_RDONLY | O_DIRECTORY);
    if (cgroup_fd < 0) {
        err = std::string("open ") + cgroup_path + ": " + std::strerror(errno);
        bpf_map_delete_elem(g_map_fd, &cgroup_id);
        return false;
    }

    struct bpf_link_create_opts opts = {};
    opts.sz = sizeof(opts);
    int link_fd = bpf_link_create(g_prog_fd, cgroup_fd,
                                  BPF_CGROUP_INET_EGRESS, &opts);
    close(cgroup_fd);
    if (link_fd < 0) {
        err = std::string("bpf_link_create: ") + std::strerror(errno);
        bpf_map_delete_elem(g_map_fd, &cgroup_id);
        return false;
    }

    std::string lpath = link_path(cgroup_id);
    if (bpf_obj_pin(link_fd, lpath.c_str()) != 0) {
        err = std::string("bpf_obj_pin link: ") + std::strerror(errno);
        close(link_fd);
        bpf_map_delete_elem(g_map_fd, &cgroup_id);
        return false;
    }
    close(link_fd);
    return true;
}

bool bpf_egress_detach(uint64_t cgroup_id, std::string &err) {
    if (!bpf_egress_ensure_loaded(err)) return false;

    std::string lpath = link_path(cgroup_id);
    bool ok = true;
    if (unlink(lpath.c_str()) != 0 && errno != ENOENT) {
        err = std::string("unlink ") + lpath + ": " + std::strerror(errno);
        ok = false;
    }
    if (bpf_map_delete_elem(g_map_fd, &cgroup_id) != 0 && errno != ENOENT) {
        if (ok) err = std::string("bpf_map_delete_elem: ") + std::strerror(errno);
        ok = false;
    }
    return ok;
}

bool bpf_egress_get_stats(uint64_t cgroup_id,
                          uint64_t &pass_bytes,
                          uint64_t &drop_bytes,
                          std::string &err) {
    if (!bpf_egress_ensure_loaded(err)) return false;

    nleash_bucket v = {};
    if (bpf_map_lookup_elem_flags(g_map_fd, &cgroup_id, &v, BPF_F_LOCK) != 0) {
        err = std::string("bpf_map_lookup_elem: ") + std::strerror(errno);
        return false;
    }
    pass_bytes = v.pass_bytes;
    drop_bytes = v.drop_bytes;
    return true;
}
