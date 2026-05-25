#include "bpf_filter.h"

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

// Userspace mirror of struct nleash_bucket in src/leash.bpf.c. Layout MUST
// match exactly; verified by a static_assert below.
struct nleash_bucket {
    uint32_t lock;     // bpf_spin_lock { __u32 val; }
    uint32_t _pad;

    uint64_t egress_rate_bps;
    uint64_t egress_burst;
    uint64_t egress_tokens;
    uint64_t egress_last_ns;
    uint64_t egress_pass_bytes;
    uint64_t egress_drop_bytes;

    uint64_t ingress_rate_bps;
    uint64_t ingress_burst;
    uint64_t ingress_tokens;
    uint64_t ingress_last_ns;
    uint64_t ingress_pass_bytes;
    uint64_t ingress_drop_bytes;
};
static_assert(sizeof(nleash_bucket) == 8 + 12 * 8,
              "nleash_bucket layout must match BPF struct nleash_bucket");

static const char *kBpfDir         = "/sys/fs/bpf/nleash";
static const char *kProgEgressPin  = "/sys/fs/bpf/nleash/prog_egress";
static const char *kProgIngressPin = "/sys/fs/bpf/nleash/prog_ingress";
static const char *kMapPin         = "/sys/fs/bpf/nleash/buckets";

static int g_prog_egress_fd  = -1;
static int g_prog_ingress_fd = -1;
static int g_map_fd          = -1;

static bool mkdir_p_one(const char *path, std::string &err) {
    if (mkdir(path, 0700) == 0) return true;
    if (errno == EEXIST)        return true;
    err = std::string("mkdir ") + path + ": " + std::strerror(errno);
    return false;
}

// Wipe a stale pin so we can re-create with the current map/prog layout.
// Quietly best-effort: ENOENT means we have nothing to do.
static void unlink_quiet(const char *path) {
    if (unlink(path) != 0 && errno != ENOENT) {
        // Non-fatal: caller will surface a real error if subsequent pinning fails.
    }
}

bool bpf_filter_ensure_loaded(std::string &err) {
    if (g_prog_egress_fd >= 0 && g_prog_ingress_fd >= 0 && g_map_fd >= 0) return true;

    struct stat st;
    if (stat("/sys/fs/bpf", &st) != 0) {
        err = "/sys/fs/bpf is not present; mount bpffs first";
        return false;
    }

    if (!mkdir_p_one(kBpfDir, err))   return false;

    int pe = bpf_obj_get(kProgEgressPin);
    int pi = bpf_obj_get(kProgIngressPin);
    int mf = bpf_obj_get(kMapPin);
    if (pe >= 0 && pi >= 0 && mf >= 0) {
        g_prog_egress_fd  = pe;
        g_prog_ingress_fd = pi;
        g_map_fd          = mf;
        return true;
    }
    // Partial / stale pins from an older build: wipe them and reload fresh.
    if (pe >= 0) close(pe);
    if (pi >= 0) close(pi);
    if (mf >= 0) close(mf);
    unlink_quiet(kProgEgressPin);
    unlink_quiet(kProgIngressPin);
    unlink_quiet(kMapPin);

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
    if (leash_bpf__load(skel) != 0) {
        err = std::string("leash_bpf__load: ") + std::strerror(errno);
        leash_bpf__destroy(skel);
        return false;
    }

    int loaded_eg = bpf_program__fd(skel->progs.leash_egress);
    int loaded_in = bpf_program__fd(skel->progs.leash_ingress);

    if (bpf_obj_pin(loaded_eg, kProgEgressPin) != 0) {
        err = std::string("bpf_obj_pin prog_egress: ") + std::strerror(errno);
        leash_bpf__destroy(skel);
        return false;
    }
    if (bpf_obj_pin(loaded_in, kProgIngressPin) != 0) {
        err = std::string("bpf_obj_pin prog_ingress: ") + std::strerror(errno);
        unlink_quiet(kProgEgressPin);
        leash_bpf__destroy(skel);
        return false;
    }

    g_prog_egress_fd  = bpf_obj_get(kProgEgressPin);
    g_prog_ingress_fd = bpf_obj_get(kProgIngressPin);
    g_map_fd          = bpf_obj_get(kMapPin);
    leash_bpf__destroy(skel);

    if (g_prog_egress_fd < 0 || g_prog_ingress_fd < 0 || g_map_fd < 0) {
        err = "failed to re-open pinned BPF objects after load";
        return false;
    }
    return true;
}

static int open_cgroup(const std::string &path, std::string &err) {
    int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0) err = std::string("open ") + path + ": " + std::strerror(errno);
    return fd;
}

// We use the legacy BPF_PROG_ATTACH path rather than BPF_LINK_CREATE + pin
// because pinning a cgroup bpf_link returns EPERM on kernel 6.17. Attachments
// made via bpf_prog_attach persist on the cgroup independently of any fd —
// they're undone with bpf_prog_detach2 (or when the cgroup is destroyed).
static bool attach_one(int prog_fd, int cgroup_fd, enum bpf_attach_type at,
                       const char *direction, std::string &err) {
    if (bpf_prog_attach(prog_fd, cgroup_fd, at, BPF_F_ALLOW_MULTI) != 0) {
        err = std::string("bpf_prog_attach(") + direction + "): " + std::strerror(errno);
        return false;
    }
    return true;
}

bool bpf_filter_attach(uint64_t cgroup_id,
                       const std::string &cgroup_path,
                       uint64_t egress_rate_bps,
                       uint64_t egress_burst_bytes,
                       uint64_t ingress_rate_bps,
                       uint64_t ingress_burst_bytes,
                       std::string &err) {
    if (!bpf_filter_ensure_loaded(err)) return false;

    nleash_bucket v = {};
    v.egress_rate_bps   = egress_rate_bps;
    v.egress_burst      = egress_burst_bytes;
    v.egress_tokens     = egress_burst_bytes;
    v.ingress_rate_bps  = ingress_rate_bps;
    v.ingress_burst     = ingress_burst_bytes;
    v.ingress_tokens    = ingress_burst_bytes;

    if (bpf_map_update_elem(g_map_fd, &cgroup_id, &v, BPF_F_LOCK) != 0) {
        err = std::string("bpf_map_update_elem(bucket): ") + std::strerror(errno);
        return false;
    }

    int cgroup_fd = open_cgroup(cgroup_path, err);
    if (cgroup_fd < 0) {
        bpf_map_delete_elem(g_map_fd, &cgroup_id);
        return false;
    }

    if (!attach_one(g_prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS,
                    "egress", err)) {
        close(cgroup_fd);
        bpf_map_delete_elem(g_map_fd, &cgroup_id);
        return false;
    }
    if (!attach_one(g_prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS,
                    "ingress", err)) {
        bpf_prog_detach2(g_prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        close(cgroup_fd);
        bpf_map_delete_elem(g_map_fd, &cgroup_id);
        return false;
    }
    close(cgroup_fd);
    return true;
}

// To detach, we need a fd to the cgroup. We reconstruct the path from state
// via the caller. If the cgroup directory is already gone (e.g. someone
// rmdir'd it first), there's nothing to detach from — the cgroup destruction
// took the BPF attachments with it.
bool bpf_filter_detach(uint64_t cgroup_id, std::string &err) {
    if (!bpf_filter_ensure_loaded(err)) return false;

    bool ok = true;
    if (bpf_map_delete_elem(g_map_fd, &cgroup_id) != 0 && errno != ENOENT) {
        err = std::string("bpf_map_delete_elem: ") + std::strerror(errno);
        ok = false;
    }
    // The actual BPF detach from the cgroup is done by the caller via
    // bpf_filter_detach_cgroup() since we need the cgroup path.
    return ok;
}

bool bpf_filter_detach_cgroup(const std::string &cgroup_path, std::string &err) {
    if (!bpf_filter_ensure_loaded(err)) return false;

    int cgroup_fd = open_cgroup(cgroup_path, err);
    if (cgroup_fd < 0) {
        // Cgroup gone already; nothing to detach.
        if (errno == ENOENT) { err.clear(); return true; }
        return false;
    }
    bool ok = true;
    if (bpf_prog_detach2(g_prog_egress_fd,  cgroup_fd, BPF_CGROUP_INET_EGRESS) != 0
        && errno != ENOENT) {
        err = std::string("bpf_prog_detach2(egress): ") + std::strerror(errno);
        ok = false;
    }
    if (bpf_prog_detach2(g_prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS) != 0
        && errno != ENOENT) {
        if (ok) err = std::string("bpf_prog_detach2(ingress): ") + std::strerror(errno);
        ok = false;
    }
    close(cgroup_fd);
    return ok;
}

bool bpf_filter_get_stats(uint64_t cgroup_id, nleash_stats &out, std::string &err) {
    if (!bpf_filter_ensure_loaded(err)) return false;

    nleash_bucket v = {};
    if (bpf_map_lookup_elem_flags(g_map_fd, &cgroup_id, &v, BPF_F_LOCK) != 0) {
        err = std::string("bpf_map_lookup_elem: ") + std::strerror(errno);
        return false;
    }
    out.egress_pass_bytes  = v.egress_pass_bytes;
    out.egress_drop_bytes  = v.egress_drop_bytes;
    out.ingress_pass_bytes = v.ingress_pass_bytes;
    out.ingress_drop_bytes = v.ingress_drop_bytes;
    return true;
}
