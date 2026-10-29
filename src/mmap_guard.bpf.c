#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#define WRITE_PROTECTION_BIT 0x2UL
#define ACCESS_DENIED 13

/* Regla configurada desde el programa usuario antes de activar los hooks. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct target_policy);
} protected_target SEC(".maps");

/* Eventos de auditoria: se envian solo para el archivo protegido. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

static __always_inline int matches_file(struct file *file)
{
    __u32 key = 0;
    struct target_policy *target;
    __u64 ino;
    __u32 dev;

    if (!file)
        return 0;

    target = bpf_map_lookup_elem(&protected_target, &key);
    if (!target || !target->enabled)
        return 0;

    /* CO-RE: leer la identidad real del archivo en el kernel, no su nombre. */
    ino = BPF_CORE_READ(file, f_inode, i_ino);
    dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    return ino == target->ino && dev == target->dev;
}

static __always_inline void report_event(__u32 action, unsigned long prot, int denied)
{
    struct mmap_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;

    event->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->prot = prot;
    event->action = action;
    event->denied = denied;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
}

SEC("lsm/mmap_file")
int BPF_PROG(guard_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    int deny;
    (void)ctx;
    (void)reqprot;
    (void)flags;

    if (ret != 0)
        return ret;
    if (!matches_file(file))
        return 0;

    deny = (prot & WRITE_PROTECTION_BIT) != 0;
    report_event(EVENT_MMAP, prot, deny);
    return deny ? -ACCESS_DENIED : 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(guard_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
    struct file *file;
    int deny;
    (void)ctx;
    (void)reqprot;

    if (ret != 0 || !vma)
        return ret;
    file = BPF_CORE_READ(vma, vm_file);
    if (!matches_file(file))
        return 0;

    deny = (prot & WRITE_PROTECTION_BIT) != 0;
    report_event(EVENT_MPROTECT, prot, deny);
    return deny ? -ACCESS_DENIED : 0;
}
