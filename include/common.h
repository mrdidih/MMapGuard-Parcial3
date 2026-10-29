#ifndef MMAPGUARD_COMMON_H
#define MMAPGUARD_COMMON_H

#define EVENT_MMAP 1U
#define EVENT_MPROTECT 2U

/* Linux: dev_t interno = (major << 20) | minor (12 + 20 bits). */
struct target_policy {
    unsigned long long ino;
    unsigned int dev;
    unsigned int enabled;
};

/* Esta estructura tiene el mismo layout en el kernel y en usuario. */
struct mmap_event {
    unsigned int pid;
    unsigned int uid;
    unsigned long long prot;
    unsigned int action;
    unsigned int denied;
    char comm[16];
};

#endif
