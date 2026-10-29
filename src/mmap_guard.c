#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <unistd.h>
#include "common.h"

static volatile sig_atomic_t running = 1;

static void stop_monitor(int signum)
{
    (void)signum;
    running = 0;
}

static int print_event(void *ctx, void *data, size_t len)
{
    const struct mmap_event *event = data;
    (void)ctx;
    if (len < sizeof(*event))
        return 0;

    printf("[%s] archivo protegido, proceso=%s PID=%u UID=%u permisos=%c%c%c resultado=%s\n",
           event->action == EVENT_MPROTECT ? "mprotect" : "mmap",
           event->comm, event->pid, event->uid,
           (event->prot & PROT_READ) ? 'R' : '-',
           (event->prot & PROT_WRITE) ? 'W' : '-',
           (event->prot & PROT_EXEC) ? 'X' : '-',
           event->denied ? "DENEGADO" : "PERMITIDO");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    struct stat st;
    struct bpf_object *object = NULL;
    struct bpf_program *mmap_program, *mprotect_program;
    struct bpf_link *mmap_link = NULL, *mprotect_link = NULL;
    struct ring_buffer *ring = NULL;
    struct target_policy target = {0};
    unsigned int key = 0;
    unsigned int major_dev, minor_dev;
    int map_fd, error = 1;

    if (argc != 2) {
        fprintf(stderr, "Uso: sudo ./build/mmap_guard archivo_protegido.txt\n");
        return 1;
    }
    if (stat(argv[1], &st) != 0 || !S_ISREG(st.st_mode)) {
        perror("El archivo protegido debe existir y ser regular (stat)");
        return 1;
    }

    major_dev = major(st.st_dev);
    minor_dev = minor(st.st_dev);
    if (major_dev > 0xfff || minor_dev > 0xfffff) {
        fprintf(stderr, "Dispositivo fuera del rango compatible con dev_t del kernel.\n");
        return 1;
    }
    target.ino = (unsigned long long)st.st_ino;
    target.dev = (major_dev << 20) | minor_dev;
    target.enabled = 1;

    signal(SIGINT, stop_monitor);
    signal(SIGTERM, stop_monitor);

    object = bpf_object__open_file("build/mmap_guard.bpf.o", NULL);
    if (!object) {
        fprintf(stderr, "No se pudo abrir build/mmap_guard.bpf.o\n");
        goto cleanup;
    }
    error = bpf_object__load(object);
    if (error) {
        fprintf(stderr, "Error al cargar BPF: %d\n", error);
        goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(object, "protected_target");
    if (map_fd < 0 || bpf_map_update_elem(map_fd, &key, &target, BPF_ANY) != 0) {
        perror("No se pudo configurar el archivo protegido");
        error = 1;
        goto cleanup;
    }

    mmap_program = bpf_object__find_program_by_name(object, "guard_mmap");
    mprotect_program = bpf_object__find_program_by_name(object, "guard_mprotect");
    if (!mmap_program || !mprotect_program) {
        fprintf(stderr, "No se encontraron ambos hooks LSM\n");
        error = 1;
        goto cleanup;
    }

    mmap_link = bpf_program__attach_lsm(mmap_program);
    if (libbpf_get_error(mmap_link)) {
        fprintf(stderr, "No se pudo conectar mmap_file: %ld\n", libbpf_get_error(mmap_link));
        mmap_link = NULL;
        error = 1;
        goto cleanup;
    }
    mprotect_link = bpf_program__attach_lsm(mprotect_program);
    if (libbpf_get_error(mprotect_link)) {
        fprintf(stderr, "No se pudo conectar file_mprotect: %ld\n", libbpf_get_error(mprotect_link));
        mprotect_link = NULL;
        error = 1;
        goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(object, "events");
    if (map_fd < 0 || !(ring = ring_buffer__new(map_fd, print_event, NULL, NULL))) {
        fprintf(stderr, "No se pudo abrir el canal de auditoria\n");
        error = 1;
        goto cleanup;
    }

    printf("MMapGuard v2 activo. Archivo protegido: %s\n", argv[1]);
    printf("Se permiten mapeos de lectura y se deniegan mapeos escribibles.\n");
    printf("Detener con Ctrl+C.\n\n");
    fflush(stdout);
    error = 0;
    while (running) {
        int n = ring_buffer__poll(ring, 250);
        if (n == -EINTR)
            continue;
        if (n < 0) {
            fprintf(stderr, "Error leyendo eventos: %d\n", n);
            error = 1;
            break;
        }
    }

cleanup:
    ring_buffer__free(ring);
    bpf_link__destroy(mprotect_link);
    bpf_link__destroy(mmap_link);
    bpf_object__close(object);
    return error ? 1 : 0;
}
