#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Uso: ./build/mmap_test ro|rw|upgrade archivo.txt */
int main(int argc, char **argv)
{
    const size_t size = 4096;
    int writable, upgrade, fd, prot, flags;
    char *mapped;
    if (argc != 3 || (strcmp(argv[1], "ro") != 0 &&
                      strcmp(argv[1], "rw") != 0 &&
                      strcmp(argv[1], "upgrade") != 0)) {
        fprintf(stderr, "Uso: %s ro|rw|upgrade archivo.txt\n", argv[0]);
        return 1;
    }
    writable = strcmp(argv[1], "rw") == 0;
    upgrade = strcmp(argv[1], "upgrade") == 0;
    fd = open(argv[2], writable ? O_RDWR : O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)size) {
        fprintf(stderr, "El archivo debe tener 4096 bytes como minimo.\n");
        close(fd);
        return 1;
    }
    prot = writable ? (PROT_READ | PROT_WRITE) : PROT_READ;
    flags = upgrade ? MAP_PRIVATE : MAP_SHARED;
    mapped = mmap(NULL, size, prot, flags, fd, 0);
    if (mapped == MAP_FAILED) {
        printf("mmap DENEGADO: %s\n", strerror(errno));
        close(fd);
        return 2;
    }
    if (upgrade) {
        if (mprotect(mapped, size, PROT_READ | PROT_WRITE) != 0) {
            printf("mprotect DENEGADO: %s\n", strerror(errno));
            munmap(mapped, size);
            close(fd);
            return 2;
        }
        /* La modalidad PRIVATE no escribe al archivo real. */
        printf("mprotect PERMITIDO (escritura PRIVATE, solo copia local).\n");
        mapped[0] = 'Z';
    } else if (writable) {
        mapped[0] = 'Z';
        if (msync(mapped, size, MS_SYNC) != 0) {
            perror("msync");
            munmap(mapped, size);
            close(fd);
            return 1;
        }
        puts("mmap de escritura PERMITIDO; cambio guardado.");
    } else {
        printf("mmap de lectura PERMITIDO; primer byte='%c'.\n", mapped[0]);
    }
    munmap(mapped, size);
    close(fd);
    return 0;
}
