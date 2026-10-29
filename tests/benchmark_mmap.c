/* MMapGuard - benchmark reproducible de mmap + primer acceso + munmap.
 * Solo utiliza un archivo de prueba normal, para evitar generar miles de
 * eventos de auditoria del archivo protegido durante las mediciones.
 * Compilar: gcc -std=c11 -O2 -Wall -Wextra -Werror tests/benchmark_mmap.c -o build/benchmark_mmap
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile unsigned long checksum;

static double seconds_now(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}

static int run_round(int fd, unsigned long iterations, double *us_per_operation,
                     long *minor_faults, long *major_faults)
{
    struct rusage before, after;
    double start, elapsed;
    if (getrusage(RUSAGE_SELF, &before) != 0) {
        perror("getrusage");
        return -1;
    }
    start = seconds_now();
    for (unsigned long i = 0; i < iterations; i++) {
        void *ptr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED) {
            perror("mmap");
            return -1;
        }
        /* Fuerza el primer acceso, que normalmente provoca un page fault menor. */
        checksum += *(volatile unsigned char *)ptr;
        if (munmap(ptr, 4096) != 0) {
            perror("munmap");
            return -1;
        }
    }
    elapsed = seconds_now() - start;
    if (getrusage(RUSAGE_SELF, &after) != 0) {
        perror("getrusage");
        return -1;
    }
    *us_per_operation = elapsed * 1000000.0 / iterations;
    *minor_faults = after.ru_minflt - before.ru_minflt;
    *major_faults = after.ru_majflt - before.ru_majflt;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Uso: %s archivo_normal.txt\n", argv[0]);
        return EXIT_FAILURE;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 4096) {
        fputs("El archivo debe tener al menos 4096 bytes.\n", stderr);
        close(fd);
        return EXIT_FAILURE;
    }

    const unsigned long warmup = 500, iterations = 10000;
    double us;
    long minor, major;
    if (run_round(fd, warmup, &us, &minor, &major) != 0) {
        close(fd);
        return EXIT_FAILURE;
    }
    puts("MMapGuard: benchmark (mmap + primer acceso + munmap)");
    printf("Archivo: %s | Iteraciones por ronda: %lu | Rondas: 5\n", argv[1], iterations);
    puts("Ronda | microsegundos/operacion | fallos menores | fallos mayores");
    for (int n = 1; n <= 5; n++) {
        if (run_round(fd, iterations, &us, &minor, &major) != 0) {
            close(fd);
            return EXIT_FAILURE;
        }
        printf("%5d | %23.3f | %14ld | %14ld\n", n, us, minor, major);
    }
    printf("Checksum de control: %lu\n", checksum);
    close(fd);
    return EXIT_SUCCESS;
}
