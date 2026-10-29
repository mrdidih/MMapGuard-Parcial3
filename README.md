# MMapGuard v2 — Seguridad de archivos con mmap y eBPF LSM

**Parcial 3 — Sistemas Operativos, EAFIT (2026-2)**

## Descripción

MMapGuard es un prototipo académico que controla los permisos de memoria solicitados sobre **un archivo de prueba**. Desde el kernel, utiliza los hooks BPF LSM `mmap_file` y `file_mprotect` para permitir mapeos de lectura y rechazar mapeos escribibles del archivo protegido. Las decisiones se muestran en la terminal como eventos de auditoría.

El archivo se identifica por su **inodo y dispositivo**, no solo por su nombre. La política se aplica a los mapeos evaluados por esos hooks, sin reemplazar los permisos normales de Linux.

> **Aviso:** es una demostración académica. No usar para proteger archivos confidenciales reales.

## Requisitos

- Linux con BPF LSM habilitado y BTF disponible (`/sys/kernel/btf/vmlinux`).
- `gcc`, `clang`, `make`, `bpftool`, `pkg-config`, `libbpf-dev`, `libelf-dev` y `zlib1g-dev`.
- Permisos de administrador para cargar y adjuntar el programa BPF.

Para verificar que BPF LSM esté activo:

```bash
cat /sys/kernel/security/lsm
```

La lista debe contener `bpf`. Si el archivo no existe, primero hay que comprobar que `securityfs` esté montado.

## Compilación

Desde la carpeta principal del proyecto:

```bash
make clean && make
```

Se generan en `build/` el monitor `mmap_guard`, el cliente `mmap_test` y `benchmark_mmap`. El archivo `vmlinux.h` y el objeto eBPF también se generan durante la compilación.

## Prueba de seguridad

**Terminal 1:** prepara los archivos y activa MMapGuard.

```bash
bash tests/prepare.sh
sudo ./build/mmap_guard "$PWD/archivo_protegido.txt"
```

**Terminal 2:** desde la misma carpeta del proyecto, ejecuta:

```bash
bash tests/check.sh
```

Se comprueban cuatro casos:

1. Leer `archivo_protegido.txt`: permitido.
2. Mapearlo con escritura: denegado.
3. Intentar habilitar escritura con `mprotect()`: denegado.
4. Mapear con escritura `archivo_normal.txt`: permitido.

Los resultados esperados aparecen como `[OK]` en el script. Para desactivar MMapGuard, vuelve a la terminal 1 y presiona **Ctrl+C**. Si se ejecuta la prueba de escritura sobre el archivo protegido sin el monitor, el mapeo podrá realizarse siempre que lo permitan los controles normales de Linux.

## Medición de rendimiento

El programa `benchmark_mmap` ejecuta **5 rondas de 10.000 operaciones** sobre un archivo normal. Cada operación incluye `mmap()`, primer acceso a memoria y `munmap()`; también cuenta fallos de página menores y mayores.

Ejecuta, desde la carpeta principal:

```bash
./build/benchmark_mmap archivo_normal.txt
```

Repite la misma prueba con el monitor **activo** y **desactivado**. Para guardar nuevos resultados puedes utilizar `tee`, por ejemplo:

```bash
./build/benchmark_mmap archivo_normal.txt | tee docs/evidencias/benchmark_sin_proteccion.txt
```

Los registros obtenidos durante el desarrollo se encuentran en `docs/evidencias/`. Estas mediciones son preliminares: no permiten atribuir con precisión todo el tiempo adicional al hook LSM ni sustituyen una serie más amplia y alternada de ejecuciones.

## Archivos principales

- `src/mmap_guard.bpf.c`: comprueba los permisos solicitados en los hooks LSM.
- `src/mmap_guard.c`: carga el programa, configura el archivo protegido y muestra los eventos.
- `include/common.h`: estructuras compartidas entre ambos programas.
- `tests/mmap_test.c`: realiza solicitudes de lectura, escritura y cambio de permisos.
- `tests/prepare.sh` y `tests/check.sh`: preparan los archivos y automatizan las pruebas.
- `tests/benchmark_mmap.c`: mide tiempo por operación y fallos de página.
- `Makefile`: genera los binarios necesarios.
- `docs/evidencias/`: conserva los resultados de pruebas y mediciones.

## Limitaciones

MMapGuard **no cifra archivos ni bloquea escrituras hechas mediante `write()` o `pwrite()`**. No inspecciona cada acceso a memoria, no distingue usuarios autorizados de no autorizados y no garantiza protección de mapeos preexistentes. Si el archivo se reemplaza por otro inodo, hay que reiniciar el monitor para actualizar la regla. Los procesos privilegiados también podrían desactivar la protección.

Por lo tanto, el prototipo demuestra control de ciertos mapeos y cambios de permisos a través del kernel; no constituye una solución completa de seguridad para archivos.
