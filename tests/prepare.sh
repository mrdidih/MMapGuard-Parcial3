#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")/.."
for f in archivo_protegido.txt archivo_normal.txt; do
  if [ ! -e "$f" ]; then
    printf 'Archivo academico de prueba.\n' > "$f"
    truncate -s 4096 "$f"
    chmod 600 "$f"
    printf 'Creado: %s\n' "$f"
  else
    printf 'Ya existe y no se modifica: %s\n' "$f"
  fi
done
