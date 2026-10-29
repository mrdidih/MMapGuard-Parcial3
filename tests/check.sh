#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.." || exit 1

check() {
  local expected="$1"; shift
  printf '\n> %s\n' "$*"
  "$@"
  local got=$?
  if [ "$got" -eq "$expected" ]; then
    printf '[OK] codigo de salida %s (esperado: %s)\n' "$got" "$expected"
  else
    printf '[ERROR] codigo de salida %s, se esperaba %s\n' "$got" "$expected"
    return 1
  fi
}

[ -f archivo_protegido.txt ] && [ -f archivo_normal.txt ] || {
  echo "Primero ejecuta: bash tests/prepare.sh"; exit 1;
}

check 0 ./build/mmap_test ro archivo_protegido.txt || exit 1
check 2 ./build/mmap_test rw archivo_protegido.txt || exit 1
check 2 ./build/mmap_test upgrade archivo_protegido.txt || exit 1
check 0 ./build/mmap_test rw archivo_normal.txt || exit 1
printf '\nPruebas completadas. El monitor BPF debio estar activo durante ellas.\n'
