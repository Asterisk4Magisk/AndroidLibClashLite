// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef int (*cli_entry)(int, char **);

int main(int argc, char **argv) {
    char path[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length < 0 || length >= (ssize_t)sizeof(path) - 1) {
        fprintf(stderr, "Cannot resolve meow launcher path\n");
        return 70;
    }
    path[length] = '\0';
    char *name = strrchr(path, '/');
    if (!name || (size_t)(name - path + 1) + sizeof("librsjni.so") > sizeof(path)) return 70;
    strcpy(name + 1, "librsjni.so");
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fprintf(stderr, "Cannot load meow library: %s\n", dlerror());
        return 70;
    }
    cli_entry entry = (cli_entry)dlsym(library, "AndroidMeowCLI_v1");
    if (!entry) {
        fprintf(stderr, "Incompatible meow library (missing CLI ABI v1)\n");
        return 71;
    }
    return entry(argc, argv);
}

