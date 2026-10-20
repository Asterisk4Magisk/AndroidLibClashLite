// Copyright 2026, AsteriskMETA contributors
// SPDX-License-Identifier: GPL-3.0
// AVD-only launcher for test_root_system_dns_helper.py. Never packaged in APK.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || getuid() != 0) return 64;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) return 70;
    pid_t parent = getpid(), child = fork();
    if (child < 0) return 70;
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) _exit(70);
        close(pair[0]);
        int flags = fcntl(pair[1], F_GETFD);
        if (flags < 0 || fcntl(pair[1], F_SETFD, flags & ~FD_CLOEXEC) != 0) _exit(70);
        char descriptor[32], classpath[4096];
        snprintf(descriptor, sizeof(descriptor), "%d", pair[1]);
        if (snprintf(classpath, sizeof(classpath), "-Djava.class.path=%s", argv[1]) >= (int)sizeof(classpath)) _exit(64);
        execl("/system/bin/app_process", "app_process", classpath, "/",
            "--nice-name=asterisk-dns-smoke", "libclash.systemdns.SystemDnsHelper", descriptor, (char *)NULL);
        _exit(70);
    }
    close(pair[1]);
    char buffer[8192];
    for (;;) {
        ssize_t count = read(pair[0], buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        for (ssize_t offset = 0; offset < count;) {
            ssize_t written = write(STDOUT_FILENO, buffer + offset, (size_t)(count - offset));
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) { kill(child, SIGKILL); return 70; }
            offset += written;
        }
    }
    close(pair[0]);
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 70;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 70;
}
