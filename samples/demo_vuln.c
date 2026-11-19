/*
 * demo_vuln.c - tiny demo target for binary-audit-pipeline.
 *
 * Build a stripped binary:
 *   gcc -O0 -g0 -fno-stack-protector -o demo_vuln demo_vuln.c
 *   strip demo_vuln
 *   python3 audit.py ./samples ./out --all-files
 *
 * Every bug here is intentional and harmless; the program is meant to be
 * audited, not deployed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void copy_name(const char *src) {
    char buf[64];
    strcpy(buf, src);          /* CWE-120: unbounded copy */
    printf("hello, %s\n", buf);
}

static void run_cmd(const char *arg) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "echo %s", arg);
    system(cmd);               /* command injection sink */
}

static void read_blob(const unsigned char *data, unsigned int len) {
    unsigned char *dst = malloc(len);
    if (!dst) {
        return;
    }
    memcpy(dst, data, len);    /* length comes straight from the caller */
    free(dst);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <name> [payload]\n", argv[0]);
        return 1;
    }

    copy_name(argv[1]);
    run_cmd(argv[1]);

    if (argc > 2) {
        read_blob((const unsigned char *)argv[2], (unsigned int)strlen(argv[2]));
    }

    return 0;
}
