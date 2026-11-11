#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TOOL_VERSION "1.4.2"
#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME  1099511628211ULL

static uint64_t fnv1a(uint64_t h, const char *s) {
    for (; *s; ++s) {
        h ^= (uint64_t)(unsigned char)*s;
        h *= FNV_PRIME;
    }
    return h;
}

static void strip_eol(char *s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: digest_tool <register-csv>\n");
        return 2;
    }
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stderr, "error: cannot open %s\n", argv[1]);
        return 3;
    }

    char line[2048];
    uint64_t reg = FNV_OFFSET;
    int count = 0;

    printf("digest_tool %s\n", TOOL_VERSION);

    if (fgets(line, sizeof line, fp) == NULL) {
        fprintf(stderr, "error: empty register\n");
        fclose(fp);
        return 4;
    }
    strip_eol(line);
    if (strncmp(line, "supplier_id,", 12) != 0) {
        fprintf(stderr, "error: missing header\n");
        fclose(fp);
        return 5;
    }

    while (fgets(line, sizeof line, fp)) {
        strip_eol(line);
        if (line[0] == '\0') continue;

        char id[64] = {0}, name[128] = {0}, region[32] = {0};
        char spend[32] = {0}, findings[16] = {0}, incidents[16] = {0};
        char audit[16] = {0}, year[16] = {0};

        int got = sscanf(line,
            "%63[^,],%127[^,],%31[^,],%31[^,],%15[^,],%15[^,],%15[^,],%15[^,]",
            id, name, region, spend, findings, incidents, audit, year);
        if (got != 8) {
            fprintf(stderr, "error: malformed row: %s\n", line);
            fclose(fp);
            return 6;
        }

        unsigned long long spend_usd = strtoull(spend, NULL, 10);
        int open_findings = atoi(findings);
        int data_incidents = atoi(incidents);
        int audit_score = atoi(audit);
        int onboarded_year = atoi(year);

        unsigned long long spend_k = spend_usd / 1000ULL;
        int score = (int)((spend_k % 500ULL)
                    + (unsigned long long)(open_findings * 17)
                    + (unsigned long long)(data_incidents * 41)
                    + (unsigned long long)((100 - audit_score) * 3)
                    + (unsigned long long)((2026 - onboarded_year) * 9));
        score = score % 1000;

        uint64_t rec_fp = fnv1a(FNV_OFFSET, line);
        reg ^= rec_fp;
        reg *= FNV_PRIME;

        printf("%s %d %016llx\n", id, score, (unsigned long long)rec_fp);
        count++;
    }

    fclose(fp);
    printf("register_fingerprint %016llx\n", (unsigned long long)reg);
    printf("count %d\n", count);
    return 0;
}
