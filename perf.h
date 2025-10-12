#pragma once

#include <stdint.h>

struct fxp_perf_group;

typedef uint64_t *fxp_perf_report;

enum fxp_perf_counter_names {
    FXP_COUNTER_CYCLES = 0,
    FXP_COUNTER_INSTRUCTIONS,
    FXP_COUNTERS_LEN
};

int fxp_init_perf_group(struct fxp_perf_group **);
void fxp_free_perf_group(struct fxp_perf_group *);
int fxp_enable_perf_group(struct fxp_perf_group *);
int fxp_disable_perf_group(struct fxp_perf_group *);

int fxp_get_perf_report(struct fxp_perf_group *, fxp_perf_report *report);
void fxp_free_perf_report(fxp_perf_report report);
