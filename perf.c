#include "perf.h"

#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

enum fxp_perf_event_include {
    FUP_PERF_INCLUDE_ALL,
    FUP_PERF_INCLUDE_KERNEL,
    FUP_PERF_INCLUDE_USER
};

struct fxp_perf_counter {
    int fd;
};

struct fxp_perf_group {
    int group_fd;
    struct fxp_perf_counter *counters;
};

int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                    int group_fd, unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int fxp_allocate_perf_group(struct fxp_perf_group **out) {
    *out = malloc(sizeof(struct fxp_perf_group));
    (*out)->counters =
        malloc(sizeof(struct fxp_perf_counter) * FUP_COUNTERS_LEN);
    memset((*out)->counters, 0,
           sizeof(struct fxp_perf_counter) * FUP_COUNTERS_LEN);

    struct perf_event_attr attr = {0};
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof attr;
    attr.config = PERF_COUNT_SW_DUMMY;

    if (((*out)->group_fd = perf_event_open(&attr, 0, -1, -1, 0)) < 0) {
        perror("perf_event_open for group");
        goto error;
    }

    if (ioctl((*out)->group_fd, PERF_EVENT_IOC_RESET) < 0) {
        perror("reset perf event group");
        goto error;
    }

    return 0;

error:
    free((*out)->counters);
    free(*out);
    *out = NULL;
    return -1;
}

void fxp_free_perf_group(struct fxp_perf_group *group) {
    if (group == NULL)
        return;

    if (group->counters) {
        for (int i = 0; i < FUP_COUNTERS_LEN; ++i) {
            int counter_fd = group->counters[i].fd;
            if (counter_fd != 0) {
                close(counter_fd);
            }
        }
        free(group->counters);
    }

    close(group->group_fd);
    free(group);
}

int fxp_perf_group_create_counter(struct fxp_perf_group *group, int fxp_type,
                                  int perf_type, int config,
                                  enum fxp_perf_event_include include) {
    struct perf_event_attr attr = {0};

    attr.type = perf_type;
    attr.size = sizeof attr;
    attr.config = config;
    attr.disabled = 1;

    attr.exclude_hv = 1;

    switch (include) {
        break;
    case FUP_PERF_INCLUDE_KERNEL:
        attr.exclude_user = 1;
        break;
    case FUP_PERF_INCLUDE_USER:
        attr.exclude_kernel = 1;
        break;
    case FUP_PERF_INCLUDE_ALL:
        break;
    }

    if ((group->counters[fxp_type].fd =
             perf_event_open(&attr, 0, -1, group->group_fd, 0)) < 0) {
        perror("perf_event_open");
        return -1;
    }

    return 0;
}

int fxp_init_perf_group(struct fxp_perf_group **group) {
    if (fxp_allocate_perf_group(group) < 0) {
        goto error;
    }

    if (fxp_perf_group_create_counter(
            *group, FUP_COUNTER_CYCLES, PERF_TYPE_HARDWARE,
            PERF_COUNT_HW_CPU_CYCLES, FUP_PERF_INCLUDE_ALL) < 0)
        goto error;
    if (fxp_perf_group_create_counter(
            *group, FUP_COUNTER_INSTRUCTIONS, PERF_TYPE_HARDWARE,
            PERF_COUNT_HW_INSTRUCTIONS, FUP_PERF_INCLUDE_ALL) < 0)
        goto error;

    return 0;
error:
    fxp_free_perf_group(*group);
    *group = NULL;
    return -1;
}

int fxp_enable_perf_group(struct fxp_perf_group *group) {
    if (ioctl(group->group_fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) < 0) {
        perror("reset perf group");
        return -1;
    }
    if (ioctl(group->group_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) <
        0) {
        perror("enable perf group");
        return -1;
    }

    return 0;
}

int fxp_disable_perf_group(struct fxp_perf_group *group) {
    if (ioctl(group->group_fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) <
        0) {
        perror("enable perf group");
        return -1;
    }

    return 0;
}

int fxp_get_perf_report(struct fxp_perf_group *group, fxp_perf_report *report) {
    *report = malloc(sizeof(uint64_t) * FUP_COUNTERS_LEN);
    for (int i = 0; i < FUP_COUNTERS_LEN; ++i) {
        if (read(group->counters[i].fd, &(*report)[i], sizeof(uint64_t)) !=
            sizeof(uint64_t)) {
            perror("read perf counter");
            goto error;
        }
    }

    return 0;

error:
    free(*report);
    *report = NULL;
    return -1;
}

void fxp_free_perf_report(fxp_perf_report report) { free(report); }
