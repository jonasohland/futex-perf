#define _GNU_SOURCE

#include <errno.h> // IWYU pragma: keep;
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/futex.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include "perf.h"

enum fxp_metric {
    FXP_METRIC_UNSPEC = 0,
    FXP_METRIC_TIME,
    FXP_METRIC_COUNTERS,
};

// clang-format off
static struct option long_options[] = {
    {"num-waiters",   1, NULL, 'w'}, 
    {"shm-directory", 1, NULL, 'd'},
    {"iterations",    1, NULL, 'n'},
    {"interval",      1, NULL, 'i'},
    {"metric",        1, NULL, 'm'},  
    {"raw",           0, NULL, 'r'},
    {"sched",         1, NULL, 's'},
    {"prio",          1, NULL, 'p'},
    {"rtprio",        0, NULL, 'R'},
    {"cpu-affinity",  1, NULL, 'c'},
    {0,               0, 0,     0},
};
// clang-format on

sig_atomic_t fxp_interrupted_v = 0;
void fxp_interrupted(int _) { fxp_interrupted_v = 1; }
int fxp_was_interrupted() { return fxp_interrupted_v; }

enum fxp_metric fxp_metric_from_str(char const *s) {
    if (strlen(s) == 0) {
        return 0;
    }

    if (strcmp(s, "time") == 0) {
        return FXP_METRIC_TIME;
    } else if (strcmp(s, "counters") == 0) {
        return FXP_METRIC_COUNTERS;
    } else {
        return -1;
    }
}

int fxp_sched_policy_from_str(char const *s) {
    if (strlen(s) == 0) {
        return 0;
    }

    if (strcmp(s, "SCHED_FIFO") == 0) {
        return SCHED_FIFO;
    } else if (strcmp(s, "SCHED_RR") == 0) {
        return SCHED_RR;
    } else {
        return -1;
    }
}

void fxp_timespec_diff(struct timespec *const start,
                       struct timespec *const stop, struct timespec *result) {
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000ULL;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return;
}

uint64_t fxp_timespec_nanos(struct timespec *const ts) {
    return ts->tv_nsec + ts->tv_sec * 1000000000ULL;
}

void fxp_nanos_timespec(uint64_t nanos, struct timespec *ts) {
    ts->tv_sec = nanos / 1000000000ULL;
    ts->tv_nsec = nanos % 1000000000ULL;
}

void fxp_microsleep(int us) {
    struct timespec ts;
    fxp_nanos_timespec(us * 1000, &ts);
    nanosleep(&ts, NULL);
}

struct fxp_context;

typedef int (*metric_fun)(struct fxp_context *, int);

struct fxp_shm {
    uint32_t word;
    _Atomic uint64_t wait_cnt;
    _Atomic uint64_t woken_cnt;
    _Atomic int abort;
};

struct fxp_context {
    char *shm_dirname;
    char *shm_filename;
    int shm_fd;

    int num_waiters;
    int num_iterations;
    int interval;

    int is_waiter;

    uint64_t *t_arr;
    uint64_t *cyc_arr;
    uint64_t *inst_arr;
    double *ipc_arr;

    int sched_policy;
    int sched_prio;
    int sched_affinity;

    enum fxp_metric metric;
    int raw;

    metric_fun metric_before;
    metric_fun metric_after;

    struct timespec start_ts;

    struct fxp_shm *shm;
    struct fxp_perf_group *perf;
};

int fxp_futex_wait(uint32_t *word, int val, struct timespec *timeout) {
    for (;;) {
        if (syscall(SYS_futex, word, FUTEX_WAIT, val, timeout, NULL, 0) < 0) {
            if (errno != EAGAIN) {
                perror("futex_wait");
                return -1;
            }
        }

        if (*word > val) {
            return 0;
        }
    }
}

int fxp_futex_wake(uint32_t *word, int v) {
    *word = v;
    return syscall(SYS_futex, word, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}

int fxp_metric_counters_before(struct fxp_context *ctx, int i) {
    return fxp_enable_perf_group(ctx->perf);
}

int fxp_metric_counters_after(struct fxp_context *ctx, int i) {
    if (fxp_disable_perf_group(ctx->perf) < 0) {
        return -1;
    }

    fxp_perf_report report;
    if (fxp_get_perf_report(ctx->perf, &report) < 0) {
        return -1;
    }

    if (ctx->raw) {
        if (i == 0) {
            printf("cycles,instructions,ipc\n");
        }

        uint64_t inst = report[FXP_COUNTER_INSTRUCTIONS];
        uint64_t cycles = report[FXP_COUNTER_CYCLES];
        double ipc = (double)cycles / (double)inst;

        printf("%lu,%lu,%f\n", cycles, inst, ipc);
    } else {
        ctx->cyc_arr[i] = report[0];
        ctx->inst_arr[i] = report[1];
    }

    fxp_free_perf_report(report);

    return 0;
}

int fxp_metric_time_before(struct fxp_context *ctx, int i) {
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ctx->start_ts) < 0) {
        perror("clock_gettime");
        return -1;
    }

    return 0;
}

int fxp_metric_time_after(struct fxp_context *ctx, int i) {
    uint64_t nanos;
    struct timespec end_ts, dur_ts;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &end_ts) < 0) {
        perror("clock_gettime");
        return -1;
    }

    fxp_timespec_diff(&ctx->start_ts, &end_ts, &dur_ts);
    nanos = fxp_timespec_nanos(&dur_ts);

    if (ctx->raw) {
        if (i == 0) {
            printf("time(ns)\n");
        }
        printf("%lu\n", nanos);
    } else {
        ctx->t_arr[i] = nanos;
    }

    return 0;
}

int fxp_cmp_uint64(void const *lhs, void const *rhs) {
    return (*(uint64_t *)lhs - *(uint64_t *)rhs);
}

int fxp_cmp_double(void const *lhs, void const *rhs) {
    return (*(double *)lhs - *(double *)rhs);
}

double fxp_stddev(uint64_t *arr, int len) {
    double mean, sqsum, var, sum = 0;
    for (int i = 0; i < len; ++i)
        sum += arr[i];

    mean = sum / len;
    for (int i = 0; i < len; ++i)
        sqsum += pow(arr[i] - mean, 2);

    var = sqsum / len;
    return sqrt(var);
}

int fxp_report_time(struct fxp_context *ctx) {
    uint64_t min, max, med;
    double stdev, avg;
    qsort(ctx->t_arr, ctx->num_iterations, sizeof(uint64_t), fxp_cmp_uint64);

    min = 0;
    max = 0;
    avg = 0;
    for (int i = 0; i < ctx->num_iterations; ++i) {
        if (ctx->t_arr[i] < min || min == 0)
            min = ctx->t_arr[i];
        if (ctx->t_arr[i] > max)
            max = ctx->t_arr[i];
        avg += ctx->t_arr[i];
    }

    avg /= ctx->num_iterations;
    med = ctx->t_arr[ctx->num_iterations / 2];
    stdev = fxp_stddev(ctx->t_arr, ctx->num_iterations);

    printf("min,max,median,avg,stddev\n");
    printf("%lu,%lu,%lu,%f,%f\n", min, max, med, avg, stdev);

    return 0;
}

int fxp_report_counters(struct fxp_context *ctx) {
    qsort(ctx->inst_arr, ctx->num_iterations, sizeof(uint64_t), fxp_cmp_uint64);
    qsort(ctx->cyc_arr, ctx->num_iterations, sizeof(uint64_t), fxp_cmp_uint64);
    qsort(ctx->ipc_arr, ctx->num_iterations, sizeof(double), fxp_cmp_double);

    return 0;
}

int fxp_report(struct fxp_context *ctx) {
    if (ctx->raw) {
        return 0;
    }

    switch (ctx->metric) {
    case FXP_METRIC_COUNTERS:
        return fxp_report_counters(ctx);
    case FXP_METRIC_TIME:
        return fxp_report_time(ctx);
    default:
        return -1;
    }
}

int fxp_context_init(struct fxp_context *ctx) {
    int fd;
    int ret = 0;
    int pid = getpid();

    // size of the shm filename
    int sl = strlen(ctx->shm_dirname) + sizeof("/futex_perf") + 6;

    // full path for shm file
    ctx->shm_filename = malloc(sl);
    if (snprintf(ctx->shm_filename, sl, "%s/futex_perf%d", ctx->shm_dirname,
                 pid) > sl) {
        ret = -1;
        goto error;
    }

    ret = 0;
error:
    if (ret != 0) {
        if (ctx->shm_filename)
            free(ctx->shm_filename);
        if (ctx->t_arr)
            free(ctx->t_arr);
        if (ctx->cyc_arr)
            free(ctx->cyc_arr);
        if (ctx->inst_arr)
            free(ctx->inst_arr);
        ctx->shm_filename = NULL;
        ctx->t_arr = NULL;
    }

    return ret;
}

int fxp_context_metric_init(struct fxp_context *ctx) {
    switch (ctx->metric) {
    case FXP_METRIC_UNSPEC:
        fprintf(stderr, "metric unspecified\n");
        return -1;
    case FXP_METRIC_TIME:
        // allocate the array for measurements
        if (!ctx->raw) {
            ctx->t_arr = malloc(sizeof(uint64_t) * ctx->num_iterations);
        }

        ctx->metric_before = fxp_metric_time_before;
        ctx->metric_after = fxp_metric_time_after;
        break;
    case FXP_METRIC_COUNTERS:
        if (fxp_init_perf_group(&ctx->perf) < 0)
            goto error;

        if (!ctx->raw) {
            ctx->inst_arr = malloc(sizeof(uint64_t) * ctx->num_iterations);
            ctx->cyc_arr = malloc(sizeof(uint64_t) * ctx->num_iterations);
            ctx->ipc_arr = malloc(sizeof(double) * ctx->num_iterations);
        }

        ctx->metric_before = fxp_metric_counters_before;
        ctx->metric_after = fxp_metric_counters_after;
        break;
    }

    return 0;
error:
    free(ctx->t_arr);
    free(ctx->cyc_arr);
    free(ctx->cyc_arr);
    free(ctx->ipc_arr);

    return -1;
}

int fxp_context_apply_scheduling(struct fxp_context *ctx) {
    if (ctx->sched_policy == 0) {
        return 0;
    }

    struct sched_param p = {.sched_priority = ctx->sched_prio};
    if (sched_setscheduler(getpid(), ctx->sched_policy, &p) < 0) {
        perror("sched_setscheduler");
        return -1;
    }

    if (ctx->sched_affinity != -1) {
        cpu_set_t cpus;
        CPU_SET(ctx->sched_affinity, &cpus);
        if (sched_setaffinity(getpid(), sizeof(cpus), &cpus) < 0) {
            perror("sched_setaffinity");
            return -1;
        }
    }

    return 0;
}

void fxp_context_cleanup(struct fxp_context *ctx) {
    free(ctx->shm_filename);
    free(ctx->shm_dirname);
    free(ctx->t_arr);
    free(ctx->cyc_arr);
    free(ctx->inst_arr);
    free(ctx->ipc_arr);

    ctx->shm_filename = NULL;
    ctx->shm_dirname = NULL;
    ctx->t_arr = NULL;
    ctx->cyc_arr = NULL;
    ctx->inst_arr = NULL;
    ctx->ipc_arr = NULL;

    if (ctx->perf)
        fxp_free_perf_group(ctx->perf);
}

int fxp_shm_alloc(struct fxp_context *ctx) {
    int fd =
        open(ctx->shm_filename, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("open shm file");
        return 1;
    }

    if (ftruncate(fd, sizeof(struct fxp_shm)) < 0) {
        perror("truncate shm file");
        return 1;
    }

    if (close(fd) < 0) {
        perror("close shm file");
        return 1;
    }

    return 0;
}

void fxp_shm_cleanup(struct fxp_context *ctx) {
    if (ctx->shm_filename) {
        if (unlink(ctx->shm_filename) < 0) {
            perror("unlink shm file");
        }
    }
}

int fxp_shm_open(struct fxp_context *ctx) {
    int fd = open(ctx->shm_filename, O_RDWR);
    if (fd < 0) {
        perror("open shm file");
        return -1;
    }

    ctx->shm_fd = fd;
    ctx->shm = mmap(NULL, sizeof(struct fxp_shm), PROT_READ | PROT_WRITE,
                    MAP_LOCKED | MAP_SHARED, ctx->shm_fd, 0);
    if (ctx->shm == NULL) {
        perror("map shm file");
        close(ctx->shm_fd);
        ctx->shm_fd = 0;
        return -1;
    }

    return 0;
}

void fxp_shm_close(struct fxp_context *context) {
    if (context->shm) {
        atomic_store(&context->shm->abort, 1);
        fxp_futex_wake(&context->shm->word, INT32_MAX);

        munmap(context->shm, sizeof(struct fxp_shm));
    }

    if (context->shm_fd) {
        close(context->shm_fd);
        context->shm_fd = 0;
    }
}

void fxp_waker_wait_ready(struct fxp_context *ctx) {
    while (atomic_load(&ctx->shm->wait_cnt) != ctx->num_waiters) {
        if (fxp_was_interrupted()) {
            return;
        }
    }
}

void fxp_waker_wait_all_woken(struct fxp_context *ctx) {
    while (atomic_load(&ctx->shm->woken_cnt) != ctx->num_waiters) {
        if (fxp_was_interrupted()) {
            return;
        }
    }
}

void fxp_waker_reset(struct fxp_context *ctx) {
    atomic_exchange(&ctx->shm->woken_cnt, 0);
    atomic_fetch_sub(&ctx->shm->wait_cnt, ctx->num_waiters);
}

int fxp_run_waker(struct fxp_context *ctx) {
    int wake_index = ctx->shm->word;
    struct timespec ts_start, ts_stop, ts_res;
    for (int i = -50; i < ctx->num_iterations; ++i) {
        if (fxp_was_interrupted())
            break;

        ++wake_index;
        // wait for all waiters to have updated the wait_cnt field
        fxp_waker_wait_ready(ctx);

        fxp_microsleep(10);

        if (i >= 0) {
            // gather our metric before doing the futex_wake / enable counters
            if (ctx->metric_before(ctx, i) < 0)
                return -1;
        }

        if (fxp_futex_wake(&ctx->shm->word, wake_index) != ctx->num_waiters) {
            fprintf(stderr,
                    "not all waiters were ready when futex_wake was called\n");
            return -1;
        }

        // gather our metric after doing the futex_wake / disable the
        // counters
        if (i >= 0) {
            if (ctx->metric_after(ctx, i) < 0)
                return -1;
        }

        // wait for all waiters to have updated the woken_cnt field
        fxp_waker_wait_all_woken(ctx);
        fxp_waker_reset(ctx);

        if (ctx->interval)
            fxp_microsleep(ctx->interval * 1000 - 10);
    }

    return 0;
}

int fxp_run_waiter(struct fxp_context *ctx) {
    struct timespec timeout;
    int wake_index = 0;

    if (ctx->interval == 0)
        fxp_nanos_timespec(1000000000000, &timeout);
    else
        fxp_nanos_timespec((1000000000 * ctx->interval) * 2, &timeout);

    for (int i = -50; i < ctx->num_iterations; ++i) {
        if (fxp_was_interrupted())
            return 0;
        if (ctx->shm->abort)
            return -1;

        wake_index = ctx->shm->word;
        atomic_fetch_add(&ctx->shm->wait_cnt, 1);
        if (fxp_futex_wait(&ctx->shm->word, wake_index, &timeout) < 0)
            return -1;
        atomic_fetch_add(&ctx->shm->woken_cnt, 1);
    }

    return 0;
}

int main(int argc, char **argv) {
    int opt, opt_index, ret;
    struct fxp_context ctx = {0};
    ctx.sched_affinity = -1;

    while ((opt = getopt_long(argc, argv, "w:d:n:i:m:rs:p:Rc:", long_options,
                              &opt_index)) != -1) {
        switch (opt) {
        case 'w':
            ctx.num_waiters = atoi(optarg);
            break;
        case 'd':
            ctx.shm_dirname = strdup(optarg);
            break;
        case 'n':
            ctx.num_iterations = atoi(optarg);
            break;
        case 'i':
            ctx.interval = atoi(optarg);
            break;
        case 'm':
            ret = fxp_metric_from_str(optarg);
            if (ret < 0) {
                fprintf(stderr, "invalid metric option\n");
                return 1;
            }
            ctx.metric = ret;
            break;
        case 'r':
            ctx.raw = 1;
            break;
        case 's':
            ret = fxp_sched_policy_from_str(optarg);
            if (ret < 0) {
                fprintf(stderr, "invalid scheduler option\n");
                return 1;
            }
            ctx.sched_policy = ret;
            break;
        case 'p':
            ctx.sched_prio = atoi(optarg);
            break;
        case 'R':
            ctx.sched_prio = 99;
            break;
        case 'c':
            ctx.sched_affinity = atoi(optarg);
            break;
        }
    }

    if (ctx.shm_dirname == NULL)
        ctx.shm_dirname = strdup("/dev/shm");

    if (ctx.metric == 0)
        ctx.metric = FXP_METRIC_TIME;

    if (signal(SIGINT, fxp_interrupted) < 0) {
        perror("signal");
        goto error;
    }

    if ((ret = fxp_context_init(&ctx)) != 0)
        goto error;

    if ((ret = fxp_shm_alloc(&ctx)) != 0)
        goto error;

    for (int i = 0; i < ctx.num_waiters; ++i) {
        ret = fork();
        if (ret == 0) {
            ctx.is_waiter = 1;
            break;
        }
    }

    if ((ret = fxp_shm_open(&ctx)) != 0)
        goto error;

    if (!ctx.is_waiter) {
        if (fxp_context_apply_scheduling(&ctx) < 0) {
            goto error;
        }
    }

    if (ctx.is_waiter) {
        fxp_run_waiter(&ctx);
    } else {
        if ((ret = fxp_context_metric_init(&ctx)) < 0)
            goto error;
        if ((ret = fxp_run_waker(&ctx)) < 0)
            goto error;
        if ((ret = fxp_report(&ctx)) < 0)
            goto error;
    }
error:
    fxp_shm_close(&ctx);

    if (!ctx.is_waiter)
        fxp_shm_cleanup(&ctx);

    fxp_context_cleanup(&ctx);

    return ret;
}
