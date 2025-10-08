#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/futex.h>
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

static struct option long_options[] = {
    {"num-waiters", 1, NULL, 'w'},
    {"shm-directory", 1, NULL, 'd'},
    {"iterations", 1, NULL, 'n'},
    {"interval", 1, NULL, 'i'},
    {0, 0, 0, 0},
};

sig_atomic_t fxp_interrupted_v = 0;
void fxp_interrupted(int _) { fxp_interrupted_v = 1; }
int fxp_was_interrupted() { return fxp_interrupted_v; }

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

void fxp_millisleep(int ms) {
    struct timespec ts;
    fxp_nanos_timespec(ms * 1000000, &ts);
    nanosleep(&ts, NULL);
}

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

    uint64_t *tarr;
    uint64_t tmin;
    uint64_t tmax;
    uint64_t tavg;

    struct fxp_shm *shm;

    struct fxp_perf_group *perf;
};

int fxp_futex_wait(uint32_t *word, int val) {
    for (;;) {
        int ret = syscall(SYS_futex, word, FUTEX_WAIT, val, NULL, NULL, 0);
        if (ret != EAGAIN) {
            return 1;
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

int fxp_report(struct fxp_context *ctx) {
    uint64_t sum = 0;
    for (int i = 0; i < ctx->num_iterations; ++i) {
        if ((UINT64_MAX - sum) < ctx->tarr[i]) {
            fprintf(stderr, "overflow while calculating avg");
            return 1;
        }

        sum += ctx->tarr[i];
    }

    ctx->tavg = sum / ctx->num_iterations;

    fprintf(stdout, "%lu,%lu,%lu\n", ctx->tmin, ctx->tmax, ctx->tavg);
    return 0;
}

int fxp_context_validate(struct fxp_context *const ctx) {
    if (ctx->num_waiters < 0) {
        return 1;
    }

    if (strlen(ctx->shm_filename) == 0) {
        return 1;
    }

    if (strlen(ctx->shm_dirname) == 0) {
        return 1;
    }

    return 0;
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

    // allocate the array for measurements
    ctx->tarr = malloc(sizeof(uint64_t) * ctx->num_iterations);

    ret = 0;
error:
    if (ret != 0) {
        if (ctx->shm_filename)
            free(ctx->shm_filename);
        if (ctx->tarr)
            free(ctx->tarr);
        ctx->shm_filename = NULL;
        ctx->tarr = NULL;
    }

    return ret;
}

void fxp_context_cleanup(struct fxp_context *ctx) {
    if (ctx->shm_filename != NULL)
        free(ctx->shm_filename);

    if (ctx->shm_dirname)
        free(ctx->shm_dirname);

    if (ctx->tarr)
        free(ctx->tarr);

    if (ctx->perf)
        fxp_free_perf_group(ctx->perf);

    ctx->shm_filename = NULL;
    ctx->shm_dirname = NULL;
    ctx->tarr = NULL;
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
        context->shm->abort = 1;
        fxp_futex_wake(&context->shm->word, INT32_MAX);

        munmap(context->shm, sizeof(struct fxp_shm));
    }

    if (context->shm_fd) {
        close(context->shm_fd);
        context->shm_fd = 0;
    }
}

void fxp_waker_wait_ready(struct fxp_context *ctx) {
    do {
        if (fxp_was_interrupted()) {
            return;
        }

        fxp_millisleep(1);
    } while (atomic_load(&ctx->shm->wait_cnt) != ctx->num_waiters);
}

void fxp_waker_wait_all_woken(struct fxp_context *ctx) {
    do {
        if (fxp_was_interrupted()) {
            return;
        }

        fxp_millisleep(1);
    } while (atomic_load(&ctx->shm->woken_cnt) != ctx->num_waiters);
}

void fxp_waker_reset(struct fxp_context *ctx) {
    atomic_exchange(&ctx->shm->woken_cnt, 0);
    atomic_fetch_sub(&ctx->shm->wait_cnt, ctx->num_waiters);
}

int fxp_run_waker(struct fxp_context *ctx) {
    int wake_index = ctx->shm->word;
    struct timespec ts_start, ts_stop, ts_res;
    for (int i = 0; i < ctx->num_iterations; ++i) {
        if (fxp_was_interrupted())
            break;

        ++wake_index;
        // wait for all waiters to have updated the wait_cnt field
        fxp_waker_wait_ready(ctx);

        if (fxp_enable_perf_group(ctx->perf) < 0)
            return -1;

        if (fxp_futex_wake(&ctx->shm->word, wake_index) != ctx->num_waiters) {
            return -1;
        }

        if (fxp_disable_perf_group(ctx->perf) < 0)
            return -1;

        fxp_perf_report report;
        if (fxp_get_perf_report(ctx->perf, &report) < 0)
            return -1;

        fprintf(stderr, "%lu,%lu\n", report[FUP_COUNTER_CYCLES],
                report[FUP_COUNTER_INSTRUCTIONS]);

        fxp_free_perf_report(report);

        // wait for all waiters to have updated the woken_cnt field
        fxp_waker_wait_all_woken(ctx);
        fxp_waker_reset(ctx);

        fxp_timespec_diff(&ts_start, &ts_stop, &ts_res);
        uint64_t tns = fxp_timespec_nanos(&ts_res);
        if (ctx->tmax < tns)
            ctx->tmax = tns;
        if (ctx->tmin > tns || ctx->tmin == 0)
            ctx->tmin = tns;

        ctx->tarr[i] = tns;

        fxp_millisleep(ctx->interval);
    }

    return 0;
}

void fxp_run_waiter(struct fxp_context *ctx) {
    int wake_index = 0;
    for (int i = 0; i < ctx->num_iterations; ++i) {
        if (fxp_was_interrupted())
            return;
        if (ctx->shm->abort)
            return;

        wake_index = ctx->shm->word;
        atomic_fetch_add(&ctx->shm->wait_cnt, 1);
        fxp_futex_wait(&ctx->shm->word, wake_index);
        atomic_fetch_add(&ctx->shm->woken_cnt, 1);
    }
}

int main(int argc, char **argv) {
    int opt, opt_index, ret;
    struct fxp_context ctx = {0};

    while ((opt = getopt_long(argc, argv, "w:d:n:i:", long_options,
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
        }
    }

    if (ctx.shm_dirname == NULL) {
        ctx.shm_dirname = strdup("/dev/shm");
    }

    signal(SIGINT, fxp_interrupted);

    if ((ret = fxp_context_init(&ctx)) != 0) {
        goto error;
    }

    if ((ret = fxp_shm_alloc(&ctx)) != 0) {
        goto error;
    }

    for (int i = 0; i < ctx.num_waiters; ++i) {
        ret = fork();
        if (ret == 0) {
            ctx.is_waiter = 1;
            break;
        }
    }

    if ((ret = fxp_shm_open(&ctx)) != 0) {
        goto error;
    }

    if (ctx.is_waiter) {
        fxp_run_waiter(&ctx);
    } else {
        if (fxp_init_perf_group(&ctx.perf) < 0)
            goto error;

        if (fxp_run_waker(&ctx) < 0)
            goto error;

        // fxp_report(&ctx);
    }
error:
    fxp_shm_close(&ctx);

    if (!ctx.is_waiter)
        fxp_shm_cleanup(&ctx);

    fxp_context_cleanup(&ctx);

    return ret;
}
