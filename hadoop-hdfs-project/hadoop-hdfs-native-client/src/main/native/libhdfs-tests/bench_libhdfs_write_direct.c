/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * A/B micro-benchmark for the libhdfs direct-write path (HDFS-15693).
 *
 * One process measures ONE mode so a JVM GC log (-Xlog:gc) attributes cleanly:
 *   BENCH_MODE=direct -> hdfsWrite dispatches to writeDirect (NewDirectByteBuffer,
 *                        no per-call heap copy)
 *   BENCH_MODE=array  -> hdfsFileDisableDirectWrite forces the legacy path
 *                        (NewByteArray + SetByteArrayRegion: one byte[] per call)
 * Both modes drive the SAME embedded mini-cluster, so NameNode/DataNode work is
 * identical and cancels in the (array - direct) delta -- including the GC churn
 * caused only by the client-side byte[] allocations.
 *
 * Knobs (env):
 *   BENCH_MODE      direct | array          (default direct)
 *   BENCH_TOTAL_MB  bytes written per file  (default 1024)
 *   BENCH_CHUNK_KB  size of each hdfsWrite   (default 8192 = 8 MiB)
 *   BENCH_ITERS     measured files           (default 5)
 *   BENCH_WARMUP    warmup files (unmeasured) (default 1)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* for RUSAGE_THREAD */
#endif

#include "hdfs/hdfs.h"
#include "hdfs_test.h"
#include "native_mini_dfs.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#define TO_STR_HELPER(X) #X
#define TO_STR(X) TO_STR_HELPER(X)

#define TLH_DEFAULT_BLOCK_SIZE 134217728

static struct NativeMiniDfsCluster *cluster;

static long env_long(const char *name, long dflt)
{
    const char *v = getenv(name);
    if (!v || !*v) return dflt;
    return strtol(v, NULL, 10);
}

static int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/*
 * CPU time (user+sys) consumed by THIS thread only. The libhdfs hdfsWrite call
 * runs the JNI copy + checksum on the calling thread; the DataStreamer drains
 * packets on a separate Java thread, and time blocked in waitAndQueuePacket is
 * not CPU. So the per-thread CPU delta isolates exactly the client-side copy/
 * checksum work, free of the pipeline-backpressure gating that confounds wall
 * clock on a fast (tmpfs) mini-cluster.
 */
static int64_t thread_cpu_ns(void)
{
    struct rusage ru;
#ifdef RUSAGE_THREAD
    const int who = RUSAGE_THREAD;
#else
    const int who = RUSAGE_SELF; /* portability fallback (process-wide CPU) */
#endif
    if (getrusage(who, &ru) != 0) return 0;
    return ((int64_t)ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000000000LL +
           ((int64_t)ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) * 1000LL;
}

static int connectToCluster(hdfsFS *fs)
{
    struct hdfsBuilder *bld;
    tPort port = (tPort)nmdGetNameNodePort(cluster);
    if (port == 0) { fprintf(stderr, "bad NN port\n"); return -1; }
    bld = hdfsNewBuilder();
    if (!bld) return -1;
    hdfsBuilderSetForceNewInstance(bld);
    hdfsBuilderSetNameNode(bld, "localhost");
    hdfsBuilderSetNameNodePort(bld, port);
    hdfsBuilderConfSetStr(bld, "dfs.block.size", TO_STR(TLH_DEFAULT_BLOCK_SIZE));
    hdfsBuilderConfSetStr(bld, "dfs.blocksize", TO_STR(TLH_DEFAULT_BLOCK_SIZE));
    *fs = hdfsBuilderConnect(bld);
    if (!*fs) { fprintf(stderr, "connect failed: %s\n", strerror(errno)); return -1; }
    return 0;
}

/*
 * Write one file of `total` bytes in `chunk`-sized hdfsWrite calls.
 * Returns 0 on success and fills *writeNs / *closeNs with the nanoseconds spent
 * in the write loop and in close respectively.
 */
static int writeOneFile(hdfsFS fs, const char *path, const uint8_t *payload,
                        long chunk, long total, int useArray,
                        int64_t *writeNs, int64_t *closeNs, int64_t *cpuNs)
{
    hdfsFile f = hdfsOpenFile(fs, path, O_WRONLY | O_CREAT, 0, 0, 0);
    int64_t t0, t1, cpu0;
    long off = 0;
    if (!f) { fprintf(stderr, "open %s failed\n", path); return -1; }

    /* A replicated DFSOutputStream always advertises WRITEBYTEBUFFER. */
    if (!hdfsFileUsesDirectWrite(f)) {
        fprintf(stderr, "expected direct-write flag set after open\n");
        return -1;
    }
    if (useArray) {
        hdfsFileDisableDirectWrite(f);
        if (hdfsFileUsesDirectWrite(f)) {
            fprintf(stderr, "failed to disable direct write\n");
            return -1;
        }
    }

    cpu0 = thread_cpu_ns();
    t0 = now_ns();
    while (off < total) {
        long want = total - off;
        if (want > chunk) want = chunk;
        tSize n = hdfsWrite(fs, f, payload, (tSize)want);
        if (n <= 0) { fprintf(stderr, "write failed at off=%ld\n", off); return -1; }
        off += n;
    }
    t1 = now_ns();
    *writeNs = t1 - t0;
    *cpuNs = thread_cpu_ns() - cpu0;

    t0 = now_ns();
    if (hdfsCloseFile(fs, f)) { fprintf(stderr, "close failed\n"); return -1; }
    t1 = now_ns();
    *closeNs = t1 - t0;
    return 0;
}

static int cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/* Print throughput plus the per-thread client CPU (the pipeline-independent
 * metric): wall median/mean, and client-CPU median/mean in seconds per GiB. */
static void summarize(const char *label, int64_t *w, int64_t *c, int64_t *p,
                      long n, double gib)
{
    int64_t wsum = 0, psum = 0, wmed, pmed;
    double wmean;
    long i;
    qsort(p, n, sizeof(int64_t), cmp_i64);
    pmed = p[n / 2];
    for (i = 0; i < n; i++) psum += p[i];
    qsort(w, n, sizeof(int64_t), cmp_i64); /* sort w last: c is unsorted, unused here */
    wmed = w[n / 2];
    for (i = 0; i < n; i++) wsum += w[i];
    wmean = wsum / (double)n;
    (void)c;
    fprintf(stderr,
        "== RESULT mode=%-6s n=%ld : wall median %.3fs (%.2f GiB/s) mean %.3fs "
        "| client-CPU median %.3fs/GiB mean %.3fs/GiB ==\n",
        label, n,
        wmed / 1e9, gib / (wmed / 1e9), wmean / 1e9,
        (pmed / 1e9) / gib, (psum / (double)n / 1e9) / gib);
}

int main(void)
{
    const char *mode = getenv("BENCH_MODE");
    int abab = (mode && strcmp(mode, "abab") == 0);
    int useArray = (mode && strcmp(mode, "array") == 0);
    long totalMb = env_long("BENCH_TOTAL_MB", 1024);
    long chunkKb = env_long("BENCH_CHUNK_KB", 8192);
    long iters = env_long("BENCH_ITERS", 5);
    long warmup = env_long("BENCH_WARMUP", 2); /* >=2 warms BOTH direct+array */
    long total = totalMb * 1024L * 1024L;
    long chunk = chunkKb * 1024L;
    double gib = total / (double)(1024 * 1024 * 1024);
    hdfsFS fs;
    uint8_t *payload;
    /* Per-mode buckets: index 0 = direct, 1 = array. */
    int64_t *wns[2], *cns[2], *pns[2];
    long cnt[2] = {0, 0};
    long i, measured;
    struct NativeMiniDfsConf conf = { 1 /* doFormat */ };

    fprintf(stderr, "== bench: mode=%s total=%ldMiB chunk=%ldKiB iters=%ld warmup=%ld ==\n",
            mode ? mode : "direct", totalMb, chunkKb, iters, warmup);

    cluster = nmdCreate(&conf);
    if (!cluster) { fprintf(stderr, "nmdCreate failed\n"); return EXIT_FAILURE; }
    if (nmdWaitClusterUp(cluster)) { fprintf(stderr, "cluster up failed\n"); return EXIT_FAILURE; }
    if (connectToCluster(&fs)) return EXIT_FAILURE;

    payload = malloc(chunk);
    if (!payload) { fprintf(stderr, "oom payload\n"); return EXIT_FAILURE; }
    for (i = 0; i < chunk; i++) payload[i] = (uint8_t)(i * 31 + 7);

    /* In abab mode each mode gets `iters` samples (2*iters measured files). */
    wns[0] = malloc(sizeof(int64_t) * iters);
    cns[0] = malloc(sizeof(int64_t) * iters);
    pns[0] = malloc(sizeof(int64_t) * iters);
    wns[1] = malloc(sizeof(int64_t) * iters);
    cns[1] = malloc(sizeof(int64_t) * iters);
    pns[1] = malloc(sizeof(int64_t) * iters);
    if (!wns[0] || !cns[0] || !pns[0] || !wns[1] || !cns[1] || !pns[1]) {
        fprintf(stderr, "oom stats\n"); return EXIT_FAILURE;
    }

    /* Warmup files (not measured): prime JIT, connections, pipeline. Warm up
     * BOTH paths so neither is cold-JIT-penalized in the measured phase. */
    for (i = 0; i < warmup; i++) {
        char path[128];
        int64_t w, c, p;
        int arr = (int)(i & 1);
        snprintf(path, sizeof(path), "/bench_warm_%ld.dat", i);
        if (writeOneFile(fs, path, payload, chunk, total, arr, &w, &c, &p))
            return EXIT_FAILURE;
        hdfsDelete(fs, path, 0);
    }

    /* Measured files. In abab mode we alternate direct/array per iteration so
     * the two paths run under identical cluster/cache conditions; otherwise the
     * single requested mode runs `iters` times. */
    measured = abab ? 2 * iters : iters;
    for (i = 0; i < measured; i++) {
        char path[128];
        /* ABBA: alternate which mode leads each pair to cancel intra-pair
         * position bias (direct,array),(array,direct),... */
        int arr = abab ? (int)(((i >> 1) ^ i) & 1) : useArray; /* 0=direct,1=array */
        long b = arr ? 1 : 0;
        int64_t w, c, p;
        snprintf(path, sizeof(path), "/bench_%s_%ld.dat", arr ? "array" : "direct", i);
        if (writeOneFile(fs, path, payload, chunk, total, arr, &w, &c, &p))
            return EXIT_FAILURE;
        if (i == 0) { /* Sanity: confirm the bytes really landed. */
            hdfsFileInfo *fi = hdfsGetPathInfo(fs, path);
            if (!fi || fi->mSize != total) {
                fprintf(stderr, "size check failed: got %ld want %ld\n",
                        fi ? (long)fi->mSize : -1L, total);
                return EXIT_FAILURE;
            }
            hdfsFreeFileInfo(fi, 1);
        }
        wns[b][cnt[b]] = w; cns[b][cnt[b]] = c; pns[b][cnt[b]] = p; cnt[b]++;
        fprintf(stderr, "  iter %ld [%s]: wall %.3fs  cpu %.3fs  close %.3fs\n",
                i, arr ? "array" : "direct", w / 1e9, p / 1e9, c / 1e9);
        hdfsDelete(fs, path, 0);
    }

    if (abab) {
        summarize("direct", wns[0], cns[0], pns[0], cnt[0], gib);
        summarize("array",  wns[1], cns[1], pns[1], cnt[1], gib);
    } else {
        long b = useArray ? 1 : 0;
        summarize(useArray ? "array" : "direct", wns[b], cns[b], pns[b], cnt[b], gib);
    }

    free(payload);
    free(wns[0]); free(cns[0]); free(pns[0]);
    free(wns[1]); free(cns[1]); free(pns[1]);
    hdfsDisconnect(fs);
    nmdShutdown(cluster);
    nmdFree(cluster);
    fprintf(stderr, "BENCH_DONE\n");
    return EXIT_SUCCESS;
}
