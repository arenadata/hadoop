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

#include "expect.h"
#include "hdfs/hdfs.h"
#include "hdfs_test.h"
#include "native_mini_dfs.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TO_STR_HELPER(X) #X
#define TO_STR(X) TO_STR_HELPER(X)

#define TLH_DEFAULT_BLOCK_SIZE 134217728

/* A payload spanning many checksum chunks and not aligned to a chunk/block. */
#define PAYLOAD_LEN (5 * 1024 * 1024 + 1234)

static struct NativeMiniDfsCluster *cluster;

static int connectToCluster(hdfsFS *fs)
{
    struct hdfsBuilder *bld;
    tPort port = (tPort)nmdGetNameNodePort(cluster);
    EXPECT_NONNEGATIVE(port);
    bld = hdfsNewBuilder();
    EXPECT_NONNULL(bld);
    hdfsBuilderSetForceNewInstance(bld);
    hdfsBuilderSetNameNode(bld, "localhost");
    hdfsBuilderSetNameNodePort(bld, port);
    hdfsBuilderConfSetStr(bld, "dfs.block.size", TO_STR(TLH_DEFAULT_BLOCK_SIZE));
    hdfsBuilderConfSetStr(bld, "dfs.blocksize", TO_STR(TLH_DEFAULT_BLOCK_SIZE));
    *fs = hdfsBuilderConnect(bld);
    EXPECT_NONNULL(*fs);
    return 0;
}

static int writeAll(hdfsFS fs, hdfsFile f, const uint8_t *data, int len)
{
    int off = 0;
    while (off < len) {
        tSize n = hdfsWrite(fs, f, data + off, len - off);
        EXPECT_INT_GT(n, 0);
        off += n;
    }
    return 0;
}

static int readBackAndVerify(hdfsFS fs, const char *path,
                             const uint8_t *expected, int len)
{
    hdfsFile f;
    uint8_t *buf;
    int off = 0, cmp;

    f = hdfsOpenFile(fs, path, O_RDONLY, 0, 0, 0);
    EXPECT_NONNULL(f);
    buf = malloc(len);
    EXPECT_NONNULL(buf);
    while (off < len) {
        tSize n = hdfsRead(fs, f, buf + off, len - off);
        EXPECT_INT_GT(n, 0);
        off += n;
    }
    cmp = memcmp(buf, expected, len);
    free(buf);
    EXPECT_ZERO(cmp);
    EXPECT_ZERO(hdfsCloseFile(fs, f));
    return 0;
}

/*
 * Open a file for write, optionally turn off the direct-write optimization,
 * stream the payload through hdfsWrite (which dispatches to writeDirect when
 * the stream advertises the WRITEBYTEBUFFER capability), then read it back and
 * verify the contents byte-for-byte.
 */
static int doWriteCase(hdfsFS fs, const char *path, const uint8_t *data,
                       int len, int disableDirect)
{
    hdfsFile f = hdfsOpenFile(fs, path, O_WRONLY | O_CREAT, 0, 0, 0);
    EXPECT_NONNULL(f);
    /* A replicated DFSOutputStream advertises WRITEBYTEBUFFER, so the
     * direct-write flag must be set right after open. */
    EXPECT_NONZERO(hdfsFileUsesDirectWrite(f));
    if (disableDirect) {
        hdfsFileDisableDirectWrite(f);
        EXPECT_ZERO(hdfsFileUsesDirectWrite(f));
    }
    EXPECT_ZERO(writeAll(fs, f, data, len));
    EXPECT_ZERO(hdfsCloseFile(fs, f));
    EXPECT_ZERO(readBackAndVerify(fs, path, data, len));
    return 0;
}

int main(void)
{
    hdfsFS fs;
    uint8_t *data;
    int i;
    struct NativeMiniDfsConf conf = {
        1, /* doFormat */
    };

    cluster = nmdCreate(&conf);
    EXPECT_NONNULL(cluster);
    EXPECT_ZERO(nmdWaitClusterUp(cluster));
    EXPECT_ZERO(connectToCluster(&fs));

    data = malloc(PAYLOAD_LEN);
    EXPECT_NONNULL(data);
    for (i = 0; i < PAYLOAD_LEN; i++) {
        data[i] = (uint8_t)(i * 31 + 7);
    }

    /* 1) Default open: hdfsWrite takes the writeDirect path; round-trips. */
    EXPECT_ZERO(doWriteCase(fs, "/tlhWriteDirect.dat", data, PAYLOAD_LEN, 0));

    /* 2) Direct write disabled: the legacy byte[] path produces identical data. */
    EXPECT_ZERO(doWriteCase(fs, "/tlhWriteByteArray.dat", data, PAYLOAD_LEN, 1));

    free(data);
    EXPECT_ZERO(hdfsDisconnect(fs));
    EXPECT_ZERO(nmdShutdown(cluster));
    nmdFree(cluster);

    fprintf(stderr, "TEST_SUCCESS\n");
    return EXIT_SUCCESS;
}
