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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "expect.h"
#include "hdfs/hdfs.h"
#include "native_mini_dfs.h"

#include <errno.h>
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Exercises the optional isolated runtime classloader (LIBHDFS_RUNTIME_CLASSLOADER_PATH).
 *
 * The scenario it reproduces: libhdfs is loaded into a JVM that some other component already
 * created, whose system classpath has no Hadoop. We create exactly such a JVM here (its own
 * -Djava.class.path is Hadoop-free) and hand the Hadoop classpath to the loader via
 * LIBHDFS_RUNTIME_CLASSLOADER_PATH. libhdfs then attaches to that JVM and must resolve every
 * Hadoop class -- to spin a MiniDFSCluster and do real file I/O -- through the isolated
 * loader. Without the feature, the first Hadoop FindClass on the attached thread returns NULL.
 *
 * The test harness provides the Hadoop classpath in the CLASSPATH environment variable.
 */

/* Internal libhdfs symbol (not part of the public hdfs.h API). */
extern jobject hdfsGetRuntimeClassLoader(void);

#define TLH_BUF_LEN 128

/* Create a JVM whose own classpath is Hadoop-free, so the isolated loader is the only path
 * to the Hadoop classes. Returns 0 on success. */
static int createHadoopFreeJvm(void)
{
    JavaVM *vm;
    JNIEnv *env;
    JavaVMInitArgs vmArgs;
    jint ret;
    size_t i;
    /* "." keeps the system classpath Hadoop-free; the JPMS opens let Hadoop's reflection run
     * on JDK 17+ and are ignored elsewhere (-XX:+IgnoreUnrecognizedVMOptions). */
    static const char *optStrings[] = {
        "-Djava.class.path=.",
        "-XX:+IgnoreUnrecognizedVMOptions",
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "--add-opens=java.base/java.io=ALL-UNNAMED",
        "--add-opens=java.base/java.net=ALL-UNNAMED",
        "--add-opens=java.base/java.nio=ALL-UNNAMED",
        "--add-opens=java.base/java.util=ALL-UNNAMED",
        "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
        "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
    };
    const size_t nOpts = sizeof(optStrings) / sizeof(optStrings[0]);
    JavaVMOption *options = calloc(nOpts, sizeof(JavaVMOption));
    if (!options) {
        return ENOMEM;
    }
    for (i = 0; i < nOpts; i++) {
        options[i].optionString = (char *) optStrings[i];
    }
    vmArgs.version = JNI_VERSION_1_8;
    vmArgs.nOptions = (jint) nOpts;
    vmArgs.options = options;
    vmArgs.ignoreUnrecognized = JNI_TRUE;
    ret = JNI_CreateJavaVM(&vm, (void **) &env, &vmArgs);
    free(options);
    if (ret != JNI_OK) {
        fprintf(stderr, "JNI_CreateJavaVM failed with error %d\n", (int) ret);
        return EIO;
    }
    return 0;
}

int main(void)
{
    const char *classpath;
    char *savedClasspath;
    struct NativeMiniDfsCluster *cl;
    struct NativeMiniDfsConf conf;
    hdfsFS fs;
    struct hdfsBuilder *bld;
    tPort port;
    hdfsFile file;
    char buf[TLH_BUF_LEN];
    static const char *PATH = "/tlh_runtime_classloader.txt";
    static const char *MSG = "isolated runtime classloader works\n";
    const int msgLen = (int) strlen(MSG);

    /* Hand the Hadoop classpath to the isolated loader BEFORE creating the JVM. */
    classpath = getenv("CLASSPATH");
    if (!classpath || !classpath[0]) {
        fprintf(stderr, "CLASSPATH is not set; cannot run this test\n");
        return EXIT_FAILURE;
    }
    savedClasspath = strdup(classpath);
    EXPECT_NONNULL(savedClasspath);
    EXPECT_ZERO(setenv("LIBHDFS_RUNTIME_CLASSLOADER_PATH", savedClasspath, 1));

    /* Create the (Hadoop-free) JVM ourselves so libhdfs attaches instead of creating it. */
    EXPECT_ZERO(createHadoopFreeJvm());

    /* From here, every Hadoop class native_mini_dfs / libhdfs touch resolves through the
     * isolated loader; the system classloader cannot see them. */
    memset(&conf, 0, sizeof(conf));
    conf.doFormat = 1;
    cl = nmdCreate(&conf);
    EXPECT_NONNULL(cl);
    EXPECT_ZERO(nmdWaitClusterUp(cl));
    port = (tPort) nmdGetNameNodePort(cl);
    EXPECT_INT_GT(port, 0);

    /* The loader must actually have been built -- proves we exercised the new path and did
     * not silently fall back to plain FindClass. */
    EXPECT_NONNULL(hdfsGetRuntimeClassLoader());

    bld = hdfsNewBuilder();
    EXPECT_NONNULL(bld);
    hdfsBuilderSetNameNode(bld, "localhost");
    hdfsBuilderSetNameNodePort(bld, port);
    fs = hdfsBuilderConnect(bld);
    EXPECT_NONNULL(fs);

    /* Write, read back, and delete a file -- a full round trip through the loaded
     * DistributedFileSystem. */
    file = hdfsOpenFile(fs, PATH, O_WRONLY | O_CREAT, 0, 0, 0);
    EXPECT_NONNULL(file);
    EXPECT_INT_EQ(msgLen, hdfsWrite(fs, file, MSG, msgLen));
    EXPECT_ZERO(hdfsCloseFile(fs, file));
    EXPECT_ZERO(hdfsExists(fs, PATH));

    file = hdfsOpenFile(fs, PATH, O_RDONLY, 0, 0, 0);
    EXPECT_NONNULL(file);
    memset(buf, 0, sizeof(buf));
    EXPECT_INT_EQ(msgLen, hdfsRead(fs, file, buf, sizeof(buf)));
    EXPECT_ZERO(memcmp(MSG, buf, msgLen));
    EXPECT_ZERO(hdfsCloseFile(fs, file));

    EXPECT_ZERO(hdfsDelete(fs, PATH, 0));
    EXPECT_ZERO(hdfsDisconnect(fs));
    EXPECT_ZERO(nmdShutdown(cl));
    nmdFree(cl);
    free(savedClasspath);

    fprintf(stderr, "TEST_SUCCESS: test_libhdfs_runtime_classloader\n");
    return EXIT_SUCCESS;
}
