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

#include "config.h"
#include "exception.h"
#include "jclasses.h"
#include "jni_helper.h"
#include "platform.h"
#include "os/mutexes.h"
#include "os/thread_local_storage.h"
#include "x-platform/c-api/dirent.h"
#include "x-platform/types.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Export a libhdfs-internal symbol from the shared library so other in-process components can
 * resolve it (hdfs.h's LIBHDFS_EXTERNAL is #undef'd at the end of that header, so it can't be
 * reused here). Harmless for the static library. */
#ifdef WIN32
    #define LIBHDFS_RUNTIME_EXPORT __declspec(dllexport)
#elif defined(__GNUC__)
    #define LIBHDFS_RUNTIME_EXPORT __attribute__((visibility("default")))
#else
    #define LIBHDFS_RUNTIME_EXPORT
#endif

/** The Native return types that methods could return */
#define JVOID         'V'
#define JOBJECT       'L'
#define JARRAYOBJECT  '['
#define JBOOLEAN      'Z'
#define JBYTE         'B'
#define JCHAR         'C'
#define JSHORT        'S'
#define JINT          'I'
#define JLONG         'J'
#define JFLOAT        'F'
#define JDOUBLE       'D'

/**
 * Length of buffer for retrieving created JVMs.  (We only ever create one.)
 */
#define VM_BUF_LENGTH 1

void destroyLocalReference(JNIEnv *env, jobject jObject)
{
  if (jObject)
    (*env)->DeleteLocalRef(env, jObject);
}

static jthrowable validateMethodType(JNIEnv *env, MethType methType)
{
    if (methType != STATIC && methType != INSTANCE) {
        return newRuntimeError(env, "validateMethodType(methType=%d): "
            "illegal method type.\n", methType);
    }
    return NULL;
}

jthrowable newJavaStr(JNIEnv *env, const char *str, jstring *out)
{
    jstring jstr;

    if (!str) {
        /* Can't pass NULL to NewStringUTF: the result would be
         * implementation-defined. */
        *out = NULL;
        return NULL;
    }
    jstr = (*env)->NewStringUTF(env, str);
    if (!jstr) {
        /* If NewStringUTF returns NULL, an exception has been thrown,
         * which we need to handle.  Probaly an OOM. */
        return getPendingExceptionAndClear(env);
    }
    *out = jstr;
    return NULL;
}

jthrowable newCStr(JNIEnv *env, jstring jstr, char **out)
{
    const char *tmp;

    if (!jstr) {
        *out = NULL;
        return NULL;
    }
    tmp = (*env)->GetStringUTFChars(env, jstr, NULL);
    if (!tmp) {
        return getPendingExceptionAndClear(env);
    }
    *out = strdup(tmp);
    (*env)->ReleaseStringUTFChars(env, jstr, tmp);
    return NULL;
}

/**
 * Does the work to actually execute a Java method. Takes in an existing jclass
 * object and a va_list of arguments for the Java method to be invoked.
 */
static jthrowable invokeMethodOnJclass(JNIEnv *env, jvalue *retval,
        MethType methType, jobject instObj, jclass cls, const char *className,
        const char *methName, const char *methSignature, va_list args)
{
    jmethodID mid;
    jthrowable jthr;
    const char *str;
    char returnType;

    jthr = methodIdFromClass(cls, className, methName, methSignature, methType,
                             env, &mid);
    if (jthr)
        return jthr;
    str = methSignature;
    while (*str != ')') str++;
    str++;
    returnType = *str;
    if (returnType == JOBJECT || returnType == JARRAYOBJECT) {
        jobject jobj = NULL;
        if (methType == STATIC) {
            jobj = (*env)->CallStaticObjectMethodV(env, cls, mid, args);
        }
        else if (methType == INSTANCE) {
            jobj = (*env)->CallObjectMethodV(env, instObj, mid, args);
        }
        retval->l = jobj;
    }
    else if (returnType == JVOID) {
        if (methType == STATIC) {
            (*env)->CallStaticVoidMethodV(env, cls, mid, args);
        }
        else if (methType == INSTANCE) {
            (*env)->CallVoidMethodV(env, instObj, mid, args);
        }
    }
    else if (returnType == JBOOLEAN) {
        jboolean jbool = 0;
        if (methType == STATIC) {
            jbool = (*env)->CallStaticBooleanMethodV(env, cls, mid, args);
        }
        else if (methType == INSTANCE) {
            jbool = (*env)->CallBooleanMethodV(env, instObj, mid, args);
        }
        retval->z = jbool;
    }
    else if (returnType == JSHORT) {
        jshort js = 0;
        if (methType == STATIC) {
            js = (*env)->CallStaticShortMethodV(env, cls, mid, args);
        }
        else if (methType == INSTANCE) {
            js = (*env)->CallShortMethodV(env, instObj, mid, args);
        }
        retval->s = js;
    }
    else if (returnType == JLONG) {
        jlong jl = -1;
        if (methType == STATIC) {
            jl = (*env)->CallStaticLongMethodV(env, cls, mid, args);
        }
        else if (methType == INSTANCE) {
            jl = (*env)->CallLongMethodV(env, instObj, mid, args);
        }
        retval->j = jl;
    }
    else if (returnType == JINT) {
        jint ji = -1;
        if (methType == STATIC) {
            ji = (*env)->CallStaticIntMethodV(env, cls, mid, args);
        }
        else if (methType == INSTANCE) {
            ji = (*env)->CallIntMethodV(env, instObj, mid, args);
        }
        retval->i = ji;
    }

    jthr = (*env)->ExceptionOccurred(env);
    if (jthr) {
        (*env)->ExceptionClear(env);
        return jthr;
    }
    return NULL;
}

jthrowable findClassAndInvokeMethod(JNIEnv *env, jvalue *retval,
        MethType methType, jobject instObj, const char *className,
        const char *methName, const char *methSignature, ...)
{
    jclass cls = NULL;
    jthrowable jthr = NULL;

    va_list args;
    va_start(args, methSignature);

    jthr = validateMethodType(env, methType);
    if (jthr) {
        goto done;
    }

    cls = globalFindClass(env, className);
    if (!cls) {
        jthr = getPendingExceptionAndClear(env);
        goto done;
    }

    jthr = invokeMethodOnJclass(env, retval, methType, instObj, cls,
            className, methName, methSignature, args);

done:
    va_end(args);
    destroyLocalReference(env, cls);
    return jthr;
}

jthrowable invokeMethod(JNIEnv *env, jvalue *retval, MethType methType,
        jobject instObj, CachedJavaClass class,
        const char *methName, const char *methSignature, ...)
{
    jthrowable jthr;

    va_list args;
    va_start(args, methSignature);

    jthr = invokeMethodOnJclass(env, retval, methType, instObj,
            getJclass(class), getClassName(class), methName, methSignature,
            args);

    va_end(args);
    return jthr;
}

static jthrowable constructNewObjectOfJclass(JNIEnv *env,
        jobject *out, jclass cls, const char *className,
                const char *ctorSignature, va_list args) {
    jmethodID mid;
    jobject jobj;
    jthrowable jthr;

    jthr = methodIdFromClass(cls, className, "<init>", ctorSignature, INSTANCE,
            env, &mid);
    if (jthr)
        return jthr;
    jobj = (*env)->NewObjectV(env, cls, mid, args);
    if (!jobj)
        return getPendingExceptionAndClear(env);
    *out = jobj;
    return NULL;
}

jthrowable constructNewObjectOfClass(JNIEnv *env, jobject *out,
        const char *className, const char *ctorSignature, ...)
{
    va_list args;
    jclass cls;
    jthrowable jthr = NULL;

    cls = globalFindClass(env, className);
    if (!cls) {
        jthr = getPendingExceptionAndClear(env);
        goto done;
    }

    va_start(args, ctorSignature);
    jthr = constructNewObjectOfJclass(env, out, cls, className,
            ctorSignature, args);
    va_end(args);
done:
    destroyLocalReference(env, cls);
    return jthr;
}

jthrowable constructNewObjectOfCachedClass(JNIEnv *env, jobject *out,
        CachedJavaClass cachedJavaClass, const char *ctorSignature, ...)
{
    jthrowable jthr = NULL;
    va_list args;
    va_start(args, ctorSignature);

    jthr = constructNewObjectOfJclass(env, out,
            getJclass(cachedJavaClass), getClassName(cachedJavaClass),
            ctorSignature, args);

    va_end(args);
    return jthr;
}

jthrowable methodIdFromClass(jclass cls, const char *className,
        const char *methName, const char *methSignature, MethType methType,
        JNIEnv *env, jmethodID *out)
{
    jthrowable jthr;
    jmethodID mid = 0;

    jthr = validateMethodType(env, methType);
    if (jthr)
        return jthr;
    if (cls == NULL) {
        /*
         * A cached jclass can be NULL when the class is not resolvable through the
         * active classloader (e.g. commons-lang3 ExceptionUtils under an isolated
         * runtime classloader). GetStaticMethodID/GetMethodID do NOT null-check the
         * jclass and would dereference it, crashing the JVM. Fail cleanly instead.
         */
        return newRuntimeError(env, "methodIdFromClass(%s.%s): class not loaded "
            "(cached jclass is NULL under the active classloader)",
            className ? className : "(null)", methName);
    }
    if (methType == STATIC) {
        mid = (*env)->GetStaticMethodID(env, cls, methName, methSignature);
    }
    else if (methType == INSTANCE) {
        mid = (*env)->GetMethodID(env, cls, methName, methSignature);
    }
    if (mid == NULL) {
        fprintf(stderr, "could not find method %s from class %s with "
            "signature %s\n", methName, className, methSignature);
        return getPendingExceptionAndClear(env);
    }
    *out = mid;
    return NULL;
}

jthrowable classNameOfObject(jobject jobj, JNIEnv *env, char **name)
{
    jthrowable jthr;
    jclass cls, clsClass = NULL;
    jmethodID mid;
    jstring str = NULL;
    const char *cstr = NULL;
    char *newstr;

    cls = (*env)->GetObjectClass(env, jobj);
    if (cls == NULL) {
        jthr = getPendingExceptionAndClear(env);
        goto done;
    }
    clsClass = (*env)->FindClass(env, "java/lang/Class");
    if (clsClass == NULL) {
        jthr = getPendingExceptionAndClear(env);
        goto done;
    }
    mid = (*env)->GetMethodID(env, clsClass, "getName", "()Ljava/lang/String;");
    if (mid == NULL) {
        jthr = getPendingExceptionAndClear(env);
        goto done;
    }
    str = (*env)->CallObjectMethod(env, cls, mid);
    jthr = (*env)->ExceptionOccurred(env);
    if (jthr) {
        (*env)->ExceptionClear(env);
        goto done;
    }
    if (str == NULL) {
        jthr = getPendingExceptionAndClear(env);
        goto done;
    }
    cstr = (*env)->GetStringUTFChars(env, str, NULL);
    if (!cstr) {
        jthr = getPendingExceptionAndClear(env);
        goto done;
    }
    newstr = strdup(cstr);
    if (newstr == NULL) {
        jthr = newRuntimeError(env, "classNameOfObject: out of memory");
        goto done;
    }
    *name = newstr;
    jthr = NULL;

done:
    destroyLocalReference(env, cls);
    destroyLocalReference(env, clsClass);
    if (str) {
        if (cstr)
            (*env)->ReleaseStringUTFChars(env, str, cstr);
        (*env)->DeleteLocalRef(env, str);
    }
    return jthr;
}

/**
 * For the given path, expand it by filling in with all *.jar or *.JAR files,
 * separated by PATH_SEPARATOR. Assumes that expanded is big enough to hold the
 * string, eg allocated after using this function with expanded=NULL to get the
 * right size. Also assumes that the path ends with a "/.". The length of the
 * expanded path is returned, which includes space at the end for either a
 * PATH_SEPARATOR or null terminator.
 */
static ssize_t wildcard_expandPath(const char* path, char* expanded)
{
    struct dirent* file;
    char* dest = expanded;
    ssize_t length = 0;
    size_t pathLength = strlen(path);
    DIR* dir;

    dir = opendir(path);
    if (dir != NULL) {
        // can open dir so try to match with all *.jar and *.JAR entries

#ifdef _LIBHDFS_JNI_HELPER_DEBUGGING_ON_
        printf("wildcard_expandPath: %s\n", path);
#endif

        errno = 0;
        while ((file = readdir(dir)) != NULL) {
            const char* filename = file->d_name;
            const size_t filenameLength = strlen(filename);
            const char* jarExtension;

            // If filename is smaller than 4 characters then it can not possibly
            // have extension ".jar" or ".JAR"
            if (filenameLength < 4) {
                continue;
            }

            jarExtension = &filename[filenameLength-4];
            if ((strcmp(jarExtension, ".jar") == 0) ||
                (strcmp(jarExtension, ".JAR") == 0)) {

                // pathLength includes an extra '.' which we'll use for either
                // separator or null termination
                length += pathLength + filenameLength;

#ifdef _LIBHDFS_JNI_HELPER_DEBUGGING_ON_
                printf("wildcard_scanPath:\t%s\t:\t%zd\n", filename, length);
#endif

                if (expanded != NULL) {
                    // pathLength includes an extra '.'
                    memcpy(dest, path, pathLength - 1);
                    dest += pathLength - 1;
                    memcpy(dest, filename, filenameLength);
                    dest += filenameLength;
                    *dest = PATH_SEPARATOR;
                    dest++;

#ifdef _LIBHDFS_JNI_HELPER_DEBUGGING_ON_
                    printf("wildcard_expandPath:\t%s\t:\t%s\n",
                      filename, expanded);
#endif
                }
            }
        }

        if (errno != 0) {
            fprintf(stderr, "wildcard_expandPath: on readdir %s: %s\n",
              path, strerror(errno));
            length = -1;
        }

        if (closedir(dir) != 0) {
            fprintf(stderr, "wildcard_expandPath: on closedir %s: %s\n",
                    path, strerror(errno));
        }
    } else if ((errno != EACCES) && (errno != ENOENT) && (errno != ENOTDIR)) {
        // can not opendir due to an error we can not handle
        fprintf(stderr, "wildcard_expandPath: on opendir %s: %s\n", path,
                strerror(errno));
        length = -1;
    }

    if (length == 0) {
        // either we failed to open dir due to EACCESS, ENOENT, or ENOTDIR, or
        // we did not find any file that matches *.jar or *.JAR

#ifdef _LIBHDFS_JNI_HELPER_DEBUGGING_ON_
        fprintf(stderr, "wildcard_expandPath: can not expand %.*s*: %s\n",
                (int)(pathLength-1), path, strerror(errno));
#endif

        // in this case, the wildcard expansion is the same as the original
        // +1 for PATH_SEPARTOR or null termination
        length = pathLength + 1;
        if (expanded != NULL) {
            // pathLength includes an extra '.'
            strncpy(dest, path, pathLength-1);
            dest += pathLength-1;
            *dest = '*'; // restore wildcard
            dest++;
            *dest = PATH_SEPARATOR;
            dest++;
        }
    }

    return length;
}

/**
 * Helper to expand classpaths. Returns the total length of the expanded
 * classpath. If expandedClasspath is not NULL, then fills that with the
 * expanded classpath. It assumes that expandedClasspath is of correct size, eg
 * allocated after using this function with expandedClasspath=NULL to get the
 * right size.
 */
static ssize_t getClassPath_helper(const char *classpath, char* expandedClasspath)
{
    ssize_t length;
    ssize_t retval;
    char* expandedCP_curr;
    char* cp_token;
    char* classpath_dup;

    classpath_dup = strdup(classpath);
    if (classpath_dup == NULL) {
        fprintf(stderr, "getClassPath_helper: failed strdup: %s\n",
          strerror(errno));
        return -1;
    }

    length = 0;

    // expandedCP_curr is the current pointer
    expandedCP_curr = expandedClasspath;

    cp_token = strtok(classpath_dup, PATH_SEPARATOR_STR);
    while (cp_token != NULL) {
        size_t tokenlen;

#ifdef _LIBHDFS_JNI_HELPER_DEBUGGING_ON_
        printf("%s\n", cp_token);
#endif

        tokenlen = strlen(cp_token);
        // We only expand if token ends with "/*"
        if ((tokenlen > 1) &&
          (cp_token[tokenlen-1] == '*') && (cp_token[tokenlen-2] == '/')) {
            // replace the '*' with '.' so that we don't have to allocate another
            // string for passing to opendir() in wildcard_expandPath()
            cp_token[tokenlen-1] = '.';
            retval = wildcard_expandPath(cp_token, expandedCP_curr);
            if (retval < 0) {
                free(classpath_dup);
                return -1;
            }

            length += retval;
            if (expandedCP_curr != NULL) {
                expandedCP_curr += retval;
            }
        } else {
            // +1 for path separator or null terminator
            length += tokenlen + 1;
            if (expandedCP_curr != NULL) {
                memcpy(expandedCP_curr, cp_token, tokenlen);
                expandedCP_curr += tokenlen;
                *expandedCP_curr = PATH_SEPARATOR;
                expandedCP_curr++;
            }
        }

        cp_token = strtok(NULL, PATH_SEPARATOR_STR);
    }

    // Fix the last ':' and use it to null terminate
    if (expandedCP_curr != NULL) {
        expandedCP_curr--;
        *expandedCP_curr = '\0';
    }

    free(classpath_dup);
    return length;
}

/**
 * Expands a classpath string. Wild card entries are resolved only if the entry
 * ends with "/\*" (backslash to escape commenting) to match against .jar and
 * .JAR. All other wild card entries (eg /path/to/dir/\*foo*) are not resolved,
 * following JAVA default behavior, see:
 * https://docs.oracle.com/javase/8/docs/technotes/tools/unix/classpath.html
 * Returns a malloc'd expanded classpath, or NULL.
 */
static char* expandClassPath(const char* classpath)
{
    char* expandedClasspath;
    ssize_t length;
    ssize_t retval;

    if (classpath == NULL) {
      return NULL;
    }

    // First, get the total size of the string we will need for the expanded
    // classpath
    length = getClassPath_helper(classpath, NULL);
    if (length < 0) {
      return NULL;
    }

#ifdef _LIBHDFS_JNI_HELPER_DEBUGGING_ON_
    printf("+++++++++++++++++\n");
#endif

    // we don't have to do anything if classpath has no valid wildcards
    // we get length = 0 when CLASSPATH is set but empty
    // if CLASSPATH is not empty, then length includes null terminator
    // if length of expansion is same as original, then return a duplicate of
    // original since expansion can only be longer
    if ((length == 0) || ((length - 1) == strlen(classpath))) {

#ifdef _LIBHDFS_JNI_HELPER_DEBUGGING_ON_
        if ((length == 0) && (strlen(classpath) != 0)) {
            fprintf(stderr, "Something went wrong with getting the wildcard \
              expansion length\n" );
        }
#endif

        expandedClasspath = strdup(classpath);

#ifdef _LIBHDFS_JNI_HELPER_DEBUGGING_ON_
        printf("Expanded classpath=%s\n", expandedClasspath);
#endif

        return expandedClasspath;
    }

    // Allocte memory for expanded classpath string
    expandedClasspath = calloc(length, sizeof(char));
    if (expandedClasspath == NULL) {
        fprintf(stderr, "getClassPath: failed calloc: %s\n", strerror(errno));
        return NULL;
    }

    // Actual expansion
    retval = getClassPath_helper(classpath, expandedClasspath);
    if (retval < 0) {
        free(expandedClasspath);
        return NULL;
    }

    // This should not happen, but dotting i's and crossing t's
    if (retval != length) {
        fprintf(stderr,
          "Expected classpath expansion length to be %zu but instead got %zu\n",
          length, retval);
        free(expandedClasspath);
        return NULL;
    }

#ifdef _LIBHDFS_JNI_HELPER_DEBUGGING_ON_
    printf("===============\n");
    printf("Allocated %zd for expanding classpath\n", length);
    printf("Used %zu for expanding classpath\n", strlen(expandedClasspath) + 1);
    printf("Expanded classpath=%s\n", expandedClasspath);
#endif

    return expandedClasspath;
}

/* Gets the (wildcard-expanded) CLASSPATH environment variable, or NULL. */
static char* getClassPath()
{
    return expandClassPath(getenv("CLASSPATH"));
}


/* ===========================================================================
 * Optional isolated runtime classloader (OPT-IN, off by default).
 *
 * Dormant unless BOTH hold:
 *   (1) env LIBHDFS_RUNTIME_CLASSLOADER_PATH is a classpath (jars, dirs, and
 *       "dir/\*" globs, like CLASSPATH), and
 *   (2) libhdfs attached to a pre-existing JVM (it did not create the JVM).
 * When off, globalFindClass() == (*env)->FindClass(), so the default behaviour
 * is byte-for-byte unchanged.
 *
 * When on (libhdfs is loaded into a JVM that another component already created,
 * whose system classloader does not have the Hadoop jars on its classpath),
 * FindClass on an attached thread returns NULL -> crash. We instead resolve
 * Hadoop classes through an isolated classloader built from
 * LIBHDFS_RUNTIME_CLASSLOADER_PATH, and pin it as the thread context classloader
 * so Hadoop's ServiceLoader lookups (FileSystem impls) resolve too.
 *
 * That classloader is, by preference, an instance of the class named by env
 * LIBHDFS_RUNTIME_CLASSLOADER_CLASS (e.g. a child-first loader that keeps the
 * supplied classpath's dependency versions while delegating other classes to its
 * parent); if that env is unset or the class is not found, a plain URLClassLoader
 * (parent = system classloader) is used instead.
 * =========================================================================== */

/* -1 unknown; 0 = libhdfs created the JVM; 1 = JVM pre-existed (attach). */
static int gJvmPreexisting = -1;
/* Global ref to the isolated loader, or NULL when the gate is off. */
static jobject gRuntimeClassLoader = NULL;
/* java.lang.Class + Class.forName(String,boolean,ClassLoader), cached with the loader. */
static jclass gClassClassRef = NULL;
static jmethodID gForNameMethod = NULL;
/* java.lang.Thread + currentThread()/setContextClassLoader(), cached for cheap TCCL re-pinning. */
static jclass gThreadClassRef = NULL;
static jmethodID gCurrentThreadMethod = NULL;
static jmethodID gSetTcclMethod = NULL;
/* Set once the (expensive) loader build has been attempted, so a build failure
 * with the gate ON is not re-tried on every attaching thread. */
static int gLoaderInitAttempted = 0;

/* Build the runtime classloader over classPath (a classpath string: jars, dirs, and "dir/\*"
 * globs, like CLASSPATH): an instance of the class named by LIBHDFS_RUNTIME_CLASSLOADER_CLASS
 * (a custom, e.g. child-first, loader over those entries) when that env is set and the class is
 * present, else a plain parent-first URLClassLoader (parent = system classloader). Returns a new
 * global ref, or NULL (with any JNI exception cleared) on error. jvmMutex held. */
static jobject buildRuntimeClassLoader(JNIEnv *env, const char *classPath)
{
    char *expanded, *tok, *save = NULL;
    char **paths = NULL;
    size_t n = 0, cap = 0, i;
    int classRequested = 0;
    jclass fileCls = NULL, uriCls = NULL, urlCls = NULL, loaderCls = NULL, clCls = NULL, rclCls = NULL;
    jmethodID fileCtor = NULL, toURI = NULL, toURL = NULL, loaderCtor = NULL, getSystem = NULL, loadClassMid = NULL;
    jobjectArray urls = NULL;
    jobject system = NULL, bootstrap = NULL, loader = NULL, result = NULL;

    /* Expand any "dir/\*" entries to concrete jars, then split into per-entry paths
     * (each path is a jar or a directory of classes/resources). */
    expanded = expandClassPath(classPath);
    if (!expanded) {
        fprintf(stderr, "libhdfs runtime classloader: empty/invalid classpath\n");
        return NULL;
    }
    for (tok = strtok_r(expanded, PATH_SEPARATOR_STR, &save); tok != NULL;
         tok = strtok_r(NULL, PATH_SEPARATOR_STR, &save)) {
        char *dup, **grown;
        if (n == cap) {
            cap = cap ? cap * 2 : 64;
            grown = realloc(paths, cap * sizeof(*paths));
            if (!grown) { free(expanded); goto cleanup_paths; }
            paths = grown;
        }
        dup = strdup(tok);
        if (!dup) { free(expanded); goto cleanup_paths; }
        paths[n++] = dup;
    }
    free(expanded);
    if (n == 0) {
        fprintf(stderr, "libhdfs runtime classloader: empty classpath\n");
        goto cleanup_paths;
    }

    fileCls   = (*env)->FindClass(env, "java/io/File");
    uriCls    = (*env)->FindClass(env, "java/net/URI");
    urlCls    = (*env)->FindClass(env, "java/net/URL");
    loaderCls = (*env)->FindClass(env, "java/net/URLClassLoader");
    clCls     = (*env)->FindClass(env, "java/lang/ClassLoader");
    if (!fileCls || !uriCls || !urlCls || !loaderCls || !clCls) goto cleanup;
    fileCtor    = (*env)->GetMethodID(env, fileCls, "<init>", "(Ljava/lang/String;)V");
    toURI       = (*env)->GetMethodID(env, fileCls, "toURI", "()Ljava/net/URI;");
    toURL       = (*env)->GetMethodID(env, uriCls, "toURL", "()Ljava/net/URL;");
    loaderCtor   = (*env)->GetMethodID(env, loaderCls, "<init>",
                       "([Ljava/net/URL;Ljava/lang/ClassLoader;)V");
    getSystem    = (*env)->GetStaticMethodID(env, clCls, "getSystemClassLoader",
                       "()Ljava/lang/ClassLoader;");
    loadClassMid = (*env)->GetMethodID(env, clCls, "loadClass",
                       "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!fileCtor || !toURI || !toURL || !loaderCtor || !getSystem || !loadClassMid) goto cleanup;

    urls = (*env)->NewObjectArray(env, (jsize)n, urlCls, NULL);
    if (!urls) goto cleanup;
    for (i = 0; i < n; i++) {
        jstring js = (*env)->NewStringUTF(env, paths[i]);
        jobject file, uri, url;
        if (!js) goto cleanup;
        file = (*env)->NewObject(env, fileCls, fileCtor, js);
        (*env)->DeleteLocalRef(env, js);
        if (!file) goto cleanup;
        uri = (*env)->CallObjectMethod(env, file, toURI);
        (*env)->DeleteLocalRef(env, file);
        if (!uri || (*env)->ExceptionCheck(env)) goto cleanup;
        url = (*env)->CallObjectMethod(env, uri, toURL);
        (*env)->DeleteLocalRef(env, uri);
        if (!url || (*env)->ExceptionCheck(env)) goto cleanup;
        (*env)->SetObjectArrayElement(env, urls, (jsize)i, url);
        (*env)->DeleteLocalRef(env, url);
    }
    /* Parent = the system classloader so the loader can SEE the host's classes; a custom
     * child-first loader (LIBHDFS_RUNTIME_CLASSLOADER_CLASS, below) keeps the supplied jars'
     * dependency versions winning for code loaded through it. */
    system = (*env)->CallStaticObjectMethod(env, clCls, getSystem);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    /* Bootstrap loader (plain, parent=system): used only to load the custom loader class
     * out of the supplied jars. */
    bootstrap = (*env)->NewObject(env, loaderCls, loaderCtor, urls, system);
    if (!bootstrap || (*env)->ExceptionCheck(env)) goto cleanup;
    {
        /* Optional custom loader class (binary name); unset -> plain URLClassLoader. */
        const char *loaderClassName = getenv("LIBHDFS_RUNTIME_CLASSLOADER_CLASS");
        if (loaderClassName && *loaderClassName) {
            jstring rclName = (*env)->NewStringUTF(env, loaderClassName);
            classRequested = 1;
            if (rclName) {
                rclCls = (jclass) (*env)->CallObjectMethod(env, bootstrap, loadClassMid, rclName);
                (*env)->DeleteLocalRef(env, rclName);
            }
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); /* not present -> fall back */
        }
    }
    if (rclCls) {
        /* Custom loader ctor signature must match URLClassLoader(URL[], ClassLoader). */
        jmethodID rclCtor = (*env)->GetMethodID(env, rclCls, "<init>",
            "([Ljava/net/URL;Ljava/lang/ClassLoader;)V");
        if (rclCtor) {
            loader = (*env)->NewObject(env, rclCls, rclCtor, urls, system);
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); /* ctor missing/failed -> fall back */
    }
    if (!loader) {
        /* Fall back to the plain bootstrap loader (parent-first, parent=system). */
        if (classRequested) {
            fprintf(stderr, "libhdfs runtime classloader: configured loader class unavailable; "
                            "using plain parent-first URLClassLoader\n");
        }
        loader = bootstrap;
        bootstrap = NULL; /* ownership moves to 'loader'; avoid a double DeleteLocalRef */
    }
    result = (*env)->NewGlobalRef(env, loader);

cleanup:
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    if (loader)    (*env)->DeleteLocalRef(env, loader);
    if (bootstrap) (*env)->DeleteLocalRef(env, bootstrap);
    if (rclCls)    (*env)->DeleteLocalRef(env, rclCls);
    if (system)    (*env)->DeleteLocalRef(env, system);
    if (urls)      (*env)->DeleteLocalRef(env, urls);
    if (fileCls)   (*env)->DeleteLocalRef(env, fileCls);
    if (uriCls)    (*env)->DeleteLocalRef(env, uriCls);
    if (urlCls)    (*env)->DeleteLocalRef(env, urlCls);
    if (loaderCls) (*env)->DeleteLocalRef(env, loaderCls);
    if (clCls)     (*env)->DeleteLocalRef(env, clCls);
cleanup_paths:
    for (i = 0; i < n; i++) free(paths[i]);
    free(paths);
    return result;
}

/* Build the runtime loader + cache Class.forName once, if the gate is on. jvmMutex held. */
static void maybeInitRuntimeClassLoaderLocked(JNIEnv *env)
{
    const char *classPath;
    jclass classCls;
    if (gRuntimeClassLoader || gLoaderInitAttempted) return;
    classPath = getenv("LIBHDFS_RUNTIME_CLASSLOADER_PATH");
    if (!classPath || !*classPath) return; // gate off: stay responsive (cheap getenv), don't mark attempted
    gLoaderInitAttempted = 1;              // build at most once, even if it fails
    gRuntimeClassLoader = buildRuntimeClassLoader(env, classPath);
    if (!gRuntimeClassLoader) return;
    classCls = (*env)->FindClass(env, "java/lang/Class");
    if (classCls) {
        gForNameMethod = (*env)->GetStaticMethodID(env, classCls, "forName",
            "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
        gClassClassRef = (jclass) (*env)->NewGlobalRef(env, classCls);
        (*env)->DeleteLocalRef(env, classCls);
    }
    if (!gForNameMethod || !gClassClassRef) {
        /* Couldn't cache Class.forName: drop everything so globalFindClass stays on FindClass. */
        fprintf(stderr, "libhdfs runtime classloader: Class.forName unavailable; disabling\n");
        if (gClassClassRef) {
            (*env)->DeleteGlobalRef(env, gClassClassRef);
            gClassClassRef = NULL;
        }
        gForNameMethod = NULL;
        (*env)->DeleteGlobalRef(env, gRuntimeClassLoader);
        gRuntimeClassLoader = NULL;
    }
    /* Cache Thread.currentThread()/setContextClassLoader() for cheap per-call TCCL re-pinning.
     * Best-effort: if unavailable, TCCL pinning is skipped (globalFindClass still resolves through
     * the loader explicitly). */
    if (gRuntimeClassLoader) {
        jclass threadCls = (*env)->FindClass(env, "java/lang/Thread");
        if (threadCls) {
            jmethodID cur = (*env)->GetStaticMethodID(env, threadCls, "currentThread",
                                "()Ljava/lang/Thread;");
            jmethodID setc = (*env)->GetMethodID(env, threadCls, "setContextClassLoader",
                                "(Ljava/lang/ClassLoader;)V");
            if (cur && setc) {
                /* Keep the three in lockstep. NewGlobalRef can return NULL (OOM) without raising;
                 * setThreadContextClassLoader gates on the method ids, so a NULL gThreadClassRef with
                 * valid ids would reach CallStaticObjectMethod on a NULL class. Only commit all three
                 * once the global ref succeeds. */
                jclass threadRef = (jclass) (*env)->NewGlobalRef(env, threadCls);
                if (threadRef) {
                    gThreadClassRef = threadRef;
                    gCurrentThreadMethod = cur;
                    gSetTcclMethod = setc;
                }
            }
            (*env)->DeleteLocalRef(env, threadCls);
        }
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
}

/* Pin the runtime loader as this thread's context classloader (no-op if the gate is off or the
 * Thread accessors weren't cached). Cheap (cached method ids) and re-asserted on every getJNIEnv,
 * so a host that resets a pooled thread's TCCL between calls cannot strand a later Hadoop
 * Configuration/ServiceLoader on its own (Hadoop-free) loader. */
static void setThreadContextClassLoader(JNIEnv *env)
{
    jobject self;
    if (!gRuntimeClassLoader || !gCurrentThreadMethod || !gSetTcclMethod) {
        return;
    }
    self = (*env)->CallStaticObjectMethod(env, gThreadClassRef, gCurrentThreadMethod);
    if (self) {
        (*env)->CallVoidMethod(env, self, gSetTcclMethod, gRuntimeClassLoader);
        (*env)->DeleteLocalRef(env, self);
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
}

/* Resolve a class. Gate off: identical to (*env)->FindClass. Gate on: resolve
 * through the isolated runtime classloader via Class.forName(name, true, loader). */
jclass globalFindClass(JNIEnv *env, const char *className)
{
    char *binary;
    size_t len, k;
    jstring jname;
    jclass cls;
    if (!gRuntimeClassLoader || !gForNameMethod) {
        return (*env)->FindClass(env, className);
    }
    len = strlen(className);
    binary = malloc(len + 1);
    if (!binary) return (*env)->FindClass(env, className);
    for (k = 0; k < len; k++) binary[k] = (className[k] == '/') ? '.' : className[k];
    binary[len] = '\0';
    jname = (*env)->NewStringUTF(env, binary);
    free(binary);
    if (!jname) return NULL;
    cls = (jclass) (*env)->CallStaticObjectMethod(env, gClassClassRef, gForNameMethod,
              jname, JNI_TRUE, gRuntimeClassLoader);
    (*env)->DeleteLocalRef(env, jname);
    /* On failure Class.forName leaves a pending ClassNotFoundException and returns
     * NULL, matching FindClass's contract (callers do getPendingExceptionAndClear). */
    return cls;
}

/* Expose the isolated loader so other JNI code in the same process can resolve classes
 * through the SAME loader (one loader => one copy of Hadoop's static state, e.g. one UGI
 * login). Returns a JNI global ref (valid for the JVM lifetime), or NULL when the gate is
 * off. */
LIBHDFS_RUNTIME_EXPORT
jobject hdfsGetRuntimeClassLoader(void)
{
    return gRuntimeClassLoader;
}


/**
 * Get the global JNI environemnt.
 *
 * We only have to create the JVM once.  After that, we can use it in
 * every thread.  You must be holding the jvmMutex when you call this
 * function.
 *
 * @return          The JNIEnv on success; error code otherwise
 */
/* A cached JNIEnv is only valid while this thread is still attached to the VM. In an
 * embedding host a detach can happen behind libhdfs' back (an external
 * DetachCurrentThread, TLS-destructor ordering at thread exit of a pooled thread); the
 * stale env then points at a freed JavaThread and the first JNI call (FindClass in
 * setThreadContextClassLoader) crashes inside SymbolTable::do_lookup. Confirm the
 * attachment via GetEnv and re-attach instead of trusting the cache. */
static JNIEnv* revalidateCachedJNIEnv(JNIEnv *cached)
{
    JavaVM* vmBuf[VM_BUF_LENGTH];
    jint noVMs = 0;
    JNIEnv *cur = NULL;
    jint rc;

    if (JNI_GetCreatedJavaVMs(&(vmBuf[0]), VM_BUF_LENGTH, &noVMs) != 0) {
        return cached; /* cannot consult the VM registry - keep the prior behavior */
    }
    if (noVMs == 0) {
        return NULL; /* the VM is gone - the cached env necessarily dangles */
    }
    rc = (*vmBuf[0])->GetEnv(vmBuf[0], (void**)&cur, JNI_VERSION_1_2);
    if (rc == JNI_OK && cur != NULL) {
        return cur; /* still attached; cur == cached in the common case */
    }
    if (rc == JNI_EDETACHED) {
        if ((*vmBuf[0])->AttachCurrentThread(vmBuf[0], (void**)&cur, NULL) == JNI_OK) {
            return cur;
        }
        fprintf(stderr, "revalidateCachedJNIEnv: re-attach after an external detach failed\n");
    }
    return NULL;
}

static JNIEnv* getGlobalJNIEnv(void)
{
    JavaVM* vmBuf[VM_BUF_LENGTH]; 
    JNIEnv *env;
    jint rv = 0; 
    jint noVMs = 0;
    jthrowable jthr;
    char *hadoopClassPath;
    const char *hadoopClassPathVMArg = "-Djava.class.path=";
    size_t optHadoopClassPathLen;
    char *optHadoopClassPath;
    int noArgs = 1;
    char *hadoopJvmArgs;
    char jvmArgDelims[] = " ";
    char *str, *token, *savePtr;
    JavaVMInitArgs vm_args;
    JavaVM *vm;
    JavaVMOption *options;

    rv = JNI_GetCreatedJavaVMs(&(vmBuf[0]), VM_BUF_LENGTH, &noVMs);
    if (rv != 0) {
        fprintf(stderr, "JNI_GetCreatedJavaVMs failed with error: %d\n", rv);
        return NULL;
    }

    if (noVMs == 0) {
        // libhdfs is creating the JVM itself -> isolated loader stays off.
        gJvmPreexisting = 0;
        //Get the environment variables for initializing the JVM
        hadoopClassPath = getClassPath();
        if (hadoopClassPath == NULL) {
            fprintf(stderr, "Environment variable CLASSPATH not set!\n");
            return NULL;
        } 
        optHadoopClassPathLen = strlen(hadoopClassPath) + 
          strlen(hadoopClassPathVMArg) + 1;
        optHadoopClassPath = malloc(sizeof(char)*optHadoopClassPathLen);
        snprintf(optHadoopClassPath, optHadoopClassPathLen,
                "%s%s", hadoopClassPathVMArg, hadoopClassPath);

        free(hadoopClassPath);

        // Determine the # of LIBHDFS_OPTS args
        hadoopJvmArgs = getenv("LIBHDFS_OPTS");
        if (hadoopJvmArgs != NULL)  {
          hadoopJvmArgs = strdup(hadoopJvmArgs);
          for (noArgs = 1, str = hadoopJvmArgs; ; noArgs++, str = NULL) {
            token = strtok_r(str, jvmArgDelims, &savePtr);
            if (NULL == token) {
              break;
            }
          }
          free(hadoopJvmArgs);
        }

        // Now that we know the # args, populate the options array
        options = calloc(noArgs, sizeof(JavaVMOption));
        if (!options) {
          fputs("Call to calloc failed\n", stderr);
          free(optHadoopClassPath);
          return NULL;
        }
        options[0].optionString = optHadoopClassPath;
        hadoopJvmArgs = getenv("LIBHDFS_OPTS");
	if (hadoopJvmArgs != NULL)  {
          hadoopJvmArgs = strdup(hadoopJvmArgs);
          for (noArgs = 1, str = hadoopJvmArgs; ; noArgs++, str = NULL) {
            token = strtok_r(str, jvmArgDelims, &savePtr);
            if (NULL == token) {
              break;
            }
            options[noArgs].optionString = token;
          }
        }

        //Create the VM
        vm_args.version = JNI_VERSION_1_2;
        vm_args.options = options;
        vm_args.nOptions = noArgs; 
        vm_args.ignoreUnrecognized = 1;

        rv = JNI_CreateJavaVM(&vm, (void*)&env, &vm_args);

        if (hadoopJvmArgs != NULL)  {
          free(hadoopJvmArgs);
        }
        free(optHadoopClassPath);
        free(options);

        if (rv != 0) {
            fprintf(stderr, "Call to JNI_CreateJavaVM failed "
                    "with error: %d\n", rv);
            return NULL;
        }

        // We use findClassAndInvokeMethod here because the jclasses in
        // jclasses.h have not loaded yet
        jthr = findClassAndInvokeMethod(env, NULL, STATIC, NULL, HADOOP_FS,
                "loadFileSystems", "()V");
        if (jthr) {
            printExceptionAndFree(env, jthr, PRINT_EXC_ALL,
                    "FileSystem: loadFileSystems failed");
            return NULL;
        }
    } else {
        //Attach this thread to the VM
        vm = vmBuf[0];
        rv = (*vm)->AttachCurrentThread(vm, (void*)&env, 0);
        if (rv != 0) {
            fprintf(stderr, "Call to AttachCurrentThread "
                    "failed with error: %d\n", rv);
            return NULL;
        }
        /* JVM pre-existed (libhdfs did not create it). Build the isolated runtime classloader
         * once (no-op unless LIBHDFS_RUNTIME_CLASSLOADER_PATH is set). The thread context
         * classloader is pinned by getJNIEnv, re-asserted on every call. */
        if (gJvmPreexisting != 0) {
            gJvmPreexisting = 1;
            maybeInitRuntimeClassLoaderLocked(env);
        }
    }

    return env;
}

/**
 * getJNIEnv: A helper function to get the JNIEnv* for the given thread.
 * If no JVM exists, then one will be created. JVM command line arguments
 * are obtained from the LIBHDFS_OPTS environment variable.
 *
 * Implementation note: we rely on POSIX thread-local storage (tls).
 * This allows us to associate a destructor function with each thread, that
 * will detach the thread from the Java VM when the thread terminates.  If we
 * failt to do this, it will cause a memory leak.
 *
 * However, POSIX TLS is not the most efficient way to do things.  It requires a
 * key to be initialized before it can be used.  Since we don't know if this key
 * is initialized at the start of this function, we have to lock a mutex first
 * and check.  Luckily, most operating systems support the more efficient
 * __thread construct, which is initialized by the linker.
 *
 * @param: None.
 * @return The JNIEnv* corresponding to the thread.
 */
JNIEnv* getJNIEnv(void)
{
    struct ThreadLocalState *state = NULL;
    THREAD_LOCAL_STORAGE_GET_QUICK(&state);
    if (state) {
      state->env = revalidateCachedJNIEnv(state->env);
      if (!state->env) {
        return NULL;
      }
      /* Re-assert the context classloader (no-op unless the isolated loader is active), in case
       * the host reset this (possibly pooled) thread's TCCL since the last call. */
      setThreadContextClassLoader(state->env);
      return state->env;
    }

    mutexLock(&jvmMutex);
    if (threadLocalStorageGet(&state)) {
      mutexUnlock(&jvmMutex);
      return NULL;
    }
    if (state) {
      mutexUnlock(&jvmMutex);

      // Free any stale exception strings.
      free(state->lastExceptionRootCause);
      free(state->lastExceptionStackTrace);
      state->lastExceptionRootCause = NULL;
      state->lastExceptionStackTrace = NULL;

      state->env = revalidateCachedJNIEnv(state->env);
      if (!state->env) {
        return NULL;
      }
      setThreadContextClassLoader(state->env);
      return state->env;
    }

    /* Create a ThreadLocalState for this thread */
    state = threadLocalStorageCreate();
    if (!state) {
      mutexUnlock(&jvmMutex);
      fprintf(stderr, "getJNIEnv: Unable to create ThreadLocalState\n");
      return NULL;
    }

    state->env = getGlobalJNIEnv();
    if (!state->env) {
        mutexUnlock(&jvmMutex);
        goto fail;
    }

    jthrowable jthr = NULL;
    jthr = initCachedClasses(state->env);
    if (jthr) {
      mutexUnlock(&jvmMutex);
      printExceptionAndFree(state->env, jthr, PRINT_EXC_ALL,
                            "initCachedClasses failed");
      goto fail;
    }

    if (threadLocalStorageSet(state)) {
      mutexUnlock(&jvmMutex);
      goto fail;
    }

    // set the TLS var only when the state passes all the checks
    THREAD_LOCAL_STORAGE_SET_QUICK(state);
    mutexUnlock(&jvmMutex);

    setThreadContextClassLoader(state->env);
    return state->env;

fail:
    fprintf(stderr, "getJNIEnv: getGlobalJNIEnv failed\n");
    hdfsThreadDestructor(state);
    return NULL;
}

char* getLastTLSExceptionRootCause()
{
    struct ThreadLocalState *state = NULL;
    THREAD_LOCAL_STORAGE_GET_QUICK(&state);
    if (!state) {
        mutexLock(&jvmMutex);
        if (threadLocalStorageGet(&state)) {
            mutexUnlock(&jvmMutex);
            return NULL;
        }
        mutexUnlock(&jvmMutex);
    }
    return state->lastExceptionRootCause;
}

char* getLastTLSExceptionStackTrace()
{
    struct ThreadLocalState *state = NULL;
    THREAD_LOCAL_STORAGE_GET_QUICK(&state);
    if (!state) {
        mutexLock(&jvmMutex);
        if (threadLocalStorageGet(&state)) {
            mutexUnlock(&jvmMutex);
            return NULL;
        }
        mutexUnlock(&jvmMutex);
    }
    return state->lastExceptionStackTrace;
}

void setTLSExceptionStrings(const char *rootCause, const char *stackTrace)
{
    struct ThreadLocalState *state = NULL;
    THREAD_LOCAL_STORAGE_GET_QUICK(&state);
    if (!state) {
        mutexLock(&jvmMutex);
        if (threadLocalStorageGet(&state)) {
            mutexUnlock(&jvmMutex);
            return;
        }
        mutexUnlock(&jvmMutex);
    }

    free(state->lastExceptionRootCause);
    free(state->lastExceptionStackTrace);
    state->lastExceptionRootCause = (char*)rootCause;
    state->lastExceptionStackTrace = (char*)stackTrace;
}

int javaObjectIsOfClass(JNIEnv *env, jobject obj, const char *name)
{
    jclass clazz;
    int ret;

    clazz = globalFindClass(env, name);
    if (!clazz) {
        printPendingExceptionAndFree(env, PRINT_EXC_ALL,
            "javaObjectIsOfClass(%s)", name);
        return -1;
    }
    ret = (*env)->IsInstanceOf(env, obj, clazz);
    (*env)->DeleteLocalRef(env, clazz);
    return ret == JNI_TRUE ? 1 : 0;
}

jthrowable hadoopConfSetStr(JNIEnv *env, jobject jConfiguration,
        const char *key, const char *value)
{
    jthrowable jthr;
    jstring jkey = NULL, jvalue = NULL;

    jthr = newJavaStr(env, key, &jkey);
    if (jthr)
        goto done;
    jthr = newJavaStr(env, value, &jvalue);
    if (jthr)
        goto done;
    jthr = invokeMethod(env, NULL, INSTANCE, jConfiguration,
            JC_CONFIGURATION, "set", "(Ljava/lang/String;Ljava/lang/String;)V",
            jkey, jvalue);
    if (jthr)
        goto done;
done:
    (*env)->DeleteLocalRef(env, jkey);
    (*env)->DeleteLocalRef(env, jvalue);
    return jthr;
}

jthrowable fetchEnumInstance(JNIEnv *env, const char *className,
                         const char *valueName, jobject *out)
{
    jclass clazz;
    jfieldID fieldId;
    jobject jEnum;
    char prettyClass[256];

    clazz = globalFindClass(env, className);
    if (!clazz) {
        return getPendingExceptionAndClear(env);
    }
    if (snprintf(prettyClass, sizeof(prettyClass), "L%s;", className)
          >= sizeof(prettyClass)) {
        return newRuntimeError(env, "fetchEnum(%s, %s): class name too long.",
                className, valueName);
    }
    fieldId = (*env)->GetStaticFieldID(env, clazz, valueName, prettyClass);
    if (!fieldId) {
        return getPendingExceptionAndClear(env);
    }
    jEnum = (*env)->GetStaticObjectField(env, clazz, fieldId);
    if (!jEnum) {
        return getPendingExceptionAndClear(env);
    }
    *out = jEnum;
    return NULL;
}

