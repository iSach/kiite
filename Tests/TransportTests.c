#include "upload.h"
#include <assert.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *root, *user, *key, *pin;
static int port;

static void digest(const char *path, char hex[65]) {
    FILE *file = fopen(path, "rb");
    assert(file);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    assert(ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1);
    unsigned char buffer[65536], bytes[32];
    size_t got;
    while ((got = fread(buffer, 1, sizeof(buffer), file))) {
        assert(EVP_DigestUpdate(ctx, buffer, got) == 1);
    }
    assert(!ferror(file));
    fclose(file);
    unsigned int count;
    assert(EVP_DigestFinal_ex(ctx, bytes, &count) == 1 && count == 32);
    EVP_MD_CTX_free(ctx);
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", bytes[i]);
}

static void make_file(const char *path, size_t size) {
    FILE *file = fopen(path, "wb");
    assert(file);
    unsigned char buffer[65536];
    unsigned int seed = 17;
    for (size_t i = 0; i < sizeof(buffer); i++) {
        seed = seed * 1664525 + 1013904223;
        buffer[i] = seed >> 24;
    }
    while (size) {
        size_t count = size < sizeof(buffer) ? size : sizeof(buffer);
        assert(fwrite(buffer, 1, count, file) == count);
        size -= count;
    }
    assert(fclose(file) == 0);
}

struct Job {
    char local[4096], staging[4096], final[4096], hash[65];
    KiiteProgress progress;
    KiiteUploadResult result;
    int code, done;
};

static void prepare(struct Job *job, const char *name, size_t size) {
    memset(job, 0, sizeof(*job));
    snprintf(job->local, sizeof(job->local), "%s/%s", root, name);
    snprintf(job->staging, sizeof(job->staging), "%s/staging/%s", root, name);
    snprintf(job->final, sizeof(job->final), "%s/public/nested/%s", root, name);
    make_file(job->local, size);
    digest(job->local, job->hash);
    job->progress.total = (int64_t)size;
}

static void *send(void *value) {
    struct Job *job = value;
    job->code = kiite_upload_file("127.0.0.1", port, user, key, NULL, NULL, pin,
        job->local, job->hash, job->staging, job->final, &job->progress, &job->result);
    __atomic_store_n(&job->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void roundtrip(const char *name, size_t size) {
    struct Job job;
    prepare(&job, name, size);
    send(&job);
    if (job.code) fprintf(stderr, "%s failed: %d %s\n", name, job.code, job.result.message);
    assert(job.code == 0 && job.result.bytes_written == (int64_t)size);
    assert(access(job.staging, F_OK) != 0);
    char actual[65];
    digest(job.final, actual);
    assert(!strcmp(actual, job.hash));
    KiiteProgress p = kiite_progress_snapshot(&job.progress);
    assert(p.written == (int64_t)size && p.verified == (int64_t)size);
    printf("PASS roundtrip %zu bytes, complete digest and progress\n", size);
}

static void cancel_phase(int phase, const char *name) {
    struct Job job;
    prepare(&job, name, 64 * 1024 * 1024);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, send, &job) == 0);
    int observed = 0;
    for (int i = 0; i < 30000 && !__atomic_load_n(&job.done, __ATOMIC_ACQUIRE); i++) {
        KiiteProgress p = kiite_progress_snapshot(&job.progress);
        if (p.phase == phase && (phase == KIITE_PHASE_VERIFYING ? p.verified : p.written) > 0) {
            observed = 1;
            kiite_progress_cancel(&job.progress);
            break;
        }
        usleep(500);
    }
    if (!observed) kiite_progress_cancel(&job.progress);
    assert(pthread_join(thread, NULL) == 0);
    assert(observed && job.code == 11);
    assert(access(job.staging, F_OK) != 0 && access(job.final, F_OK) != 0);
    printf("PASS cancellation during %s, unpublished staging removed\n", name);
}

int main(int argc, char **argv) {
    assert(argc == 6);
    root = argv[1]; user = argv[2]; key = argv[3]; pin = argv[4]; port = atoi(argv[5]);
    roundtrip("empty.bin", 0);
    roundtrip("small.bin", 17);
    roundtrip("partial-buffer.bin", 1024 * 1024 + 113);
    roundtrip("large.bin", 4 * 1024 * 1024 + 37);
    struct Job job;
    prepare(&job, "wrong-hash.bin", 1024 * 1024 + 37);
    job.hash[0] = job.hash[0] == 'a' ? 'b' : 'a';
    send(&job);
    assert(job.code == 9 && access(job.final, F_OK) != 0 && access(job.staging, F_OK) != 0);
    puts("PASS hash mismatch refuses publication and removes staging");
    prepare(&job, "wrong-pin.bin", 17);
    char wrong[65]; memset(wrong, '0', 64); wrong[64] = 0;
    int code = kiite_upload_file("127.0.0.1", port, user, key, NULL, NULL, wrong,
        job.local, job.hash, job.staging, job.final, &job.progress, &job.result);
    assert(code == 10 && access(job.final, F_OK) != 0);
    puts("PASS wrong host pin refuses upload");
    char link[4096], target[4096];
    snprintf(link, sizeof(link), "%s/link", root);
    snprintf(target, sizeof(target), "%s/public", root);
    assert(symlink(target, link) == 0);
    prepare(&job, "symlink.bin", 17);
    snprintf(job.final, sizeof(job.final), "%s/link/symlink.bin", root);
    send(&job);
    assert(job.code == 6 && access(job.final, F_OK) != 0 && access(job.staging, F_OK) != 0);
    puts("PASS symlink ancestor remains rejected");
    cancel_phase(KIITE_PHASE_UPLOADING, "upload-cancel.bin");
    cancel_phase(KIITE_PHASE_VERIFYING, "verify-cancel.bin");
    return 0;
}
