#ifndef KIITE_UPLOAD_H
#define KIITE_UPLOAD_H

#include <stdint.h>

#define KIITE_PHASE_HASHING 0
#define KIITE_PHASE_CONNECTING 1
#define KIITE_PHASE_DIRECTORIES 2
#define KIITE_PHASE_UPLOADING 3
#define KIITE_PHASE_VERIFYING 4
#define KIITE_PHASE_PUBLISHING 5

typedef struct {
    int64_t written;
    int64_t total;
    int cancel;
    int phase;
    int64_t verified;
} KiiteProgress;

typedef struct {
    int code;
    int64_t bytes_written;
    char message[240];
    double connect_seconds;
    double directory_seconds;
    double write_seconds;
    double verify_seconds;
    double publish_seconds;
    double close_seconds;
} KiiteUploadResult;

typedef struct {
    int code;
    char algorithm[64];
    char sha256_hex[65];
    char message[240];
} KiiteProbeResult;

/* Handshake only. Copies the server host-key algorithm and SHA-256.
   Does not authenticate and does not read credentials. */
int kiite_probe_hostkey(const char *_Nonnull host, int port, KiiteProbeResult *_Nonnull result);

void kiite_progress_cancel(KiiteProgress *_Nonnull progress);
KiiteProgress kiite_progress_snapshot(KiiteProgress *_Nonnull progress);

/* Publishes local_path by writing staging_path and posix-rename onto final_path.
   Host-key mismatch returns 10 before any userauth call.
   file_sha256_hex is compared to a read-back of the staging object before rename.
   key_path and password are alternatives; passphrase applies only to key_path. */
int kiite_upload_file(
    const char *_Nonnull host,
    int port,
    const char *_Nonnull user,
    const char *_Nullable key_path,
    const char *_Nullable passphrase,
    const char *_Nullable password,
    const char *_Nonnull host_sha256_hex,
    const char *_Nonnull local_path,
    const char *_Nonnull file_sha256_hex,
    const char *_Nonnull staging_path,
    const char *_Nonnull final_path,
    KiiteProgress *_Nullable progress,
    KiiteUploadResult *_Nonnull result);

/* Authenticated check that both SFTP paths are directories and are not symlinks.
   Host-key mismatch returns 10 before userauth. */
int kiite_check_directories(
    const char *_Nonnull host,
    int port,
    const char *_Nonnull user,
    const char *_Nullable key_path,
    const char *_Nullable passphrase,
    const char *_Nullable password,
    const char *_Nonnull host_sha256_hex,
    const char *_Nonnull remote_root,
    const char *_Nonnull staging_root,
    KiiteUploadResult *_Nonnull result);

/* Removes one regular file. Refuses empty paths, "/", and any ".." segment.
   Host-key mismatch returns 10 before userauth. */
int kiite_remove_file(
    const char *_Nonnull host,
    int port,
    const char *_Nonnull user,
    const char *_Nullable key_path,
    const char *_Nullable passphrase,
    const char *_Nullable password,
    const char *_Nonnull host_sha256_hex,
    const char *_Nonnull remote_path,
    KiiteUploadResult *_Nonnull result);

#endif
