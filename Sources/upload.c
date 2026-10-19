#include "upload.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <libssh2.h>
#include <libssh2_sftp.h>
#include <openssl/evp.h>

struct Conn {
    int fd;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftp;
};

/* A large caller buffer lets libssh2 pipeline multiple SFTP packets. Keep the
   buffer unchanged until every partial write has consumed its original data. */
#define TRANSFER_BUFFER_SIZE (1024 * 1024)

static double monotonic_seconds(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec + value.tv_nsec / 1e9;
}

static void note_phase(KiiteProgress *progress, int phase) {
    if (progress != NULL) {
        __atomic_store_n(&progress->phase, phase, __ATOMIC_RELAXED);
    }
}

static void set_message(KiiteUploadResult *result, const char *text) {
    snprintf(result->message, sizeof(result->message), "%s", text);
}

static void note_progress(KiiteProgress *progress, int64_t written) {
    if (progress == NULL) {
        return;
    }
    __atomic_store_n(&progress->written, written, __ATOMIC_RELAXED);
}

static int cancelled(KiiteProgress *progress) {
    if (progress == NULL) {
        return 0;
    }
    return __atomic_load_n(&progress->cancel, __ATOMIC_RELAXED) != 0;
}

void kiite_progress_cancel(KiiteProgress *progress) {
    if (progress != NULL) {
        __atomic_store_n(&progress->cancel, 1, __ATOMIC_RELAXED);
    }
}

KiiteProgress kiite_progress_snapshot(KiiteProgress *progress) {
    KiiteProgress snapshot;
    snapshot.written = __atomic_load_n(&progress->written, __ATOMIC_RELAXED);
    snapshot.total = progress->total;
    snapshot.cancel = __atomic_load_n(&progress->cancel, __ATOMIC_RELAXED);
    snapshot.phase = __atomic_load_n(&progress->phase, __ATOMIC_RELAXED);
    snapshot.verified = __atomic_load_n(&progress->verified, __ATOMIC_RELAXED);
    return snapshot;
}

static int hex_equal(const char *got, const char *expected) {
    if (got == NULL || expected == NULL || strlen(got) != 64 || strlen(expected) != 64) {
        return 0;
    }
    for (int i = 0; i < 64; i++) {
        char a = got[i];
        char b = expected[i];
        if (a >= 'A' && a <= 'F') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'F') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

static const char *algorithm_name(int type) {
    switch (type) {
    case LIBSSH2_HOSTKEY_TYPE_RSA:
        return "ssh-rsa";
    case LIBSSH2_HOSTKEY_TYPE_DSS:
        return "ssh-dss";
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
        return "ecdsa-sha2-nistp256";
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
        return "ecdsa-sha2-nistp384";
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
        return "ecdsa-sha2-nistp521";
    case LIBSSH2_HOSTKEY_TYPE_ED25519:
        return "ssh-ed25519";
    default:
        return "unknown";
    }
}

static int fill_hostkey(LIBSSH2_SESSION *session, char *algorithm, size_t algorithm_len, char *hex, size_t hex_len) {
    size_t key_len = 0;
    int type = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
    const char *key = libssh2_session_hostkey(session, &key_len, &type);
    const unsigned char *hash = (const unsigned char *)libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256);
    if (key == NULL || hash == NULL || algorithm_len < 8 || hex_len < 65) {
        return -1;
    }
    snprintf(algorithm, algorithm_len, "%s", algorithm_name(type));
    for (int i = 0; i < 32; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = 0;
    return 0;
}

static int path_is_safe(const char *path) {
    if (path == NULL || path[0] != '/' || path[1] == '\0') {
        return 0;
    }
    size_t length = strlen(path);
    if (length >= 4096 || strstr(path, "//") != NULL) {
        return 0;
    }
    const char *cursor = path;
    while (*cursor != '\0') {
        const char *slash = strchr(cursor + 1, '/');
        size_t segment = slash == NULL ? strlen(cursor + 1) : (size_t)(slash - (cursor + 1));
        if (segment == 0 || (segment == 1 && cursor[1] == '.') || (segment == 2 && cursor[1] == '.' && cursor[2] == '.')) {
            return 0;
        }
        if (slash == NULL) {
            break;
        }
        cursor = slash;
    }
    return 1;
}

static int connect_tcp(const char *host, int port) {
    if (host == NULL || host[0] == '\0' || port < 1 || port > 65535) {
        return -1;
    }
    char port_text[8];
    snprintf(port_text, sizeof(port_text), "%d", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *results = NULL;
    if (getaddrinfo(host, port_text, &hints, &results) != 0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *item = results; item != NULL; item = item->ai_next) {
        fd = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        int rc = connect(fd, item->ai_addr, item->ai_addrlen);
        if (rc != 0 && errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }
        if (rc != 0) {
            struct pollfd ready;
            ready.fd = fd;
            ready.events = POLLOUT;
            int waited;
            do {
                waited = poll(&ready, 1, 15000);
            } while (waited < 0 && errno == EINTR);
            int soerr = 0;
            socklen_t length = sizeof(soerr);
            if (waited != 1 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &length) < 0 || soerr != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }
        fcntl(fd, F_SETFL, flags);
        struct timeval budget;
        budget.tv_sec = 60;
        budget.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &budget, sizeof(budget));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &budget, sizeof(budget));
        break;
    }
    freeaddrinfo(results);
    return fd;
}

static void close_conn(struct Conn *conn, int code) {
    if (conn->sftp != NULL) {
        libssh2_sftp_shutdown(conn->sftp);
        conn->sftp = NULL;
    }
    if (conn->session != NULL) {
        libssh2_session_disconnect(conn->session, code == 10 ? "host key rejected before auth" : "done");
        libssh2_session_free(conn->session);
        conn->session = NULL;
    }
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

static int handshake_session(struct Conn *conn, char *algorithm, size_t algorithm_len, char *hex, size_t hex_len, KiiteUploadResult *result) {
    conn->session = libssh2_session_init();
    if (conn->session == NULL) {
        set_message(result, "ssh session init failed");
        return 4;
    }
    libssh2_session_set_blocking(conn->session, 1);
    if (libssh2_session_handshake(conn->session, conn->fd) != 0) {
        set_message(result, "handshake failed");
        return 4;
    }
    if (fill_hostkey(conn->session, algorithm, algorithm_len, hex, hex_len) != 0) {
        set_message(result, "host key is unavailable");
        return 10;
    }
    return 0;
}

/* Opens an authenticated SFTP session. A host-key mismatch returns 10
   before userauth and before the password or key file is sent. */
static int open_authenticated(
    const char *host,
    int port,
    const char *user,
    const char *key_path,
    const char *passphrase,
    const char *password,
    const char *host_sha256_hex,
    struct Conn *conn,
    KiiteUploadResult *result) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
    if (user == NULL || user[0] == '\0') {
        set_message(result, "username is missing");
        return 5;
    }
    if (host_sha256_hex == NULL || strlen(host_sha256_hex) != 64) {
        set_message(result, "host key is not trusted");
        return 10;
    }
    libssh2_init(0);
    conn->fd = connect_tcp(host, port);
    if (conn->fd < 0) {
        set_message(result, "cannot connect");
        return 2;
    }
    char algorithm[64];
    char hex[65];
    int code = handshake_session(conn, algorithm, sizeof(algorithm), hex, sizeof(hex), result);
    if (code != 0) {
        close_conn(conn, code);
        return code;
    }
    if (!hex_equal(hex, host_sha256_hex)) {
        set_message(result, "host key rejected before auth");
        close_conn(conn, 10);
        return 10;
    }
    int auth;
    if (key_path != NULL && key_path[0] != '\0') {
        const char *phrase = (passphrase != NULL && passphrase[0] != '\0') ? passphrase : NULL;
        auth = libssh2_userauth_publickey_fromfile(conn->session, user, NULL, key_path, phrase);
        if (auth != 0) {
            set_message(result, "public key authentication failed");
            close_conn(conn, 5);
            return 5;
        }
    } else if (password != NULL && password[0] != '\0') {
        auth = libssh2_userauth_password(conn->session, user, password);
        if (auth != 0) {
            set_message(result, "password authentication failed");
            close_conn(conn, 5);
            return 5;
        }
    } else {
        set_message(result, "no credential provided");
        close_conn(conn, 5);
        return 5;
    }
    conn->sftp = libssh2_sftp_init(conn->session);
    if (conn->sftp == NULL) {
        set_message(result, "sftp init failed");
        close_conn(conn, 6);
        return 6;
    }
    return 0;
}

int kiite_probe_hostkey(const char *host, int port, KiiteProbeResult *result) {
    if (result == NULL) {
        return 2;
    }
    memset(result, 0, sizeof(*result));
    libssh2_init(0);
    struct Conn conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = connect_tcp(host, port);
    if (conn.fd < 0) {
        snprintf(result->message, sizeof(result->message), "cannot connect");
        result->code = 2;
        return 2;
    }
    KiiteUploadResult handshake;
    memset(&handshake, 0, sizeof(handshake));
    int code = handshake_session(&conn, result->algorithm, sizeof(result->algorithm), result->sha256_hex, sizeof(result->sha256_hex), &handshake);
    if (code != 0) {
        snprintf(result->message, sizeof(result->message), "%s", handshake.message);
        close_conn(&conn, code);
        result->code = code;
        return code;
    }
    /* Probe stops here. Credentials are not read and userauth is not called. */
    snprintf(result->message, sizeof(result->message), "host key");
    close_conn(&conn, 0);
    result->code = 0;
    return 0;
}

static int mkdir_one(LIBSSH2_SFTP *sftp, const char *path, long mode) {
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    memset(&attrs, 0, sizeof(attrs));
    if (libssh2_sftp_lstat(sftp, path, &attrs) != 0) {
        if (libssh2_sftp_last_error(sftp) != LIBSSH2_FX_NO_SUCH_FILE) {
            return -1;
        }
        if (libssh2_sftp_mkdir(sftp, path, mode) == 0) {
            return 0;
        }
        // A concurrent upload may have created it. Still reject symlinks.
        memset(&attrs, 0, sizeof(attrs));
        if (libssh2_sftp_lstat(sftp, path, &attrs) != 0) {
            return -1;
        }
    }
    if ((attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) == 0) {
        return -1;
    }
    if (LIBSSH2_SFTP_S_ISLNK(attrs.permissions) || !LIBSSH2_SFTP_S_ISDIR(attrs.permissions)) {
        return -1;
    }
    return 0;
}

static int ensure_directories(LIBSSH2_SFTP *sftp, const char *file_path, long mode) {
    size_t length = strlen(file_path);
    if (length < 2 || length >= 4096 || file_path[0] != '/') {
        return -1;
    }
    char path[4096];
    memcpy(path, file_path, length + 1);
    char *last = strrchr(path, '/');
    if (last == NULL) {
        return -1;
    }
    if (last == path) {
        return 0;
    }
    *last = '\0';
    for (char *cursor = path + 1; *cursor != '\0'; cursor++) {
        if (*cursor != '/') {
            continue;
        }
        *cursor = '\0';
        if (mkdir_one(sftp, path, mode) != 0) {
            return -1;
        }
        *cursor = '/';
    }
    return mkdir_one(sftp, path, mode);
}

static int directory_ok(LIBSSH2_SFTP *sftp, const char *path) {
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    memset(&attrs, 0, sizeof(attrs));
    if (libssh2_sftp_lstat(sftp, path, &attrs) != 0) {
        return 0;
    }
    if ((attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) == 0) {
        return 0;
    }
    if (LIBSSH2_SFTP_S_ISLNK(attrs.permissions) || !LIBSSH2_SFTP_S_ISDIR(attrs.permissions)) {
        return 0;
    }
    return 1;
}

static void unlink_quiet(LIBSSH2_SFTP *sftp, const char *path) {
    if (path != NULL && path_is_safe(path)) {
        libssh2_sftp_unlink(sftp, path);
    }
}

static int write_local_file(
    LIBSSH2_SFTP *sftp,
    const char *path,
    FILE *local,
    KiiteProgress *progress,
    int64_t *written_out,
    char *error,
    size_t error_len) {
    LIBSSH2_SFTP_HANDLE *handle = libssh2_sftp_open(
        sftp, path,
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
        0600);
    if (handle == NULL) {
        snprintf(error, error_len, "staging open failed");
        return 3;
    }
    char *buffer = malloc(TRANSFER_BUFFER_SIZE);
    if (buffer == NULL) {
        libssh2_sftp_close(handle);
        unlink_quiet(sftp, path);
        snprintf(error, error_len, "transfer buffer unavailable");
        return 3;
    }
    int code = 0;
    int64_t written = 0;
    for (;;) {
        if (cancelled(progress)) {
            snprintf(error, error_len, "cancelled");
            code = 11;
            goto done;
        }
        size_t got = fread(buffer, 1, TRANSFER_BUFFER_SIZE, local);
        if (got == 0) {
            if (ferror(local)) {
                snprintf(error, error_len, "read snapshot failed");
                code = 3;
                goto done;
            }
            break;
        }
        size_t offset = 0;
        while (offset < got) {
            if (cancelled(progress)) {
                snprintf(error, error_len, "cancelled");
                code = 11;
                goto done;
            }
            ssize_t chunk = libssh2_sftp_write(handle, buffer + offset, got - offset);
            if (chunk < 0) {
                snprintf(error, error_len, "staging write failed");
                code = 3;
                goto done;
            }
            if (chunk == 0) {
                snprintf(error, error_len, "staging write stalled");
                code = 3;
                goto done;
            }
            offset += (size_t)chunk;
            written += chunk;
            note_progress(progress, written);
        }
    }
    int synced = libssh2_sftp_fsync(handle);
    if (synced != 0) {
        unsigned long sftp_error = libssh2_sftp_last_error(sftp);
        if (sftp_error != LIBSSH2_FX_OP_UNSUPPORTED) {
            snprintf(error, error_len, "staging fsync failed");
            code = 3;
            goto done;
        }
    }
done:
    free(buffer);
    int closed = libssh2_sftp_close(handle);
    if (code == 0 && closed != 0) {
        snprintf(error, error_len, "staging close failed");
        code = 3;
    }
    if (code != 0) { unlink_quiet(sftp, path); }
    *written_out = written;
    return code;
}

static int sha256_remote(LIBSSH2_SFTP *sftp, const char *path, KiiteProgress *progress, char hex[65], char *error, size_t error_len) {
    LIBSSH2_SFTP_HANDLE *handle = libssh2_sftp_open(sftp, path, LIBSSH2_FXF_READ, 0);
    if (handle == NULL) {
        snprintf(error, error_len, "staging read-back failed");
        return 3;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        libssh2_sftp_close(handle);
        snprintf(error, error_len, "staging read-back failed");
        return 3;
    }
    char *buffer = malloc(TRANSFER_BUFFER_SIZE);
    if (buffer == NULL) {
        EVP_MD_CTX_free(ctx);
        libssh2_sftp_close(handle);
        snprintf(error, error_len, "verification buffer unavailable");
        return 3;
    }
    int code = 0;
    int64_t verified = 0;
    for (;;) {
        if (cancelled(progress)) {
            snprintf(error, error_len, "cancelled");
            code = 11;
            break;
        }
        ssize_t got = libssh2_sftp_read(handle, buffer, TRANSFER_BUFFER_SIZE);
        if (got == 0) {
            break;
        }
        if (got < 0 || EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) {
            snprintf(error, error_len, "staging read-back failed");
            code = 3;
            break;
        }
        verified += got;
        if (progress != NULL) {
            __atomic_store_n(&progress->verified, verified, __ATOMIC_RELAXED);
        }
    }
    free(buffer);
    int closed = libssh2_sftp_close(handle);
    if (code == 0 && closed != 0) {
        snprintf(error, error_len, "staging read-back close failed");
        code = 3;
    }
    if (code != 0) {
        EVP_MD_CTX_free(ctx);
        return code;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != 32) {
        EVP_MD_CTX_free(ctx);
        snprintf(error, error_len, "staging read-back failed");
        return 3;
    }
    EVP_MD_CTX_free(ctx);
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(hex + (i * 2), "%02x", digest[i]);
    }
    hex[64] = 0;
    return 0;
}

static int remote_size(LIBSSH2_SFTP *sftp, const char *path, uint64_t *size) {
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    memset(&attrs, 0, sizeof(attrs));
    if (libssh2_sftp_stat(sftp, path, &attrs) != 0) {
        return -1;
    }
    if ((attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) == 0) {
        return -1;
    }
    *size = attrs.filesize;
    return 0;
}

int kiite_upload_file(
    const char *host,
    int port,
    const char *user,
    const char *key_path,
    const char *passphrase,
    const char *password,
    const char *host_sha256_hex,
    const char *local_path,
    const char *file_sha256_hex,
    const char *staging_path,
    const char *final_path,
    KiiteProgress *progress,
    KiiteUploadResult *result) {
    if (result == NULL) {
        return 2;
    }
    memset(result, 0, sizeof(*result));
    if (!path_is_safe(staging_path) || !path_is_safe(final_path) || strcmp(staging_path, final_path) == 0) {
        set_message(result, "remote path rejected");
        result->code = 3;
        return 3;
    }
    struct Conn conn;
    note_phase(progress, KIITE_PHASE_CONNECTING);
    double phase_started = monotonic_seconds();
    int code = open_authenticated(host, port, user, key_path, passphrase, password, host_sha256_hex, &conn, result);
    result->connect_seconds = monotonic_seconds() - phase_started;
    if (code != 0) {
        result->code = code;
        return code;
    }
    FILE *local = NULL;
    note_phase(progress, KIITE_PHASE_DIRECTORIES);
    phase_started = monotonic_seconds();
    int directories = ensure_directories(conn.sftp, staging_path, 0700) == 0 && ensure_directories(conn.sftp, final_path, 0755) == 0;
    result->directory_seconds = monotonic_seconds() - phase_started;
    if (!directories) {
        set_message(result, "could not create remote directories");
        code = 6;
        goto done;
    }
    local = fopen(local_path, "rb");
    if (local == NULL) {
        set_message(result, "cannot open snapshot");
        code = 3;
        goto done;
    }
    int64_t written = 0;
    char error[160];
    note_phase(progress, KIITE_PHASE_UPLOADING);
    phase_started = monotonic_seconds();
    code = write_local_file(conn.sftp, staging_path, local, progress, &written, error, sizeof(error));
    result->write_seconds = monotonic_seconds() - phase_started;
    fclose(local);
    local = NULL;
    result->bytes_written = written;
    if (code != 0) {
        set_message(result, error);
        goto done;
    }
    if (cancelled(progress)) {
        unlink_quiet(conn.sftp, staging_path);
        set_message(result, "cancelled");
        code = 11;
        goto done;
    }
    note_phase(progress, KIITE_PHASE_VERIFYING);
    phase_started = monotonic_seconds();
    uint64_t size = 0;
    if (remote_size(conn.sftp, staging_path, &size) != 0 || size != (uint64_t)written) {
        unlink_quiet(conn.sftp, staging_path);
        set_message(result, "staging size mismatch; not published");
        code = 9;
        goto done;
    }
    char remote_hex[65];
    code = sha256_remote(conn.sftp, staging_path, progress, remote_hex, error, sizeof(error));
    result->verify_seconds = monotonic_seconds() - phase_started;
    if (code != 0) {
        unlink_quiet(conn.sftp, staging_path);
        set_message(result, error);
        goto done;
    }
    if (file_sha256_hex == NULL || strcmp(remote_hex, file_sha256_hex) != 0) {
        unlink_quiet(conn.sftp, staging_path);
        set_message(result, "staging hash mismatch; not published");
        code = 9;
        goto done;
    }
    note_phase(progress, KIITE_PHASE_PUBLISHING);
    phase_started = monotonic_seconds();
    LIBSSH2_SFTP_ATTRIBUTES mode;
    memset(&mode, 0, sizeof(mode));
    mode.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
    mode.permissions = 0644;
    if (libssh2_sftp_setstat(conn.sftp, staging_path, &mode) != 0) {
        unlink_quiet(conn.sftp, staging_path);
        set_message(result, "could not set published permissions");
        code = 6;
        goto done;
    }
    if (cancelled(progress)) {
        unlink_quiet(conn.sftp, staging_path);
        set_message(result, "cancelled");
        code = 11;
        goto done;
    }
    if (libssh2_sftp_posix_rename(conn.sftp, staging_path, final_path) != 0) {
        unlink_quiet(conn.sftp, staging_path);
        set_message(result, "posix-rename failed; not published");
        code = 8;
        goto done;
    }
    uint64_t published = 0;
    if (remote_size(conn.sftp, final_path, &published) != 0 || published != (uint64_t)written) {
        set_message(result, "published size mismatch");
        code = 9;
        goto done;
    }
    result->bytes_written = written;
    set_message(result, "published");
    code = 0;
    result->publish_seconds = monotonic_seconds() - phase_started;

done:
    if (local != NULL) {
        fclose(local);
    }
    phase_started = monotonic_seconds();
    close_conn(&conn, code);
    result->close_seconds = monotonic_seconds() - phase_started;
    result->code = code;
    return code;
}

int kiite_check_directories(
    const char *host,
    int port,
    const char *user,
    const char *key_path,
    const char *passphrase,
    const char *password,
    const char *host_sha256_hex,
    const char *remote_root,
    const char *staging_root,
    KiiteUploadResult *result) {
    if (result == NULL) {
        return 2;
    }
    memset(result, 0, sizeof(*result));
    if (!path_is_safe(remote_root) || !path_is_safe(staging_root)) {
        set_message(result, "remote path rejected");
        result->code = 3;
        return 3;
    }
    struct Conn conn;
    int code = open_authenticated(host, port, user, key_path, passphrase, password, host_sha256_hex, &conn, result);
    if (code != 0) {
        result->code = code;
        return code;
    }
    if (!directory_ok(conn.sftp, remote_root)) {
        set_message(result, "public root is not a directory");
        code = 12;
    } else if (!directory_ok(conn.sftp, staging_root)) {
        set_message(result, "staging root is not a directory");
        code = 12;
    } else {
        set_message(result, "directories ok");
        code = 0;
    }
    close_conn(&conn, code);
    result->code = code;
    return code;
}

int kiite_remove_file(
    const char *host,
    int port,
    const char *user,
    const char *key_path,
    const char *passphrase,
    const char *password,
    const char *host_sha256_hex,
    const char *remote_path,
    KiiteUploadResult *result) {
    if (result == NULL) {
        return 2;
    }
    memset(result, 0, sizeof(*result));
    if (!path_is_safe(remote_path)) {
        set_message(result, "remote path rejected");
        result->code = 3;
        return 3;
    }
    struct Conn conn;
    int code = open_authenticated(host, port, user, key_path, passphrase, password, host_sha256_hex, &conn, result);
    if (code != 0) {
        result->code = code;
        return code;
    }
    if (libssh2_sftp_unlink(conn.sftp, remote_path) != 0) {
        set_message(result, "could not remove the test file");
        code = 6;
    } else {
        set_message(result, "removed");
        code = 0;
    }
    close_conn(&conn, code);
    result->code = code;
    return code;
}
